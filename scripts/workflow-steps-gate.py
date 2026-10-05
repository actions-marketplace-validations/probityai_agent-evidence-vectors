#!/usr/bin/env python3
"""Run every shell step of every GitHub workflow locally, before the push.

The bug this exists to stop, observed 2026-08-01: a change was pushed after its
author opened `.github/workflows/no-internal-drafts.yml`, read the first two
steps, ran those two by hand, and saw them pass. The guard has three steps. The
third one rejects first-party product names, it was the one the change broke,
and it never ran locally because nobody read that far down the file. The push
went red on a public repository and the tag cut from it had to be withdrawn.

Running "the checks I happened to read" is not running the checks. So this
reads the workflows themselves and runs every shell step in them, in file and
step order, and it is deliberately noisy about the ones it cannot run.

    python3 scripts/workflow-steps-gate.py            # every workflow
    python3 scripts/workflow-steps-gate.py --list     # show the plan, run nothing
    python3 scripts/workflow-steps-gate.py --only no-internal-drafts

Exit 0 only when every runnable step exited 0. Any step failure, any workflow
that will not parse, and any absent dependency is a non-zero exit -- never a
skip. A gate that quietly skips what it cannot check reports a clean result for
a check that did not run, which is the same defect in a different costume.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping
from typing import Any, NamedTuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from _lockfile import single_instance  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"

# A marketplace step is one with `uses:` and no shell body. Every one of them
# used to be printed as SKIP and left at that, and on 2026-09-11 that cost three
# red pushes in a row: `golangci-lint (core module)` is a marketplace step, this
# gate skipped it on every push, and the remote failed it on every push with a
# finding a locally installed golangci-lint reports in under a second.
#
# So a marketplace step is now asked whether this workstation can do the same
# work, and the three answers are kept apart on purpose.
#
#   MIRRORED    -- there is a local equivalent, and it RUNS. A failure here is a
#                  failure of the gate, exactly as a shell step's is.
#   CANNOT_RUN  -- the step does something only a runner can do: provision a
#                  toolchain, upload to the run's artifact store, open a pull
#                  request. It is printed NOT RUN, by name, with the reason.
#   neither     -- an action nobody has classified. That is a FAULT rather than
#                  a skip. An action added to a workflow would otherwise remove
#                  itself from this gate's coverage silently, which is the whole
#                  defect above in its next costume.


class Local(NamedTuple):
    """What this workstation can do about one marketplace step."""

    run: str | None  # the shell to run, when there is a local equivalent
    reason: str  # why there is not, when `run` is None
    fault: bool = False  # an unclassified action, which fails the gate


def installed_golangci_version() -> str:
    """The golangci-lint version on PATH, or "" when there is none."""
    binary = shutil.which("golangci-lint")
    if binary is None:
        return ""
    proc = subprocess.run(  # noqa: S603 -- reading the version of a binary we are about to run
        [binary, "version"], capture_output=True, text=True, check=False
    )
    found = re.search(r"version\s+v?(\S+)", proc.stdout + proc.stderr)
    return found.group(1) if found else "unknown"


def golangci_lint(inputs: dict[str, Any]) -> Local:
    """Mirror golangci/golangci-lint-action with the binary on PATH.

    The pinned version is not a detail. golangci-lint adds, removes and retunes
    linters between patch releases, so a mirror running a different version
    reports on a different tool and its silence means nothing. A mismatch is
    therefore NOT RUN with both versions named, never a quiet pass.
    """
    wanted = str(inputs.get("version", "")).strip().lstrip("v")
    installed = installed_golangci_version()
    if not installed:
        return Local(None, f"golangci-lint is not on PATH; the workflow pins v{wanted}")
    if wanted and installed != wanted:
        return Local(
            None,
            f"the workflow pins v{wanted} and this workstation has v{installed}, "
            "which is a different set of linters",
        )
    directory = str(inputs.get("working-directory", "") or ".")
    # `golangci-lint run`, with nothing added. Narrowing the concurrency or the
    # linter set would make this a mirror of a command the remote never runs.
    return Local(f"cd {shlex.quote(directory)}\ngolangci-lint run", "")


def own_action(inputs: dict[str, Any]) -> Local:
    """Mirror `uses: ./`, this repository's composite action, from the checkout.

    The action installs the package from its own checkout and replays one corpus
    against the verifier named in its inputs, then derives its outputs from the
    report. Both halves are mirrored here, and the second half matters as much
    as the first: a step later in the workflow reads this action's outputs, and
    a mirror that replayed the corpus but produced no outputs would leave that
    step comparing against empty strings and failing a push the remote accepts.

    The harness is packaging/run_vectors.py and the output arithmetic is
    scripts/action-summary.py -- the same file the action itself runs, not a
    second copy of it here, so the mirror cannot drift from what it mirrors.

    The installation step is the runner's: it pip-installs the package into the
    job's environment, and the harness it installs is the file on disk here.
    The job summary is written to a scratch file, and the artifact upload is
    not mirrored at all.
    """
    verifier = str(inputs.get("verifier", "")).strip()
    if not verifier:
        return Local(None, "the action was used without a verifier input")
    corpus = str(inputs.get("corpus", "") or "vectors")
    report = str(inputs.get("report-path", "") or "agent-evidence-vectors-report.json")
    report_name = pathlib.Path(report).name
    # The replay's status is captured rather than allowed to abort the block:
    # the action writes its summary and its outputs for a failing run too, and
    # the mirror has to reach the same place. The status is re-raised at the end
    # so a failing replay still fails this step, as the action's last step does.
    return Local(
        ': "${RUNNER_TEMP:?RUNNER_TEMP is required}"\n'
        f'report_path="$RUNNER_TEMP"/{shlex.quote(report_name)}\n'
        "status=0\n"
        "python3 packaging/run_vectors.py"
        f" --corpus {shlex.quote(corpus)}"
        f" --verifier {shlex.quote(verifier)}"
        ' --report "$report_path" || status=$?\n'
        'echo "report=$report_path" >> "$GITHUB_OUTPUT"\n'
        f'REPORT="$report_path" STATUS="$status" CORPUS={shlex.quote(corpus)} \\\n'
        "  python3 scripts/action-summary.py\n"
        # The action's last step fails the job on the exit status OR on a
        # summary verdict other than pass, so the mirror does both.
        'if [ "$status" != 0 ]; then exit "$status"; fi\n'
        'grep -qx "result=pass" "$GITHUB_OUTPUT" || exit 1\n',
        "",
    )


def uv_python_available(version: str) -> bool:
    """Whether uv can provide a CPython release the pin accepts, installed or downloadable.

    A three-part pin (3.13.15) accepts that release and nothing else. A two-part
    pin (3.12) is what setup-python reads as "the newest 3.12", so any 3.12.x
    satisfies it, on the runner and here alike.
    """
    if shutil.which("uv") is None:
        return False
    proc = subprocess.run(  # noqa: S603 -- asking uv what it can install
        ["uv", "python", "list", "--all-versions", version],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return False
    if re.fullmatch(r"\d+\.\d+", version):
        return f"cpython-{version}." in proc.stdout
    return f"cpython-{version}-" in proc.stdout


def setup_python(inputs: dict[str, Any]) -> Local:
    """Mirror actions/setup-python with a fresh, pip-seeded interpreter from uv.

    The runner's step puts a Python WITH pip on PATH, and the workflows that use
    it start with `python -m pip install ...`. Leaving the step NOT RUN meant the
    next steps ran against the hook's uv-built project venv, which has no pip,
    and three workflows failed here on 2026-10-01 while passing on the remote.

    The interpreter is announced through $GITHUB_PATH, exactly as the action
    does, so it lasts for the rest of the job and no longer. The pinned release
    is used or nothing is: when uv cannot provide that exact version, the step
    is NOT RUN and so is the rest of its job (see `execute`). A nearby release
    is not a mirror -- the WIMSE reproduction refuses any interpreter but its
    pinned one, so a fallback fails a push the remote accepts.
    """
    wanted = str(inputs.get("python-version", "")).strip()
    if not wanted:
        return Local(None, "actions/setup-python was used without a python-version input")
    if not uv_python_available(wanted):
        return Local(
            None,
            f"actions/setup-python pins CPython {wanted}, which uv on this workstation "
            "cannot provide; the job's later steps are not run on a different interpreter",
        )
    return Local(
        f'uv venv -q --seed --python {shlex.quote(wanted)} "$RUNNER_TEMP/setup-python"\n'
        'echo "$RUNNER_TEMP/setup-python/bin" >> "$GITHUB_PATH"\n',
        "",
    )


MIRRORED: dict[str, Callable[[dict[str, Any]], Local]] = {
    "golangci/golangci-lint-action": golangci_lint,
    "actions/setup-python": setup_python,
    "./": own_action,
}

# Steps that belong to the runner rather than to the repository. Each reason
# says what the step does there, so a reader can judge the gap rather than
# taking "not runnable" on trust.
CANNOT_RUN = {
    "actions/checkout": (
        "materialises the repository on the runner; this gate already runs "
        "inside a checkout of the revision under test"
    ),
    "actions/setup-go": "provisions a Go toolchain on the runner; the one on PATH is used here",
    "actions/setup-node": "provisions Node.js on the runner; the one on PATH is used here",
    "pypa/gh-action-pypi-publish": (
        "uploads the built distributions to PyPI under the workflow's OIDC "
        "identity, which only the runner holds"
    ),
    "astral-sh/setup-uv": "provisions uv on the runner; the one on PATH is used here",
    "sigstore/cosign-installer": "provisions cosign on the runner; the one on PATH is used here",
    "actions/upload-artifact": "writes to the run's artifact store, which is only on the remote",
    "peter-evans/create-pull-request": "opens a pull request on the remote",
    "ossf/scorecard-action": "reads the repository's remote metadata and needs a token",
    "github/codeql-action/init": "builds a CodeQL database with a toolchain provisioned per run",
    "github/codeql-action/analyze": "queries a CodeQL database built by the step above",
    "github/codeql-action/upload-sarif": "uploads to code scanning on the remote",
    "actions/configure-pages": (
        "reads the repository's Pages settings from the remote to tell the build "
        "what base URL the site will be served from"
    ),
    "actions/upload-pages-artifact": (
        "packs the built directory into the run's artifact store, which is only on the remote"
    ),
    "actions/deploy-pages": (
        "publishes an uploaded artifact to the repository's Pages site, which "
        "only the remote can do"
    ),
}


def local_equivalent(uses: str, inputs: dict[str, Any]) -> Local:
    """Classify one marketplace step. Never returns a silent skip."""
    action = uses.split("@", 1)[0]
    builder = MIRRORED.get(action)
    if builder is not None:
        return builder(inputs)
    reason = CANNOT_RUN.get(action)
    if reason is not None:
        return Local(None, f"{action} {reason}")
    return Local(
        None,
        f"{action} is not classified in this gate. Add it to MIRRORED with a "
        "local equivalent, or to CANNOT_RUN with the reason a runner is needed. "
        "An unclassified action drops out of local coverage without saying so.",
        fault=True,
    )


def load_yaml(path: pathlib.Path) -> Any:
    """Parse a workflow, or fail loudly. Never return a partial parse."""
    try:
        import yaml  # noqa: PLC0415 -- optional dependency, reported explicitly below
    except ImportError:
        sys.exit(
            "workflow-steps-gate: PyYAML is not importable.\n"
            "  Install it, or run this gate through uv:\n"
            "    uv run --with pyyaml python scripts/workflow-steps-gate.py\n"
            "  Refusing to continue: a gate that cannot read the workflows cannot\n"
            "  report that they passed."
        )
    try:
        return yaml.safe_load(path.read_text())
    except Exception as exc:  # noqa: BLE001 -- any parse failure is fatal by design
        sys.exit(f"workflow-steps-gate: {path.name} did not parse: {exc}")


class Step(NamedTuple):
    """One workflow step: a shell body, or a marketplace action and its inputs."""

    job: str
    # Not `index`: a NamedTuple field of that name overrides tuple.index().
    position: int
    name: str
    run: str | None
    uses: str
    inputs: dict[str, Any]
    # `ident` rather than `id`: the step's own `id:`, which is how a later step
    # names this one's outputs. Empty when the step declares none.
    ident: str = ""
    # The step's `env:` block, verbatim. Dropping it used to be silent: a step
    # whose assertions read variables set here ran with none of them set, which
    # is a check reporting a verdict on an input it never received.
    env: dict[str, Any] = {}
    # `continue-on-error: true`. A failing step so marked does not fail the job
    # on the runner; its `outcome` is failure and its `conclusion` is success,
    # which is how a workflow asserts that something MUST fail. Ignoring the key
    # made every such negative step a red push the remote would accept.
    continue_on_error: bool = False
    # The directory a `run:` block starts in, relative to the checkout: the
    # step's own `working-directory`, else the job's `defaults.run`, else the
    # workflow's. Ignoring it ran every step of a job declaring a default
    # directory from the repository root, where its scripts are not found.
    workdir: str = ""
    # The step's `if:` expression, verbatim, or "" when it has none.
    condition: str = ""
    # The job's matrix combination, as `matrix.<key>` reads it. Empty for a job
    # with no matrix. A matrix job runs once per combination on the runner, and
    # each combination is its own job here too, with its own label.
    matrix: dict[str, str] = {}
    # Set when the job's matrix cannot be expanded here; every step of the job
    # is then NOT RUN with this reason rather than run with `matrix.*` empty.
    unexpanded: str = ""

    @property
    def label(self) -> str:
        return f"{self.job}[{self.position}] {self.name}"


def scalar(value: Any) -> str:
    """A YAML scalar as an expression reads it: booleans are `true`/`false`."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def matrix_combinations(job: Any) -> tuple[list[dict[str, str]], str]:
    """Every combination of a job's `strategy.matrix`, or the reason there are none.

    The runner starts one job per combination and `matrix.<key>` reads that
    combination's value. Before this, `matrix.*` resolved to the empty string,
    so a job pinning `python-version: ${{ matrix.python }}` asked setup-python
    for no version at all and none of its steps ever ran here.

    The expansion follows the documented rules: the cross product of the list
    keys, then each `include` entry is merged into every combination whose
    ORIGINAL keys it agrees with (it may add keys, never overwrite an original
    one) or appended as a combination of its own when it agrees with none, then
    every combination matching an `exclude` entry on all of its keys is dropped.
    A matrix built from an expression (`fromJSON(...)`) is not guessed: the
    reason comes back instead and the job's steps are NOT RUN.
    """
    matrix = ((job or {}).get("strategy") or {}).get("matrix")
    if matrix is None:
        return [{}], ""
    if not isinstance(matrix, dict):
        return [], f"its matrix is the expression {matrix!r}, which this gate does not evaluate"
    axes = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
    for key, values in axes.items():
        if not isinstance(values, list):
            return [], (
                f"its matrix key `{key}` is {values!r}, not a list, which this gate "
                "does not evaluate"
            )
    combos = _cross(axes)
    for entry in matrix.get("include") or []:
        _include(combos, {str(k): scalar(v) for k, v in (entry or {}).items()}, set(axes))
    for entry in matrix.get("exclude") or []:
        drop = {str(k): scalar(v) for k, v in (entry or {}).items()}
        combos = [c for c in combos if not all(c.get(k) == v for k, v in drop.items())]
    if not combos:
        return [], "its matrix expands to no combination"
    return combos, ""


def _cross(axes: dict[str, list[Any]]) -> list[dict[str, str]]:
    """The cross product of the matrix's list keys; empty when there are none."""
    if not axes:
        return []
    combos: list[dict[str, str]] = [{}]
    for key, values in axes.items():
        combos = [{**combo, key: scalar(value)} for combo in combos for value in values]
    return combos


def _include(combos: list[dict[str, str]], entry: dict[str, str], axes: set[str]) -> None:
    """Merge one `include` entry, or append it when no combination agrees with it."""
    matched = False
    for combo in combos:
        if all(combo.get(k) == v for k, v in entry.items() if k in axes):
            combo.update({k: v for k, v in entry.items() if k not in axes})
            matched = True
    if not matched:
        combos.append(dict(entry))


def steps_of(doc: Any, path: pathlib.Path) -> Iterator[Step]:
    """Yield every step, in declaration order, once per matrix combination."""
    jobs = (doc or {}).get("jobs") or {}
    if not jobs:
        sys.exit(f"workflow-steps-gate: {path.name} declares no jobs. Refusing to call it covered.")
    workflow_dir = default_directory(doc)
    for job_name, job in jobs.items():
        job_dir = default_directory(job) or workflow_dir
        combos, unexpanded = matrix_combinations(job)
        for combo in combos or [{}]:
            label = job_name
            if combo:
                label = f"{job_name} ({', '.join(f'{k}={v}' for k, v in combo.items())})"
            for i, step in enumerate(job.get("steps") or []):
                name = step.get("name") or f"step {i}"
                yield Step(
                    job=label,
                    position=i,
                    name=name,
                    run=None if step.get("run") is None else scalar(step.get("run")),
                    uses=str(step.get("uses") or ""),
                    inputs=step.get("with") or {},
                    ident=str(step.get("id") or ""),
                    env=step.get("env") or {},
                    continue_on_error=step.get("continue-on-error") is True,
                    workdir=str(step.get("working-directory") or job_dir),
                    condition=str(step.get("if") or ""),
                    matrix=combo,
                    unexpanded=unexpanded,
                )


def default_directory(node: Any) -> str:
    """`defaults.run.working-directory` of a workflow or a job, or ""."""
    defaults = (node or {}).get("defaults") or {}
    return str((defaults.get("run") or {}).get("working-directory") or "")


# The runner's default shell is bash, and workflow steps rely on it: `set -o pipefail`
# is a bashism that dash rejects outright, so running a step under /bin/sh reports a
# failure the remote would never see. A local gate that fails differently from the gate
# it mirrors is worse than none, because it trains its reader to ignore it.
SHELL = "/bin/bash"

# GitHub Actions runs every `run:` block under `bash -e {0}` -- its own logs print
# that line above each step. Without `-e`, a multi-command block reports only the
# LAST command's status, so a step whose first command fails and whose remaining
# commands pass exits 0 here and non-zero on the remote. That is not a cosmetic
# divergence: it is this gate reporting a clean mirror of a workflow that is
# about to go red, which is the exact failure the gate was written to prevent,
# one level up. Origin 2026-08-07: the four-command forcing step failed its first
# command, passed the other three, and this gate passed the push.
#
# `pipefail` is NOT added. Actions does not set it, and a mirror stricter than
# the thing it mirrors fails pushes the remote would have accepted -- the job is
# to match, not to improve. scripts/workflow-steps-gate-test.py pins both halves.
SHELL_FLAGS = ("-e",)


# `${{ ... }}`. Actions substitutes it in `env:` values, in `with:` inputs and in
# the text of a `run:` block before bash ever sees the block.
EXPRESSION = re.compile(r"\$\{\{(.+?)\}\}", re.DOTALL)
STEP_OUTPUT = re.compile(r"^steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)$")
STEP_STATUS = re.compile(r"^steps\.([A-Za-z0-9_-]+)\.(outcome|conclusion)$")
REFERENCE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_*-]+)*$")
# Contexts Actions defines. A reference into one of these that this gate has no
# value for resolves to the empty string, as Actions yields for an absent value.
# Anything else (a function call, an index, a name outside these) is not
# guessed: the step is NOT RUN with the expression named.
KNOWN_CONTEXTS = (
    "github",
    "env",
    "vars",
    "job",
    "jobs",
    "steps",
    "runner",
    "secrets",
    "strategy",
    "matrix",
    "needs",
    "inputs",
)


def _literal(text: str) -> tuple[bool, Any]:
    """(is a literal, its value) for one operand of an expression."""
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return True, text[1:-1].replace("''", "'")
    if text in ("true", "false"):
        return True, text == "true"
    if text == "null":
        return True, None
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return True, float(text) if "." in text else int(text)
    return False, None


def _rendered(value: Any) -> str:
    """An expression value as Actions writes it into text."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _split_top(expression: str, operator: str) -> list[str]:
    """Split on an operator outside single-quoted strings."""
    parts: list[str] = []
    depth_quote = False
    current = ""
    i = 0
    while i < len(expression):
        ch = expression[i]
        if ch == "'":
            depth_quote = not depth_quote
        if not depth_quote and expression.startswith(operator, i):
            parts.append(current)
            current = ""
            i += len(operator)
            continue
        current += ch
        i += 1
    parts.append(current)
    return [part.strip() for part in parts]


class _Evaluator:
    """One expression body, evaluated the way Actions does for the subset used here.

    Supported: references, string, number and boolean literals, `==`, `!=`, `!`,
    `&&` and `||` with Actions' short-circuit values (`a || b` is a when a is
    truthy, else b). A parenthesis or a function call is outside that and is
    refused by name rather than approximated.
    """

    def __init__(
        self,
        expression: str,
        outputs: dict[str, dict[str, str]],
        statuses: dict[str, dict[str, str]] | None,
        context: Mapping[str, str] | None,
        where: str,
    ) -> None:
        self.expression = expression
        self.outputs = outputs
        self.statuses = statuses or {}
        self.context = context or {}
        self.where = where
        self.shown = f"${{{{ {expression.strip()} }}}}"

    def run(self) -> tuple[Any, str]:
        if "(" in self.expression or "[" in self.expression:
            return None, (
                f"{self.where} {self.shown}, which calls a function or indexes a value; "
                "this gate evaluates references, literals, ==, !=, !, && and || only "
                "and will not approximate the rest"
            )
        value: Any = None
        for part in _split_top(self.expression, "||"):
            value, missing = self.conjunction(part)
            if missing or value:
                return value, missing
        return value, ""

    def conjunction(self, text: str) -> tuple[Any, str]:
        value: Any = True
        for part in _split_top(text, "&&"):
            value, missing = self.comparison(part)
            if missing or not value:
                return value, missing
        return value, ""

    def comparison(self, text: str) -> tuple[Any, str]:
        for operator in ("==", "!="):
            sides = _split_top(text, operator)
            if len(sides) > 2:
                return None, f"{self.where} {self.shown}, which chains `{operator}`; not evaluated"
            if len(sides) == 2:
                left, missing = self.operand(sides[0])
                right, missing_right = self.operand(sides[1])
                if missing or missing_right:
                    return None, missing or missing_right
                same = _rendered(left).lower() == _rendered(right).lower()
                return (same if operator == "==" else not same), ""
        return self.operand(text)

    def operand(self, text: str) -> tuple[Any, str]:
        text = text.strip()
        negate = False
        while text.startswith("!"):
            negate = not negate
            text = text[1:].strip()
        value, missing = self.atom(text)
        return (not value if negate else value), missing

    def atom(self, text: str) -> tuple[Any, str]:
        is_literal, value = _literal(text)
        if is_literal:
            return value, ""
        if not REFERENCE.match(text):
            return None, (
                f"{self.where} {self.shown}, and `{text}` is not an expression this gate can read"
            )
        if STEP_STATUS.match(text) or STEP_OUTPUT.match(text):
            return self.step_reference(text)
        if text in self.context:
            return self.context[text], ""
        if text.split(".", 1)[0] in KNOWN_CONTEXTS:
            return "", ""
        return None, f"{self.where} {self.shown}, and `{text}` names no context Actions defines"

    def step_reference(self, text: str) -> tuple[Any, str]:
        """A step's outcome or output, as recorded when this gate ran the step.

        One that was not run here, or ran without writing the name, is not
        guessed: the reason names the step and what is missing.
        """
        status = STEP_STATUS.match(text)
        if status is not None:
            step_id, which = status.groups()
            recorded_status = self.statuses.get(step_id)
            if recorded_status is None:
                return None, (
                    f"{self.where} {self.shown}, and step `{step_id}` was not run here, so "
                    "this gate has no outcome for it and will not invent one"
                )
            return recorded_status[which], ""
        reference = STEP_OUTPUT.match(text)
        assert reference is not None
        step_id, name = reference.groups()
        recorded = self.outputs.get(step_id)
        if recorded is None:
            return None, (
                f"{self.where} {self.shown}, and step `{step_id}` was not run here, so "
                "this gate has no value for it and will not invent one"
            )
        if name not in recorded:
            return None, (
                f"{self.where} {self.shown}, and step `{step_id}` ran here without writing "
                f"`{name}` to $GITHUB_OUTPUT. Either the action declares an output its "
                "local mirror does not produce, or the name is wrong"
            )
        return recorded[name], ""


def evaluate(
    expression: str,
    outputs: dict[str, dict[str, str]],
    statuses: dict[str, dict[str, str]] | None = None,
    context: Mapping[str, str] | None = None,
    where: str = "its env reads",
) -> tuple[Any, str]:
    """Evaluate one expression body. Returns (value, reason it could not be)."""
    return _Evaluator(expression, outputs, statuses, context, where).run()


def expand(
    value: str,
    outputs: dict[str, dict[str, str]],
    statuses: dict[str, dict[str, str]] | None = None,
    context: Mapping[str, str] | None = None,
    where: str = "its env reads",
) -> tuple[str, str]:
    """Resolve the expressions in one string. Returns (expanded, reason it could not be).

    Three kinds of reference appear in these workflows and they are not treated
    alike.

    A reference to ANOTHER STEP'S OUTPUT is answered from what that step wrote
    to $GITHUB_OUTPUT when this gate ran it. If the named step was not run here,
    or ran and never wrote that name, the value is NOT guessed: the step is
    declared NOT RUN and the reason says which output was missing. Substituting
    an empty string instead is how this hole opened -- `test "$RESULT" = pass`
    against an unset RESULT fails, and a gate that fails a push the remote would
    accept is a gate its reader learns to bypass.

    A context value this gate KNOWS is supplied: `github.sha` is the revision
    under test, `github.repository` is read from the origin remote,
    `runner.temp` is the job's scratch directory, `matrix.*` is the job's
    combination, and `github.event_name` is `push`, the event a pre-push gate
    stands for. Before, every one of these was the empty string, so a reader
    step passing `--reader-revision "${{ github.sha }}"` was handed no revision.

    ANY OTHER CONTEXT -- `github.event.before`, `github.ref`, `secrets.*` --
    resolves to the empty string, which is what Actions itself yields for a
    context value that is absent. The steps here that read one are written for
    it: the commit-message lint falls back to the unpublished range when
    `github.ref` is empty, and the crosswalk filer prints its body and exits when
    `$GITHUB_ACTIONS` is not true. Supplying an invented value instead would
    steer those fallbacks wrong.
    """
    missing = ""

    def one(match: re.Match[str]) -> str:
        nonlocal missing
        result, reason = evaluate(match.group(1), outputs, statuses, context, where)
        if reason and not missing:
            missing = reason
        return _rendered(result)

    return EXPRESSION.sub(one, value), missing


def file_safe(label: str) -> str:
    """A job label (which carries a matrix combination) as a file name part."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", label)


def step_environment(
    step: Step,
    outputs: dict[str, dict[str, str]],
    scratch: str,
    statuses: dict[str, dict[str, str]] | None = None,
    context: Mapping[str, str] | None = None,
) -> tuple[dict[str, str], str]:
    """The environment for one step, or the reason it cannot be assembled.

    Every step is given its own $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY, the way
    the runner does, so a step that writes outputs can be read by the next one
    and a step that writes a summary is not writing to a variable that is unset.
    """
    stem = f"{file_safe(step.job)}-{step.position}"
    env: dict[str, str] = {
        "GITHUB_OUTPUT": str(pathlib.Path(scratch) / f"output-{stem}"),
        "GITHUB_STEP_SUMMARY": str(pathlib.Path(scratch) / f"summary-{stem}"),
        "GITHUB_ENV": str(pathlib.Path(scratch) / f"env-{stem}"),
        "GITHUB_PATH": str(pathlib.Path(scratch) / f"path-{stem}"),
    }
    for key, raw in step.env.items():
        value, missing = expand(str(raw), outputs, statuses, context)
        if missing:
            return env, missing
        env[str(key)] = value
    for key in ("GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GITHUB_ENV", "GITHUB_PATH"):
        pathlib.Path(env[key]).write_text("", encoding="utf-8")
    return env, ""


def read_github_env(text: str) -> dict[str, str]:
    """Parse a $GITHUB_ENV file: `NAME=value` lines and `NAME<<DELIM` blocks."""
    found: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            name, delimiter = line.split("<<", 1)
            body: list[str] = []
            while i < len(lines) and lines[i] != delimiter:
                body.append(lines[i])
                i += 1
            i += 1
            found[name.strip()] = "\n".join(body)
            continue
        key, sep, value = line.partition("=")
        if sep:
            found[key.strip()] = value
    return found


class JobState:
    """What one job carries between its steps on a runner and nowhere else.

    $RUNNER_TEMP is a directory private to the job; $GITHUB_ENV and $GITHUB_PATH
    are how one step sets variables and PATH entries for the steps after it in
    the same job. None of the three existed here, so a step that wrote a binary
    to $RUNNER_TEMP and named it through $GITHUB_ENV crashed on the KeyError,
    and the steps that read the variable failed after it.
    """

    def __init__(self, scratch: str, label: str) -> None:
        self.label = label
        self.temp = pathlib.Path(scratch) / f"runner-temp-{file_safe(label)}"
        self.temp.mkdir(parents=True, exist_ok=True)
        self.env: dict[str, str] = {}
        self.path: list[str] = []
        # Set when a step that provisions the job's toolchain could not run;
        # every later step of the job is then NOT RUN with this reason.
        self.blocked = ""
        # Tools a runner-only step of this job would have put on PATH (cosign
        # from sigstore/cosign-installer, node from actions/setup-node), keyed by
        # the action that provides them. A later step that dies because one is
        # absent here is NOT RUN with the error, never a failure and never a pass.
        self.provided: dict[str, str] = {}
        # Directories this job fetched for a foreign checkout, removed when the
        # job ends: every job starts from a fresh workspace on the runner.
        self.fetched: list[pathlib.Path] = []

    def finish(self) -> None:
        """Remove what this job fetched, as the runner discards the workspace."""
        for directory in reversed(self.fetched):
            shutil.rmtree(directory, ignore_errors=True)
        self.fetched.clear()

    def environment(self, base: dict[str, str]) -> dict[str, str]:
        env = {**base, **self.env, "RUNNER_TEMP": str(self.temp), "GITHUB_WORKSPACE": str(REPO)}
        if self.path:
            env["PATH"] = os.pathsep.join([*reversed(self.path), env.get("PATH", "")])
        return env

    def absorb(self, env: dict[str, str]) -> None:
        """Carry what the step just wrote to $GITHUB_ENV and $GITHUB_PATH forward."""
        self.env.update(
            read_github_env(pathlib.Path(env["GITHUB_ENV"]).read_text(encoding="utf-8"))
        )
        for line in pathlib.Path(env["GITHUB_PATH"]).read_text(encoding="utf-8").splitlines():
            if line.strip():
                self.path.append(line.strip())


def record_outputs(step: Step, env: dict[str, str], outputs: dict[str, dict[str, str]]) -> None:
    """Keep what a step wrote to $GITHUB_OUTPUT, so a later step can read it."""
    if not step.ident:
        return
    written: dict[str, str] = {}
    for line in pathlib.Path(env["GITHUB_OUTPUT"]).read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            written[key.strip()] = value
    outputs[step.ident] = written


def run_step(run: str, env: dict[str, str], workdir: str = "") -> subprocess.CompletedProcess[str]:
    """Run one block from its directory, or report the directory as missing.

    A `working-directory` that does not exist used to raise FileNotFoundError
    out of subprocess and kill the whole gate, so one job reading bytes this
    gate never fetched refused every push. The runner fails that step and goes
    on; so does this.
    """
    cwd = REPO / workdir
    if not cwd.is_dir():
        return subprocess.CompletedProcess(
            [SHELL], 1, "", f"working-directory {workdir!r} does not exist in {REPO}\n"
        )
    return subprocess.run(  # noqa: S603 -- running the repo's own workflow steps is the point
        [SHELL, *SHELL_FLAGS, "-c", run],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
    )


# What a runner-only provisioning step puts on PATH for the rest of its job.
PROVIDES: dict[str, tuple[str, ...]] = {
    "sigstore/cosign-installer": ("cosign",),
    "actions/setup-go": ("go", "gofmt"),
    "actions/setup-node": ("node", "npm", "npx", "corepack"),
    "astral-sh/setup-uv": ("uv", "uvx"),
}
COMMAND_NOT_FOUND = re.compile(r"(?:^|: )([A-Za-z0-9_.+-]+): command not found\s*$", re.MULTILINE)
NO_PIP = re.compile(r"^(\S+): No module named pip\s*$", re.MULTILINE)


def missing_tool(
    proc: subprocess.CompletedProcess[str], env: Mapping[str, str], job: JobState
) -> str:
    """Why a failed step failed for want of a tool the runner has, or "".

    Two absences are recognised, and each is verified before it is believed:

    * exit 127 naming a command that a runner-only step of THIS job provides
      (cosign from sigstore/cosign-installer, for one), when that command is
      not on the step's PATH here;
    * `<python>: No module named pip`, when that interpreter really cannot
      import pip. Every runner image's Python carries pip; a workstation's or a
      gate box's system Python often does not.

    Anything else stays a failure. A command that no step of the job provides
    is a typo or a real dependency the remote lacks too, and excusing it would
    let this gate pass a push the remote fails.
    """
    stderr = proc.stderr or ""
    if proc.returncode == 127:
        for name in COMMAND_NOT_FOUND.findall(stderr):
            provider = job.provided.get(name)
            if provider and shutil.which(name, path=env.get("PATH")) is None:
                line = next(ln for ln in stderr.splitlines() if f"{name}: command not found" in ln)
                return (
                    f"`{name}` is not installed here and {provider} provides it on the "
                    f"runner; the step stopped with: {line.strip()}"
                )
    for interpreter in NO_PIP.findall(stderr):
        probe = subprocess.run(  # noqa: S603 -- asking the named interpreter whether pip imports
            [interpreter, "-c", "import pip"],
            env=dict(env),
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode != 0:
            return (
                f"{interpreter} has no pip here, and the runner image's Python does; "
                f"the step stopped with: {interpreter}: No module named pip"
            )
    return ""


# Where actions/checkout fetches from. A module constant so the tests can point
# it at a local repository instead of the network.
CHECKOUT_BASE = "https://github.com"


def _git_head(git: str, directory: pathlib.Path) -> str:
    """The commit a checkout is at, or "" when it is not one."""
    proc = subprocess.run(  # noqa: S603 -- reading the commit a checkout is at
        [git, "-C", str(directory), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _fetch_into(git: str, url: str, ref: str, target: pathlib.Path) -> str:
    """Shallow-fetch `ref` from `url` into a new checkout at `target`; "" on success."""
    commands = (
        [git, "init", "-q", str(target)],
        [git, "-C", str(target), "fetch", "-q", "--depth", "1", url, ref or "HEAD"],
        [git, "-C", str(target), "checkout", "-q", "--detach", "FETCH_HEAD"],
    )
    for command in commands:
        try:
            proc = subprocess.run(  # noqa: S603 -- fetching a pinned public checkout
                command, capture_output=True, text=True, check=False, timeout=900
            )
        except subprocess.TimeoutExpired:
            return f"fetching {url} at {ref} did not finish in 900 s"
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            return f"fetching {url} at {ref} failed: {detail[-1] if detail else proc.returncode}"
    return ""


def fetch_checkout(repository: str, ref: str, path: str, job: JobState) -> str:
    """Fetch another repository into the workspace, as actions/checkout does.

    Returns "" when `path` now holds `repository` at `ref`, else the reason it
    does not. The fetch is a shallow fetch of exactly `ref`; a full commit SHA
    is then checked against what arrived, so a ref that moved or a fetch that
    landed elsewhere is caught rather than run against.

    An existing directory is used only when it is already a checkout at `ref`,
    and is then left in place at the end; anything else there is refused
    rather than overwritten. A directory this function creates is removed when
    the job ends.
    """
    root = REPO.resolve()
    target = (REPO / path).resolve()
    if root not in target.parents:
        return f"the checkout path {path!r} is not inside the workspace"
    git = shutil.which("git")
    if git is None:
        return "git is not on PATH, so the checkout cannot be fetched"
    full_sha = re.fullmatch(r"[0-9a-f]{40}", ref) is not None
    if target.exists():
        if full_sha and _git_head(git, target) == ref:
            return ""
        return (
            f"{path} already exists and is not a checkout of {repository} at {ref}; "
            "this gate does not overwrite it"
        )
    created = target
    while not created.parent.exists():
        created = created.parent
    url = f"{CHECKOUT_BASE}/{repository}.git"
    problem = _fetch_into(git, url, ref, target)
    if problem:
        shutil.rmtree(created, ignore_errors=True)
        return problem
    job.fetched.append(created)
    landed = _git_head(git, target)
    if full_sha and landed != ref:
        return f"the fetch of {url} landed at {landed}, not at {ref}"
    return ""


def report_failure(label: str, proc: subprocess.CompletedProcess[str]) -> None:
    print(f"  FAIL  {label}  (exit {proc.returncode})")
    for stream in (proc.stdout, proc.stderr):
        for line in (stream or "").splitlines():
            print(f"        {line}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print the plan and run nothing")
    ap.add_argument("--only", metavar="NAME", help="run one workflow, by file stem")
    args = ap.parse_args()

    if not WORKFLOWS.is_dir():
        sys.exit(f"workflow-steps-gate: {WORKFLOWS} does not exist.")

    files = sorted(p for p in WORKFLOWS.glob("*.yml") if not args.only or p.stem == args.only)
    if not files:
        sys.exit(
            f"workflow-steps-gate: no workflow matched {args.only!r}. "
            "An empty selection is a typo, not a pass."
        )

    if args.list:
        return plan(files)

    # One mirror at a time. This runs the repository's real workflow steps, some
    # of which are heavyweight parallel campaigns, so two mirrors do not finish
    # in the time of one -- they oversubscribe the machine and both crawl. The
    # lock is taken here rather than left to the individual steps so the refusal
    # arrives before any work starts, instead of partway through a long run.
    with single_instance("aee-workflow-steps-gate"):
        return execute(files)


def plan(files: list[pathlib.Path]) -> int:
    planned = 0
    not_run: list[str] = []
    known = run_context()
    for path in files:
        doc = load_yaml(path)
        print(f"\n=== {path.name} ===")
        for step in steps_of(doc, path):
            if step.unexpanded:
                not_run.append(f"{step.label}  ({step.unexpanded})")
                print(f"  NOT RUN  {step.label}  ({step.unexpanded})")
                continue
            # Inputs are shown as the run would see them; a step output is not
            # known until the run, so a step that reads one keeps its raw text.
            context = {**known, **{f"matrix.{k}": v for k, v in step.matrix.items()}}
            interpolated, unknown = interpolate(step, {}, {}, context)
            if not unknown:
                step = interpolated
            foreign = step.inputs.get("repository")
            if step.uses.split("@", 1)[0] == "actions/checkout" and foreign:
                planned += 1
                print(f"  PLAN  {step.label}  (checkout of {foreign}, fetched locally)")
                continue
            if step.run is not None:
                planned += 1
                print(f"  PLAN  {step.label}")
                continue
            local = local_equivalent(step.uses, step.inputs)
            if local.run is not None:
                planned += 1
                print(f"  PLAN  {step.label}  (marketplace action, mirrored locally)")
            else:
                not_run.append(f"{step.label}  ({local.reason})")
                print(f"  NOT RUN  {step.label}  ({local.reason})")
    return summarise("planned", planned, 0, not_run)


def step_base_environment(ambient: Mapping[str, str]) -> dict[str, str]:
    """The environment every step starts from.

    The hook runs this gate through `uv run --with pyyaml ...`, which exports
    VIRTUAL_ENV naming a throwaway environment. Steps inherited it, so a
    workflow's `uv pip install --no-deps .` installed the package into that
    throwaway environment while every later `uv run` used the project one,
    which never received it. A runner sets no VIRTUAL_ENV at all; its `uv pip`
    finds the project's environment. So VIRTUAL_ENV here is the project
    environment the hook names in UV_PROJECT_ENVIRONMENT, or nothing.
    """
    base = {**ambient, "CI": "1", "GITHUB_ACTIONS": ""}
    base.pop("VIRTUAL_ENV", None)
    project_env = ambient.get("UV_PROJECT_ENVIRONMENT", "")
    if project_env:
        base["VIRTUAL_ENV"] = project_env
    return base


def origin_repository() -> str:
    """`owner/name` of the origin remote on github.com, or "" when there is none."""
    proc = subprocess.run(  # noqa: S603 -- reading this checkout's own remote
        ["git", "-C", str(REPO), "remote", "get-url", "origin"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    found = re.search(r"github\.com[:/]([^/\s]+/[^/\s]+?)(?:\.git)?/?$", proc.stdout.strip())
    return found.group(1) if found else ""


def run_context() -> dict[str, str]:
    """The context values this gate knows for the revision under test.

    Only values that are TRUE here are supplied. `github.ref`, `github.run_id`
    and `github.event.before` describe a run on the remote that has not
    happened, so they stay absent and resolve to the empty string, which the
    steps that read them are written to handle.
    """
    context = {
        "github.event_name": LOCAL_EVENT,
        "github.workspace": str(REPO),
        "github.server_url": "https://github.com",
        "runner.os": "Linux",
    }
    proc = subprocess.run(  # noqa: S603 -- the commit this gate runs on
        ["git", "-C", str(REPO), "rev-parse", "HEAD"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        context["github.sha"] = proc.stdout.strip()
    repository = origin_repository()
    if repository:
        context["github.repository"] = repository
        context["github.repository_owner"] = repository.split("/", 1)[0]
    return context


def interpolate(
    step: Step,
    outputs: dict[str, dict[str, str]],
    statuses: dict[str, dict[str, str]],
    context: Mapping[str, str],
) -> tuple[Step, str]:
    """The step with `${{ }}` substituted in its run block and its inputs.

    Actions does this before the shell starts, so `--revision "${{ github.sha }}"`
    reaches bash as a SHA. Left in place, bash read `${{` as a bad substitution
    and the step failed here and nowhere else.
    """
    run = step.run
    if run is not None:
        run, missing = expand(run, outputs, statuses, context, "its run block reads")
        if missing:
            return step, missing
    inputs: dict[str, Any] = {}
    for key, raw in step.inputs.items():
        if isinstance(raw, str):
            raw, missing = expand(raw, outputs, statuses, context, f"its `with: {key}` reads")
            if missing:
                return step, missing
        inputs[key] = raw
    return step._replace(run=run, inputs=inputs), ""


class _Run:
    """The state one execution of the gate carries across workflows and jobs."""

    def __init__(self, scratch: str) -> None:
        self.scratch = scratch
        self.ran = self.failed = 0
        self.not_run: list[str] = []
        self.base = step_base_environment(os.environ)
        # What each step with an `id:` wrote to $GITHUB_OUTPUT, so a later step
        # that names it gets the value the runner would have given it.
        self.outputs: dict[str, dict[str, str]] = {}
        # Each step with an `id:` also has an outcome and a conclusion, which a
        # later step reads as steps.<id>.outcome; they differ only under
        # continue-on-error.
        self.statuses: dict[str, dict[str, str]] = {}
        self.known = run_context()

    def skip(self, step: Step, reason: str) -> None:
        self.not_run.append(f"{step.label}  ({reason})")
        print(f"  NOT RUN  {step.label}  ({reason})")

    def context(self, step: Step, job: JobState) -> dict[str, str]:
        return {
            **self.known,
            "runner.temp": str(job.temp),
            **{f"matrix.{k}": v for k, v in step.matrix.items()},
        }

    def step(self, step: Step, job: JobState) -> None:
        """Resolve, run and record one step of `job`."""
        context = self.context(step, job)
        if not job.blocked:
            step, missing = interpolate(step, self.outputs, self.statuses, context)
            if missing:
                self.skip(step, missing)
                return
        block, suffix, fault = resolve_in_job(step, job)
        if fault:
            self.failed += 1
        if block is None:
            self.skip(step, suffix)
            return
        env, missing = step_environment(step, self.outputs, self.scratch, self.statuses, context)
        if missing:
            self.skip(step, missing)
            return
        print(f"  RUN   {step.label}{suffix}")
        # A `working-directory` applies to `run:` blocks only; a mirrored
        # action's shell starts at the root, as the action itself does.
        workdir = step.workdir if step.run is not None else ""
        step_env = {**job.environment(self.base), **env}
        proc = run_step(block, step_env, workdir)
        absent = missing_tool(proc, step_env, job) if proc.returncode else ""
        if absent:
            # Not a failure and not a pass: the step could not do its work
            # here, and the rest of the job reads what it would have made.
            self.skip(step, absent)
            job.blocked = f"an earlier step of the job was not run: {absent}"
            return
        self.ran += 1
        self.record(step, env, job, proc)

    def record(
        self, step: Step, env: dict[str, str], job: JobState, proc: subprocess.CompletedProcess[str]
    ) -> None:
        outcome = "success" if proc.returncode == 0 else "failure"
        if proc.returncode != 0 and step.continue_on_error:
            print(f"  FAILED, continue-on-error  {step.label}  (exit {proc.returncode})")
        elif proc.returncode != 0:
            self.failed += 1
            report_failure(step.label, proc)
        record_outputs(step, env, self.outputs)
        job.absorb(env)
        if step.ident:
            self.statuses[step.ident] = {
                "outcome": outcome,
                "conclusion": "success" if step.continue_on_error else outcome,
            }


def execute(files: list[pathlib.Path]) -> int:
    with tempfile.TemporaryDirectory(prefix="aee-workflow-steps-") as scratch:
        run = _Run(scratch)
        job: JobState | None = None
        try:
            for path in files:
                doc = load_yaml(path)
                print(f"\n=== {path.name} ===")
                for step in steps_of(doc, path):
                    if job is None or job.label != f"{path.stem}-{step.job}":
                        if job is not None:
                            job.finish()
                        job = JobState(scratch, f"{path.stem}-{step.job}")
                        if step.unexpanded:
                            job.blocked = f"the job was not expanded: {step.unexpanded}"
                    run.step(step, job)
        finally:
            if job is not None:
                job.finish()
    return summarise("ran", run.ran, run.failed, run.not_run)


def resolve_in_job(step: Step, job: JobState) -> tuple[str | None, str, bool]:
    """`resolve`, inside a job whose earlier steps may not have run.

    Once setup-python cannot be mirrored, every later step of the job is NOT RUN
    rather than run on an interpreter the remote job never has. A checkout of
    another repository is fetched here, as the runner fetches it; when the
    fetch fails, the rest of the job is NOT RUN with the reason, because its
    later steps read those bytes. A runner-only step that provisions a tool
    records the tool, so a later step that needs it and finds it absent is
    reported as not run rather than as failed.
    """
    if job.blocked:
        return None, job.blocked, False
    action = step.uses.split("@", 1)[0]
    foreign = str(step.inputs.get("repository") or "") if action == "actions/checkout" else ""
    if foreign and event_excludes(step.condition) == "":
        ref = str(step.inputs.get("ref") or "")
        where = str(step.inputs.get("path") or ".")
        problem = fetch_checkout(foreign, ref, where, job)
        if problem:
            job.blocked = (
                f"the job checks out {foreign} at {ref or 'its default branch'} into "
                f"{where}, and {problem}"
            )
            return None, job.blocked, False
        return (
            ":",
            f"  (checked out {foreign} at {ref or 'its default branch'} into {where})",
            False,
        )
    block, suffix, fault = resolve(step)
    if block is None and action == "actions/setup-python":
        job.blocked = f"the job's interpreter was not provisioned: {suffix}"
    if block is None:
        for tool in PROVIDES.get(action, ()):
            job.provided[tool] = action
    return block, suffix, fault


# The event a local run stands for. The pre-push hook mirrors a push, so a step
# guarded to another event would not run on the remote for this push either.
LOCAL_EVENT = "push"
EVENT_TEST = re.compile(
    r"^\s*(?:\$\{\{\s*)?github\.event_name\s*(==|!=)\s*'([a-z_]+)'\s*(?:\}\})?\s*$"
)


def event_excludes(condition: str) -> str:
    """The reason a step's `if:` is false for a push, or "" when it is not.

    Only a bare comparison of github.event_name is decided here. Any other
    expression is left to run as before, because deciding it wrongly would turn
    a step the remote runs into one this gate silently skips.
    """
    match = EVENT_TEST.match(condition)
    if not match:
        return ""
    operator, event = match.groups()
    holds = (LOCAL_EVENT == event) if operator == "==" else (LOCAL_EVENT != event)
    if holds:
        return ""
    return f"its condition `{condition.strip()}` is false for a {LOCAL_EVENT}"


def resolve(step: Step) -> tuple[str | None, str, bool]:
    """(shell to run, the parenthetical or reason, whether it is a fault)."""
    excluded = event_excludes(step.condition)
    if excluded:
        return None, excluded, False
    if step.run is not None:
        return step.run, "", False
    local = local_equivalent(step.uses, step.inputs)
    if local.run is not None:
        return local.run, "  (marketplace action, mirrored locally)", False
    return None, local.reason, local.fault


def summarise(verb: str, count: int, failed: int, not_run: list[str]) -> int:
    print(f"\n{verb} {count} steps, {failed} failed, {len(not_run)} not run here")
    if not_run:
        print("\nNOT RUN by this gate, each with the reason:")
        for line in not_run:
            print(f"  {line}")
        print(
            "\nThis run says nothing about the steps above. A push is therefore not\n"
            "finished when this gate passes: it is finished when the remote run for\n"
            "the pushed commit has CONCLUDED. Watch it, do not assume it:\n"
            '    gh run list --commit "$(git rev-parse HEAD)"\n'
            "    gh run watch <run-id>"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
