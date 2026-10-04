"""Check recipe boundaries during the documentation move."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

SCRIPT = Path(__file__).with_name("distribution-gate.py")
SPEC = importlib.util.spec_from_file_location("distribution_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

HEADING = "Verify a release without trusting us"
REFERENCE = "docs/reference/release-verification.md"
RECIPE = "```bash\n# 1. check the retained bytes\npython3 scripts/release-digests.py --check\n```"
NO_BLOCK = f"{REFERENCE} has the heading '{HEADING}' and no fenced block under it"
SAFE_LINE = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789 -_./", min_size=1, max_size=60)


class TestRecipeBlock:
    """The recipe belongs to its heading and retains its exact bytes."""

    class TestPassingCases:
        @pytest.mark.parametrize("level", range(1, 7))
        def test_heading_level(self, level: int) -> None:
            text = f"{'#' * level} {HEADING}\n\n{RECIPE}\n"
            assert GATE.recipe_block(text, REFERENCE) == RECIPE

        @given(lines=st.lists(SAFE_LINE, min_size=1, max_size=12))
        def test_shell_comments_and_commands_preserve_bytes(self, lines: list[str]) -> None:
            body = "\n".join(lines)
            recipe = f"```bash\n# 1. a shell comment, not a Markdown boundary\n{body}\n```"
            text = f"## {HEADING}\n\n{recipe}\n"
            assert GATE.recipe_block(text, REFERENCE) == recipe

        @given(before=SAFE_LINE, after=SAFE_LINE)
        def test_other_sections_do_not_change_the_recipe(self, before: str, after: str) -> None:
            text = (
                f"## Earlier section\n\n```text\n{before}\n```\n\n"
                f"## {HEADING}\n\n{RECIPE}\n\n"
                f"## Later section\n\n```text\n{after}\n```\n"
            )
            assert GATE.recipe_block(text, REFERENCE) == RECIPE

    class TestFailingCases:
        @pytest.mark.parametrize(
            ("text", "expected"),
            [
                (
                    "## Check a release\n\n" + RECIPE,
                    f"{REFERENCE} has no heading '{HEADING}'",
                ),
                (f"## {HEADING}\n\nNo recipe yet.\n", NO_BLOCK),
                (f"## {HEADING}\n\n## Other commands\n\n{RECIPE}\n", NO_BLOCK),
                (f"## {HEADING}\n\n#\n\n{RECIPE}\n", NO_BLOCK),
                (f"## {HEADING}\n\n## \n\n{RECIPE}\n", NO_BLOCK),
                (
                    f"## {HEADING}\n\n```bash\necho check\n",
                    f"{REFERENCE}: the fenced block under '{HEADING}' is never closed",
                ),
                (
                    f"## {HEADING}\n\n{RECIPE}\n\n## {HEADING}\n",
                    f"{REFERENCE} has 2 headings '{HEADING}'; expected one",
                ),
                (
                    f"## {HEADING}\n\n## Another section\n\n```bash\necho check\n",
                    NO_BLOCK,
                ),
            ],
        )
        def test_refusal_names_the_recipe_fault(self, text: str, expected: str) -> None:
            with pytest.raises(GATE.GateError) as caught:
                GATE.recipe_block(text, REFERENCE)
            assert str(caught.value) == expected

        @given(level=st.integers(min_value=1, max_value=6), section=SAFE_LINE)
        def test_a_later_sections_block_cannot_satisfy_the_recipe(
            self, level: int, section: str
        ) -> None:
            text = f"## {HEADING}\n\nNo recipe.\n\n{'#' * level} {section}\n\n{RECIPE}\n"
            with pytest.raises(GATE.GateError) as caught:
                GATE.recipe_block(text, REFERENCE)
            assert str(caught.value) == NO_BLOCK
