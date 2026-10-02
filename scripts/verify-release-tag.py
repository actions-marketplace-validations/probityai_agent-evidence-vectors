#!/usr/bin/env python3
"""Refuse a release tag that the published tag-signing key did not sign.

Why this file exists
--------------------
The digest list a release publishes is signed, and the tag that names the
release was not checked by anything. A tag can be moved or recreated by anyone
who can push to the repository, and a stranger who fetches by tag name trusts
whatever the tag points at. Release tags from v0.13.0 on were already signed
with the key in `release/tag-signing-key.asc`, but only because of the
maintainer's local git configuration, and nothing checked it. This script is
what the release workflow now runs to refuse a tag that is not signed by it.

The key is imported into a throwaway GnuPG home, so the check reads only the
published key and nothing the runner's keyring happens to hold. A good
signature is not enough: the signing key's fingerprint must be the pinned one,
because any key at all produces a good signature over its own tag.

Usage:
  python3 scripts/verify-release-tag.py vX.Y.Z
  python3 scripts/verify-release-tag.py vX.Y.Z --key-file K --fingerprint F
  python3 scripts/verify-release-tag.py vX.Y.Z --expected-commit COMMIT
    --expected-tag-object TAG_OBJECT

The optional object IDs must come from the caller's selected run inputs. The
release workflow selects them before refreshing the remote tag. A valid signer
alone does not establish that the tag names the commit whose artifacts ran.

Exit 0 when the tag is annotated, signed, and signed by the pinned key; 1
otherwise, with the reason on stderr.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = REPO_ROOT / "release" / "tag-signing-key.asc"
# The primary key fingerprint of release/tag-signing-key.asc.
FINGERPRINT = "494767A5F0B0494C3A8878F320D2E0E72DF45D39"


def signer_fingerprints(status: str) -> set[str]:
    """Primary-key fingerprints named by VALIDSIG lines of a GnuPG status stream.

    VALIDSIG carries the signing subkey's fingerprint first and the primary
    key's last, so both are returned and either may match the pin.
    """
    found: set[str] = set()
    for line in status.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "[GNUPG:]" and fields[1] == "VALIDSIG":
            found.add(fields[2].upper())
            found.add(fields[-1].upper())
    return found


def resolve_tag(tag: str, repo: Path) -> tuple[str | None, str | None]:
    """Resolve the name once and require an annotated tag object."""
    ref = f"refs/tags/{tag}"
    valid_ref = subprocess.run(
        ["git", "check-ref-format", ref], capture_output=True, text=True, check=False
    )
    if valid_ref.returncode != 0:
        return None, f"tag {tag!r} is not a valid tag name"
    resolved = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", ref],
        capture_output=True,
        text=True,
        check=False,
    )
    if resolved.returncode != 0:
        return None, f"tag {tag} does not resolve: {resolved.stderr.strip()}"
    tag_object = resolved.stdout.strip()
    kind = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-t", tag_object],
        capture_output=True,
        text=True,
        check=False,
    )
    if kind.returncode != 0:
        return None, f"tag object {tag_object} could not be read: {kind.stderr.strip()}"
    if kind.stdout.strip() != "tag":
        return None, f"tag {tag} is a lightweight tag, so it carries no signature"
    return tag_object, None


def selected_objects_reason(
    tag: str,
    tag_object: str,
    repo: Path,
    expected_commit: str | None,
    expected_tag_object: str | None,
) -> str | None:
    """Compare the resolved object with immutable inputs selected by the caller."""
    for label, selected in (("commit", expected_commit), ("tag object", expected_tag_object)):
        if (
            selected is not None
            and re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", selected) is None
        ):
            return f"expected {label} must be a full immutable object ID"
    if expected_tag_object is not None and tag_object != expected_tag_object.lower():
        return (
            f"tag {tag} is object {tag_object}, not the selected tag object {expected_tag_object}"
        )
    if expected_commit is not None:
        target = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", f"{tag_object}^{{commit}}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if target.returncode != 0:
            return f"tag {tag} does not name a commit: {target.stderr.strip()}"
        if target.stdout.strip() != expected_commit.lower():
            return (
                f"tag {tag} names commit {target.stdout.strip()}, "
                f"not the selected commit {expected_commit}"
            )
    return None


def signed_name_reason(tag: str, tag_object: str, repo: Path) -> str | None:
    """A mutable reference alias cannot supply a name the signer never signed."""
    content = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-p", tag_object],
        capture_output=True,
        text=True,
        check=False,
    )
    if content.returncode != 0:
        return f"tag object {tag_object} could not be read: {content.stderr.strip()}"
    signed_names = [
        line[4:]
        for line in content.stdout.split("\n\n", 1)[0].splitlines()
        if line.startswith("tag ")
    ]
    if signed_names != [tag]:
        return f"tag {tag} aliases signed tag name {signed_names!r}, not the selected release name"
    return None


def verify(
    tag: str,
    key_file: Path,
    fingerprint: str,
    repo: Path,
    expected_commit: str | None = None,
    expected_tag_object: str | None = None,
) -> str | None:
    """None when the selected tag is signed by the pinned key, else a refusal."""
    tag_object, reason = resolve_tag(tag, repo)
    if tag_object is None:
        return reason
    # Every later check uses this immutable object, even if a fetch or another
    # process changes the tag reference while key import or verification runs.
    reason = selected_objects_reason(tag, tag_object, repo, expected_commit, expected_tag_object)
    if reason is not None:
        return reason
    reason = signed_name_reason(tag, tag_object, repo)
    if reason is not None:
        return reason
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        env = {**os.environ, "GNUPGHOME": home}
        imported = subprocess.run(
            ["gpg", "--batch", "--import", str(key_file)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        if imported.returncode != 0:
            return f"the key file {key_file} did not import: {imported.stderr.strip()}"
        checked = subprocess.run(
            ["git", "-C", str(repo), "verify-tag", "--raw", tag_object],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    if checked.returncode != 0:
        return f"tag {tag} has no good signature from the published key: {checked.stderr.strip()}"
    signers = signer_fingerprints(checked.stderr)
    if fingerprint.upper() not in signers:
        return f"tag {tag} is signed by {sorted(signers)}, not the pinned key {fingerprint}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("tag")
    parser.add_argument("--key-file", type=Path, default=KEY_FILE)
    parser.add_argument("--fingerprint", default=FINGERPRINT)
    parser.add_argument("--repo", type=Path, default=REPO_ROOT)
    parser.add_argument("--expected-commit", help="caller-selected full commit object ID")
    parser.add_argument(
        "--expected-tag-object", help="caller-selected full annotated tag object ID"
    )
    args = parser.parse_args()
    reason = verify(
        args.tag,
        args.key_file,
        args.fingerprint,
        args.repo,
        args.expected_commit,
        args.expected_tag_object,
    )
    if reason is not None:
        print(f"verify-release-tag: REFUSED: {reason}", file=sys.stderr)
        return 1
    print(f"verify-release-tag: {args.tag} is signed by {args.fingerprint}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
