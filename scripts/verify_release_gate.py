#!/usr/bin/env python3
"""Verify pre-release gates for tagged agent-security releases.

This gate runs before publishing a tagged release. It fails closed on:

- missing or malformed release tag arguments,
- tags that do not point at the commit being released,
- unrecoverable packaging drift (via the Phase 18 ``--check`` gate),
- a ``CHANGELOG.md`` without a matching section for the tag,
- dist artifacts that disagree with the deterministic rebuild,
- secret-shaped content inside packaged release artifacts.

The gate never modifies the repository, the dist tree, or remote state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGER = ROOT / "scripts" / "package_skills.py"
CHANGELOG = ROOT / "CHANGELOG.md"
DEFAULT_DIST = ROOT / "dist"

MANIFEST_NAME = "MANIFEST.json"
TAG_PATTERN = re.compile(r"^v\d+\.\d+\.\d+$")
SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+$")

# High-signal, low-false-positive token shapes. Patterns are matched
# case-sensitively against artifact text and never printed with matches.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_pat_token", re.compile(r"github_pat_[A-Za-z0-9_]{36,}")),
    ("github_classic_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)

EXIT_OK = 0
EXIT_GATE_FAILURE = 1
EXIT_USAGE = 2


def gate_failure(message: str) -> None:
    print(f"release gate: {message}", file=sys.stderr)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="release tag being verified, e.g. v0.1.0")
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=DEFAULT_DIST,
        help="artifact directory to verify (default: dist)",
    )
    parser.add_argument(
        "--commit",
        default=None,
        help="commit SHA the release workflow is building (defaults to HEAD)",
    )
    parser.add_argument(
        "--skip-packager-check",
        action="store_true",
        help="skip the Phase 18 packager --check invocation (tests and offline audits)",
    )
    return parser.parse_args(argv)


def verify_tag_shape(tag: str) -> str | None:
    """Return an error string when the tag is not a stable ``vX.Y.Z`` tag."""
    if tag != tag.strip():
        return f"tag {tag!r} has surrounding whitespace"
    if not TAG_PATTERN.match(tag):
        return (
            f"tag {tag!r} is not a stable semantic tag of the form vMAJOR.MINOR.PATCH "
            "(pre-release suffixes are not supported by this gate yet)"
        )
    return None


def verify_tag_points_at_commit(tag: str, commit: str) -> str | None:
    """Return an error string when the tag does not resolve to ``commit``.

    Both sides are peeled to commit SHAs first: for annotated tags the
    workflow-provided SHA may be the tag object rather than the commit.
    """
    resolved = subprocess.run(
        ["git", "rev-parse", f"{tag}^{{commit}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if resolved.returncode != 0:
        return f"could not resolve tag {tag!r} to a commit: {resolved.stderr.strip()}"
    tagged_commit = resolved.stdout.strip()
    peeled = subprocess.run(
        ["git", "rev-parse", f"{commit}^{{commit}}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if peeled.returncode != 0:
        return f"could not resolve provided commit {commit!r}: {peeled.stderr.strip()}"
    provided_commit = peeled.stdout.strip()
    if tagged_commit != provided_commit:
        return (
            f"tag {tag!r} points at {tagged_commit} but the release workflow is building {commit}; "
            "re-tag at the release commit or re-run the workflow from the tagged commit"
        )
    return None


def verify_changelog_section(tag: str) -> str | None:
    """Return an error string when CHANGELOG.md lacks a released section for ``tag``."""
    try:
        text = CHANGELOG.read_text(encoding="utf-8")
    except OSError as exc:
        return f"could not read CHANGELOG.md: {exc}"
    version = tag.lstrip("v")
    if not SEMVER_PATTERN.match(version):
        return f"tag {tag!r} does not carry a parseable version"
    heading = f"## {version}"
    for line in text.splitlines():
        if line.startswith("#"):
            if line.strip() == heading:
                return None
            if line.strip() in {"## Unreleased", "## Unreleased changes"}:
                continue
            # Any other heading encountered above the target section means
            # the version section is missing or ordered below later entries.
            if line.startswith("## "):
                return (
                    f"CHANGELOG.md has no '## {version}' section; add released notes for {tag} "
                    "above older release headings"
                )
    return f"CHANGELOG.md has no '## {version}' section for tag {tag}"


def verify_dist_inventory(dist_dir: Path) -> list[str]:
    """Return a list of inventory problems in the dist directory."""
    problems: list[str] = []
    if not dist_dir.is_dir():
        return [f"artifact directory {dist_dir} does not exist; run ./package-skills.sh first"]
    expected_archives = {"agent-security.skill", "healthcheck.skill", MANIFEST_NAME}
    # Directory-descriptor safety is enforced by the packager; this inventory
    # pass only checks names so the gate can report actionable problems.
    observed = {entry.name for entry in dist_dir.iterdir()}
    missing = sorted(expected_archives - observed)
    extra = sorted(observed - expected_archives)
    for name in missing:
        problems.append(f"missing expected artifact {name!r} in {dist_dir}")
    for name in extra:
        problems.append(f"unexpected extra entry {name!r} in {dist_dir}")
    return problems


def load_manifest(dist_dir: Path) -> tuple[dict | None, str | None]:
    """Load and structurally validate dist/MANIFEST.json."""
    path = dist_dir / MANIFEST_NAME
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return None, f"could not read {path}: {exc}"
    except json.JSONDecodeError as exc:
        return None, f"{path} is not valid JSON: {exc}"

    problems: list[str] = []
    if not isinstance(manifest.get("schema_version"), str):
        problems.append("manifest 'schema_version' is missing or not a string")
    archives = manifest.get("archives")
    if not isinstance(archives, list) or not archives:
        return None, "manifest 'archives' is missing or empty"
    names = {entry.get("name") for entry in archives if isinstance(entry, dict)}
    if names != {"agent-security", "healthcheck"}:
        problems.append(f"manifest archive names {sorted(map(str, names))} != ['agent-security', 'healthcheck']")
    if problems:
        return None, "; ".join(problems)
    return manifest, None


def verify_artifact_digests(dist_dir: Path, manifest: dict) -> list[str]:
    """Recompute SHA-256 digests for each archive and compare with the manifest."""
    problems: list[str] = []
    for entry in manifest["archives"]:
        name = entry.get("name")
        expected = entry.get("sha256")
        archive = dist_dir / f"{name}.skill"
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            problems.append(f"manifest entry for {name!r} lacks a valid sha256 digest")
            continue
        try:
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        except OSError as exc:
            problems.append(f"could not read {archive}: {exc}")
            continue
        if digest != expected:
            problems.append(
                f"archive {archive.name} digest {digest} does not match manifest sha256 {expected}"
            )
    return problems


def scan_artifacts_for_secrets(dist_dir: Path) -> list[str]:
    """Scan packaged artifact bytes for secret-shaped content; never echo matches."""
    problems: list[str] = []
    for archive in sorted(dist_dir.glob("*.skill")):
        try:
            data = archive.read_bytes()
        except OSError:
            problems.append(f"could not read {archive} for secret scanning")
            continue
        try:
            text = data.decode("utf-8", errors="ignore")
        except OSError:
            problems.append(f"could not decode {archive} for secret scanning")
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                problems.append(
                    f"{archive.name} contains secret-shaped content matching {label}; "
                    "inspect the archive before publishing"
                )
    return problems


def run_packager_check(dist_dir: Path) -> str | None:
    """Run the Phase 18 deterministic rebuild comparison and return an error string on drift."""
    proc = subprocess.run(
        [sys.executable, str(PACKAGER), "--check", "--output-dir", str(dist_dir)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()
        summary = detail[-1] if detail else f"exit code {proc.returncode}"
        return f"packager --check failed: {summary}"
    return None


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    failures: list[str] = []

    tag_error = verify_tag_shape(args.tag)
    if tag_error:
        gate_failure(tag_error)
        failures.append(tag_error)
    valid_tag = tag_error is None

    commit = args.commit or _head_commit()
    if commit is None:
        head_error = "could not determine HEAD commit; pass --commit explicitly"
        gate_failure(head_error)
        failures.append(head_error)
    else:
        tag_commit_error = verify_tag_points_at_commit(args.tag, commit)
        if tag_commit_error:
            gate_failure(tag_commit_error)
            failures.append(tag_commit_error)

    if valid_tag:
        changelog_error = verify_changelog_section(args.tag)
        if changelog_error:
            gate_failure(changelog_error)
            failures.append(changelog_error)

    inventory_problems = verify_dist_inventory(args.dist_dir)
    for problem in inventory_problems:
        gate_failure(problem)
    failures.extend(inventory_problems)

    manifest, manifest_error = load_manifest(args.dist_dir)
    if manifest_error:
        gate_failure(manifest_error)
        failures.append(manifest_error)

    if manifest is not None:
        digest_problems = verify_artifact_digests(args.dist_dir, manifest)
        for problem in digest_problems:
            gate_failure(problem)
        failures.extend(digest_problems)

        secret_problems = scan_artifacts_for_secrets(dist_dir=args.dist_dir)
        for problem in secret_problems:
            gate_failure(problem)
        failures.extend(secret_problems)

    if not args.skip_packager_check:
        packager_error = run_packager_check(args.dist_dir)
        if packager_error:
            gate_failure(packager_error)
            failures.append(packager_error)

    if failures:
        print(f"release gate: {len(failures)} blocking issue(s); release blocked", file=sys.stderr)
        return EXIT_GATE_FAILURE
    print(f"release gate passed for {args.tag}")
    return EXIT_OK


def _head_commit() -> str | None:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
