import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
INSTALL_DOC = ROOT / "docs" / "installation-and-release.md"
CHANGELOG = ROOT / "CHANGELOG.md"
README = ROOT / "README.md"
ROADMAP = ROOT / "docs" / "roadmap.md"
PACKAGE_SCRIPT = ROOT / "package-skills.sh"

REQUIRED_ARCHIVE_MEMBERS = {
    "agent-security.skill": [
        "agent-security/SKILL.md",
        "agent-security/references/prompt-injection.md",
        "agent-security/references/rules.md",
        "agent-security/scripts/config_risk_summary.py",
        "agent-security/scripts/score_prompt_injection_exposure.py",
        "agent-security/scripts/flag_prompt_injection_signals.py",
    ],
    "healthcheck.skill": [
        "healthcheck/SKILL.md",
        "healthcheck/references/openclaw-hardening.md",
        "healthcheck/references/os-checks.md",
        "healthcheck/references/profiles.md",
        "healthcheck/scripts/parse_openclaw_audit.py",
        "healthcheck/scripts/summarize_openclaw_posture.py",
    ],
}


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected Phase 7 artifact: {path.relative_to(ROOT)}"
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n"), f"{path.relative_to(ROOT)} should end with a newline"
    return text


def test_packaged_skill_archives_contain_required_files() -> None:
    subprocess.run([str(PACKAGE_SCRIPT)], cwd=ROOT, check=True, text=True, capture_output=True)

    for archive_name, required_members in REQUIRED_ARCHIVE_MEMBERS.items():
        archive = DIST / archive_name
        assert archive.exists(), f"{archive_name} was not generated"
        assert archive.stat().st_size > 0, f"{archive_name} is empty"
        with zipfile.ZipFile(archive) as skill_archive:
            members = set(skill_archive.namelist())
            assert skill_archive.testzip() is None, f"{archive_name} has a corrupt member"

        for member in required_members:
            assert member in members, f"{archive_name} is missing {member}"

        assert not any(member.startswith("../") or member.startswith("/") for member in members)
        assert not any("__pycache__/" in member for member in members)


def test_installation_release_docs_and_changelog_cover_phase7_scope() -> None:
    doc = _read(INSTALL_DOC)
    changelog = _read(CHANGELOG)

    required_doc_phrases = [
        "Install from packaged archives",
        "Inspect a packaged archive before importing",
        "Use from the source tree",
        "Release checklist",
        "Archive integrity",
        "No-real-secret scan",
        "Versioning guidance",
        "Rule or schema changes",
        "Script CLI changes",
        "Documentation-only updates",
    ]
    for phrase in required_doc_phrases:
        assert phrase in doc

    assert "agent-security.skill" in doc
    assert "healthcheck.skill" in doc
    assert "./package-skills.sh" in doc
    assert "python3 -m compileall -q skills tests" in doc
    assert "python3 -m pytest -q" in doc
    assert "ruff check ." in doc

    assert "## Unreleased" in changelog
    assert "### Rule or schema changes" in changelog
    assert "### Script CLI changes" in changelog
    assert "### Documentation-only updates" in changelog


def test_readme_and_roadmap_mark_phase7_shipped() -> None:
    readme = _read(README)
    roadmap = _read(ROADMAP)

    assert "docs/installation-and-release.md" in readme
    assert "CHANGELOG.md" in readme
    assert "Install from packaged archives" in readme
    assert "## Phase 7: Packaging, release, and installation polish" in roadmap
    assert "**Status:** Shipped" in roadmap
    assert "tests/test_phase7_packaging_release.py" in roadmap
    assert "CHANGELOG.md" in roadmap
