import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POSTURE_SCRIPT = ROOT / "skills" / "healthcheck" / "scripts" / "summarize_openclaw_posture.py"
AUDIT_SCRIPT = ROOT / "skills" / "healthcheck" / "scripts" / "parse_openclaw_audit.py"
PHASE13_DOC = ROOT / "docs" / "healthcheck-helper-output.md"

AUDIT_TEXT = """
OpenClaw security audit
Summary: 1 critical · 2 warn · 3 info
CRITICAL Browser private-network access is enabled on a shared host
WARN SSH password authentication is enabled
WARN Backups have not been verified recently
INFO Firewall is enabled
""".strip()

POSTURE_TEXT = """
OpenClaw status --deep
Summary: 0 critical · 1 warn · 2 info
Channel │ discord:#general
Update               │ available
""".strip()


def run_script(script: Path, payload: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [sys.executable, str(script), *args],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    if check:
        assert proc.returncode == 0, proc.stderr
    return proc


def test_phase13_audit_json_markdown_and_strict_exit_codes():
    data = json.loads(run_script(AUDIT_SCRIPT, AUDIT_TEXT).stdout)
    assert data["ok"] is False
    assert data["summary"] == {"critical": 1, "warn": 2, "info": 3}
    assert data["items"][0] == {
        "severity": "critical",
        "title": "Browser private-network access is enabled on a shared host",
    }

    markdown = run_script(AUDIT_SCRIPT, AUDIT_TEXT, "--format", "markdown").stdout
    assert markdown.startswith("# OpenClaw audit summary")
    assert "| critical | 1 |" in markdown
    assert "Browser private-network access is enabled on a shared host" in markdown

    strict = run_script(AUDIT_SCRIPT, AUDIT_TEXT, "--strict", check=False)
    assert strict.returncode == 1
    assert json.loads(strict.stdout)["ok"] is False


def test_phase13_audit_counts_item_lines_when_summary_is_missing():
    payload = """
OpenClaw security audit
CRITICAL Browser private-network access is enabled on a shared host
WARN Backups have not been verified recently
INFO Firewall is enabled
""".strip()

    data = json.loads(run_script(AUDIT_SCRIPT, payload).stdout)
    assert data["ok"] is False
    assert data["summary"] == {"critical": 1, "warn": 1, "info": 1}

    strict = run_script(AUDIT_SCRIPT, payload, "--strict", check=False)
    assert strict.returncode == 1


def test_phase13_audit_markdown_escapes_table_and_mention_text():
    payload = """
OpenClaw security audit
Summary: 0 critical · 1 warn · 0 info
WARN Check a|b and notify @everyone
""".strip()

    markdown = run_script(AUDIT_SCRIPT, payload, "--format", "markdown").stdout
    assert "a\\|b" in markdown
    assert "@\u200beveryone" in markdown
    assert "@everyone" not in markdown


def test_phase13_posture_json_markdown_and_strict_exit_codes():
    data = json.loads(run_script(POSTURE_SCRIPT, POSTURE_TEXT).stdout)
    assert data["ok"] is False
    assert data["summary"] == {"critical": 0, "warn": 1, "info": 2}
    assert data["channel"] == "discord:#general"
    assert data["update_available"] is True

    markdown = run_script(POSTURE_SCRIPT, POSTURE_TEXT, "--format", "markdown").stdout
    assert markdown.startswith("# OpenClaw posture summary")
    assert "**Channel:** discord:#general" in markdown
    assert "**Update available:** yes" in markdown

    strict = run_script(POSTURE_SCRIPT, POSTURE_TEXT, "--strict", check=False)
    assert strict.returncode == 1
    assert json.loads(strict.stdout)["ok"] is False


def test_phase13_posture_counts_item_lines_when_summary_is_missing():
    payload = """
OpenClaw status --deep
WARN Update checks are stale
INFO Firewall is enabled
""".strip()

    data = json.loads(run_script(POSTURE_SCRIPT, payload).stdout)
    assert data["ok"] is False
    assert data["summary"] == {"critical": 0, "warn": 1, "info": 1}

    strict = run_script(POSTURE_SCRIPT, payload, "--strict", check=False)
    assert strict.returncode == 1


def test_phase13_docs_readme_changelog_and_roadmap_are_in_sync():
    doc = PHASE13_DOC.read_text(encoding="utf-8")
    assert "--format markdown" in doc
    assert "--strict" in doc
    assert "summarize_openclaw_posture.py" in doc
    assert "parse_openclaw_audit.py" in doc

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/healthcheck-helper-output.md" in readme

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "Phase 13 healthcheck helper" in changelog

    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    phase13 = roadmap.split("## Phase 13:", 1)[1].split("## Implementation order", 1)[0]
    assert "**Status:** Shipped" in phase13
    assert "tests/test_phase13_healthcheck_outputs.py" in phase13


def test_roadmap_current_state_matches_merged_phase_work():
    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    current_baseline = roadmap.split("## Current baseline", 1)[1].split(
        "## Active pull requests that affect the roadmap",
        1,
    )[0]
    assert "Healthcheck helper scripts emit JSON/Markdown output and strict CI/scheduled-check gates." in current_baseline

    active_prs = roadmap.split("## Active pull requests that affect the roadmap", 1)[1].split(
        "## Phase 1:",
        1,
    )[0]
    assert "No active roadmap-affecting pull requests" in active_prs
    assert "PR #2" not in active_prs
    assert "PR #3" not in active_prs
