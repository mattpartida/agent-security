import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "score_prompt_injection_exposure.py"


def run_script(payload, *args):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=json.dumps(payload) if not isinstance(payload, str) else payload,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc


def test_malformed_input_returns_error_severity():
    proc = run_script("{")
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["severity"] == "error"


def test_high_exposure_scores_high_or_critical():
    payload = {
        "channels": {"discord": {"enabled": True, "groupPolicy": "allowlist"}},
        "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
        "tools": {"exec": {"security": "full"}, "elevated": {"enabled": True}, "fs": {"workspaceOnly": False}},
        "agents": {"defaults": {"model": {"fallbacks": ["ollama/qwen2.5:7b"]}}},
        "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
        "memory": {"enabled": True},
    }
    proc = run_script(payload)
    data = json.loads(proc.stdout)
    assert data["severity"] in {"high", "critical"}
    assert any(f["factor"] == "shared_channel_with_high_impact_tools" for f in data["factors"])


def high_exposure_payload():
    return {
        "channels": {"discord": {"enabled": True, "groupPolicy": "allowlist"}},
        "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
        "tools": {"exec": {"security": "full"}, "elevated": {"enabled": True}, "fs": {"workspaceOnly": False}},
        "agents": {"defaults": {"model": {"fallbacks": ["ollama/qwen2.5:7b"]}}},
        "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
        "memory": {"enabled": True},
    }


def test_markdown_format_emits_summary_header_and_score():
    proc = run_script(high_exposure_payload(), "--format", "markdown")
    assert proc.returncode in (0, 1)
    markdown = proc.stdout
    assert "# Prompt Injection Exposure Score" in markdown
    assert "**Score:**" in markdown
    assert "**Severity:**" in markdown
    assert "**Schema version:** `1.0`" in markdown


def test_markdown_format_lists_risk_factors_table():
    proc = run_script(high_exposure_payload(), "--format", "markdown")
    assert proc.returncode in (0, 1)
    markdown = proc.stdout
    assert "## Risk factors" in markdown
    assert "| Factor | Points |" in markdown
    assert "| --- | --- |" in markdown
    assert "shared_channel_with_high_impact_tools" in markdown
    assert "browser_private_network_allowed" in markdown


def test_markdown_format_includes_total_score_and_note():
    proc = run_script(high_exposure_payload(), "--format", "markdown")
    assert proc.returncode in (0, 1)
    markdown = proc.stdout
    assert "**Total points:**" in markdown
    assert "exposure scoring" in markdown.lower()


def test_markdown_format_for_empty_input_documents_error():
    proc = run_script("", "--format", "markdown")
    assert proc.returncode == 1
    markdown = proc.stdout
    assert "# Prompt Injection Exposure Score" in markdown
    assert "**Severity:** error" in markdown


def test_markdown_format_for_clean_config_shows_no_factors():
    proc = run_script({}, "--format", "markdown")
    assert proc.returncode == 0
    markdown = proc.stdout
    assert "**Score:** 0" in markdown
    assert "No exposure factors were detected" in markdown
    assert "## Risk factors" not in markdown


def test_json_remains_default_format():
    proc = run_script(high_exposure_payload())
    data = json.loads(proc.stdout)
    assert data["schema_version"] == "1.0"
    assert "score" in data
    assert "factors" in data
