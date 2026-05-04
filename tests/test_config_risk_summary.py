import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"


def run_script(payload, *args):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=json.dumps(payload) if not isinstance(payload, str) else payload,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc


def test_empty_input_returns_json_error():
    proc = run_script("")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["findings"][0]["risk"] == "empty_input"


def test_wrong_type_fallback_does_not_crash():
    proc = run_script({"agents": {"defaults": {"model": {"fallbacks": [123, None, "ollama/qwen2.5:7b"]}}}})
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert any(f["risk"] == "risky_default_model" for f in data["findings"])


def test_disabled_elevated_does_not_warn_missing_allowlist():
    proc = run_script({"tools": {"elevated": {"enabled": False}}})
    data = json.loads(proc.stdout)
    assert not any(f["risk"] == "elevated_enabled_without_allowlist" for f in data["findings"])


def test_compound_shared_channel_private_network_is_critical():
    payload = {
        "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
        "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
    }
    proc = run_script(payload)
    data = json.loads(proc.stdout)
    assert any(f["risk"] == "shared_channel_with_private_network_browser" for f in data["findings"])
