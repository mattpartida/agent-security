import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "score_prompt_injection_exposure.py"


def run_script(payload):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
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
