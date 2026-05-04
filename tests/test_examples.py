import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"
EXAMPLES = ROOT / "examples"


def run_config_example(name: str):
    payload = (EXAMPLES / name).read_text()
    proc = subprocess.run(
        [sys.executable, str(CONFIG_SCRIPT)],
        input=payload,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


def test_high_risk_example_triggers_lethal_shared_surface_findings():
    data = run_config_example("high-risk-agent-config.json")

    assert data["ok"] is False
    risks = {finding["risk"] for finding in data["findings"]}
    assert "shared_channel_with_exec_surface" in risks
    assert "shared_channel_with_private_network_browser" in risks
    assert "browser_private_network_allowed" in risks


def test_hardened_example_has_no_high_or_critical_findings():
    data = run_config_example("hardened-agent-config.json")

    assert data["ok"] is True
    severities = {finding["severity"] for finding in data["findings"]}
    assert "critical" not in severities
    assert "high" not in severities
