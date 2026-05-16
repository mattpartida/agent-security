import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"
POLICY_DOC = ROOT / "docs" / "policies.md"
EXAMPLE_POLICY = ROOT / "examples" / "policies" / "agent-security-policy.json"
README = ROOT / "README.md"
ROADMAP = ROOT / "docs" / "roadmap.md"
CHANGELOG = ROOT / "CHANGELOG.md"


def run_script(payload: dict, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )


def browser_private_network_payload() -> dict:
    return {"browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}}}


def shared_browser_payload() -> dict:
    return {
        "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
        "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
    }


def write_policy(tmp_path: Path, policy: dict) -> Path:
    path = tmp_path / "agent-security-policy.json"
    path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    return path


def test_policy_severity_override_is_visible_without_mutating_static_rule_metadata(tmp_path: Path) -> None:
    policy = write_policy(tmp_path, {"version": 1, "severity_overrides": {"ASG-002": "warn"}})

    proc = run_script(browser_private_network_payload(), "--policy", str(policy), "--format", "sarif")

    assert proc.returncode == 0
    sarif = json.loads(proc.stdout)
    result = sarif["runs"][0]["results"][0]
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert result["ruleId"] == "ASG-002"
    assert result["properties"]["severity"] == "warn"
    assert result["properties"]["policy"]["severity_override"] == {"from": "high", "to": "warn"}
    assert rule["properties"]["default_severity"] == "high"


def test_policy_disabled_rules_are_auditable_and_recompute_strict_status(tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path,
        {
            "version": 1,
            "disabled_rules": ["ASG-002"],
            "metadata": {"owner": "security-team", "reason": "Temporarily accepted in isolated local lab."},
        },
    )

    proc = run_script(browser_private_network_payload(), "--policy", str(policy), "--strict")

    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["ok"] is True
    assert data["risk_count"] == 0
    assert data["findings"] == []
    assert data["policy_suppressed_summary"] == {"count": 1, "counts": {"high": 1}}
    suppressed = data["policy_suppressed_findings"]
    assert suppressed[0]["rule_id"] == "ASG-002"
    assert suppressed[0]["policy"]["suppression_type"] == "disabled_rule"
    assert suppressed[0]["policy"]["owner"] == "security-team"


def test_policy_allowlist_suppresses_only_matching_rule_and_evidence_path(tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path,
        {
            "version": 1,
            "allowlists": [
                {
                    "rule_id": "ASG-006",
                    "evidence_paths": ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"],
                    "reason": "Incomplete composite allowlist should not match the shared binding risk.",
                }
            ],
        },
    )

    proc = run_script(shared_browser_payload(), "--policy", str(policy))

    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    active_rule_ids = {finding.get("rule_id") for finding in data["findings"]}
    assert "ASG-006" in active_rule_ids
    assert data["policy_suppressed_findings"] == []
    assert data["policy_suppressed_summary"] == {"count": 0, "counts": {}}


def test_invalid_policy_reports_structured_error_before_scanning(tmp_path: Path) -> None:
    bad_policy = write_policy(tmp_path, {"version": 1, "severity_overrides": {"ASG-002": "urgent"}})

    proc = run_script(browser_private_network_payload(), "--policy", str(bad_policy), "--strict")

    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["findings"] == [
        {
            "severity": "error",
            "risk": "invalid_policy",
            "message": "policy severity override for ASG-002 must be one of: critical, error, high, info, warn",
            "field": "severity_overrides.ASG-002",
        }
    ]
    assert data["policy_suppressed_findings"] == []
    assert data["policy_suppressed_summary"] == {"count": 0, "counts": {}}


def test_policy_docs_example_and_roadmap_are_in_sync() -> None:
    for path in (POLICY_DOC, EXAMPLE_POLICY):
        assert path.exists(), f"missing {path.relative_to(ROOT)}"
        assert path.read_text(encoding="utf-8").endswith("\n")

    example = json.loads(EXAMPLE_POLICY.read_text(encoding="utf-8"))
    assert example["version"] == 1
    assert example["severity_overrides"]
    assert example["disabled_rules"]
    assert example["allowlists"]
    assert all(entry.get("rule_id", "").startswith("ASG-") for entry in example["allowlists"])
    assert all(entry.get("evidence_paths") for entry in example["allowlists"])
    assert all(entry.get("reason") for entry in example["allowlists"])

    doc = POLICY_DOC.read_text(encoding="utf-8")
    for phrase in [
        "Policy files",
        "severity_overrides",
        "disabled_rules",
        "allowlists",
        "policy_suppressed_findings",
        "policy_suppressed_summary",
        "Policy precedence",
        "review patterns",
    ]:
        assert phrase in doc

    readme = README.read_text(encoding="utf-8")
    assert "--policy examples/policies/agent-security-policy.json" in readme
    assert "docs/policies.md" in readme

    changelog = CHANGELOG.read_text(encoding="utf-8")
    assert "--policy <path>" in changelog
    assert "policy_suppressed_findings" in changelog

    roadmap = ROADMAP.read_text(encoding="utf-8")
    phase10 = roadmap.split("## Phase 10:", 1)[1].split("## Phase 11:", 1)[0]
    assert "**Status:** Shipped" in phase10
    assert "tests/test_phase10_policies.py" in phase10
    assert "docs/policies.md" in phase10
