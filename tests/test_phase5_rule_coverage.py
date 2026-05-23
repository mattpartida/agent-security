import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"
RULE_COVERAGE_DOC = ROOT / "docs" / "rule-coverage.md"


def run_script(payload):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def findings_by_rule(payload):
    data = run_script(payload)
    by_rule = {}
    for finding in data["findings"]:
        rule_id = finding.get("rule_id")
        if rule_id:
            by_rule.setdefault(rule_id, []).append(finding)
    return by_rule


RULE_CASES = {
    "ASG-001": {
        "severity": "high",
        "risky": {
            "tools": {"exec": {"enabled": True}},
            "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
        },
        "safe": {"tools": {"exec": {"enabled": True}}, "bindings": []},
    },
    "ASG-002": {
        "severity": "high",
        "risky": {"browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}}},
        "safe": {"browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": False}}},
    },
    "ASG-003": {
        "severity": "warn",
        "risky": {"memory": {"enabled": True}, "browser": {"enabled": True}},
        "safe": {"memory": {"enabled": True}},
    },
    "ASG-004": {
        "severity": "high",
        "risky": {"tools": {"elevated": {"enabled": True}}},
        "safe": {"tools": {"elevated": {"enabled": True, "allowFrom": ["owner"]}}},
    },
    "ASG-005": {
        "severity": "warn",
        "risky": {"agents": {"defaults": {"model": "ollama/qwen2.5:7b"}}},
        "safe": {"agents": {"defaults": {"model": "openai/gpt-5.2"}}},
    },
    "ASG-006": {
        "severity": "critical",
        "risky": {
            "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
            "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
        },
        "safe": {"browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}}, "bindings": []},
    },
    "ASG-007": {
        "severity": "high",
        "risky": {
            "tools": {"elevated": {"allowFrom": ["owner"]}},
            "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
        },
        "safe": {"tools": {"elevated": {"allowFrom": ["owner"]}}, "bindings": []},
    },
    "ASG-008": {
        "severity": "high",
        "risky": {"tools": {"exec": {"security": "full"}}},
        "safe": {"tools": {"exec": {"security": "approval"}}},
    },
    "ASG-009": {
        "severity": "high",
        "risky": {
            "channels": {"discord": {"enabled": True, "execApprovals": {"enabled": True}}},
            "tools": {"exec": {"enabled": True}},
        },
        "safe": {
            "channels": {"discord": {"enabled": True, "execApprovals": {"enabled": True, "approvers": ["owner"]}}},
            "tools": {"exec": {"enabled": True}},
        },
    },
    "ASG-010": {
        "severity": "warn",
        "risky": {"channels": {"discord": {"enabled": True}}, "tools": {"exec": {"enabled": True}}},
        "safe": {
            "channels": {"discord": {"enabled": True, "execApprovals": {"enabled": True, "approvers": ["owner"]}}},
            "tools": {"exec": {"enabled": True}},
        },
    },
    "ASG-011": {
        "severity": "warn",
        "risky": {"tools": {"fs": {"workspaceOnly": False}}},
        "safe": {"tools": {"fs": {"workspaceOnly": True}}},
    },
    "ASG-012": {
        "severity": "warn",
        "risky": {"sandbox": {"enabled": False}},
        "safe": {"sandbox": {"enabled": True}},
    },
    "ASG-013": {
        "severity": "warn",
        "risky": {"tools": {"exec": {"enabled": True}}},
        "safe": {"tools": {"exec": {"enabled": True}}, "commands": {"ownerAllowFrom": ["owner"]}},
    },
    "ASG-014": {
        "severity": "info",
        "risky": {"channels": {"discord": {"enabled": True, "groupPolicy": "all"}}},
        "safe": {"channels": {"discord": {"enabled": True, "groupPolicy": "dm"}}},
    },
    "ASG-015": {
        "severity": "info",
        "risky": {"bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}]},
        "safe": {"bindings": [{"agentId": "dm", "match": {"channel": "discord", "peer": {"kind": "dm"}}}]},
    },
}


def test_every_asg_rule_has_risky_and_safe_negative_coverage():
    assert set(RULE_CASES) == {f"ASG-{idx:03d}" for idx in range(1, 16)}
    for rule_id, case in RULE_CASES.items():
        risky_findings = findings_by_rule(case["risky"])
        assert rule_id in risky_findings, rule_id
        assert any(finding["severity"] == case["severity"] for finding in risky_findings[rule_id]), rule_id
        assert all(finding.get("evidence_paths") for finding in risky_findings[rule_id]), rule_id
        assert all(finding.get("recommendation") for finding in risky_findings[rule_id]), rule_id

        safe_findings = findings_by_rule(case["safe"])
        assert rule_id not in safe_findings, rule_id


def test_multi_risk_rule_ids_cover_documented_variants():
    agent_elevated = findings_by_rule({"agents": {"list": [{"id": "worker", "tools": {"elevated": {"enabled": True}}}]}})
    assert any(finding["risk"] == "agent_elevated_without_allowlist" for finding in agent_elevated["ASG-004"])

    safe_agent_elevated = findings_by_rule({
        "agents": {"list": [{"id": "worker", "tools": {"elevated": {"enabled": True, "allowFrom": ["owner"]}}}]}
    })
    assert "ASG-004" not in safe_agent_elevated

    risky_agent_model = findings_by_rule({
        "agents": {"list": [{"id": "worker", "model": "local/phi-3-mini", "tools": {"exec": {"enabled": True}}}]}
    })
    assert any(finding["risk"] == "risky_agent_model_with_tools" for finding in risky_agent_model["ASG-005"])

    safe_agent_model = findings_by_rule({"agents": {"list": [{"id": "worker", "model": "local/phi-3-mini"}]}})
    assert "ASG-005" not in safe_agent_model


def test_rule_coverage_document_maps_every_rule_to_risky_safe_and_severity_rationale():
    doc = RULE_COVERAGE_DOC.read_text(encoding="utf-8")
    assert "# Agent Security Rule Coverage" in doc
    assert "No Phase 5 detection semantics changed" in doc
    for rule_id in RULE_CASES:
        assert f"| {rule_id} |" in doc
    for required_phrase in (
        "Risky coverage",
        "Safe/negative coverage",
        "Severity rationale",
        "Compensating control",
        "tests/test_phase5_rule_coverage.py",
    ):
        assert required_phrase in doc


def test_phase5_roadmap_and_readme_point_to_rule_coverage():
    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    phase5 = roadmap.split("## Phase 5:", 1)[1].split("## Phase 6:", 1)[0]
    assert "**Status:** Shipped" in phase5
    assert "docs/rule-coverage.md" in phase5
    assert "No severity or detection semantics changed" in phase5

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/rule-coverage.md" in readme
