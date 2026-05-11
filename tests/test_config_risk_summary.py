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


def pretty_json(payload):
    return json.dumps(payload, indent=2)


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


def high_risk_payload():
    return {
        "channels": {"discord": {"enabled": True}},
        "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
        "tools": {
            "exec": {"security": "full"},
            "elevated": {"enabled": True},
        },
        "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
        "memory": {"enabled": True},
    }


def test_key_findings_include_stable_rule_ids():
    proc = run_script(high_risk_payload())
    data = json.loads(proc.stdout)
    findings_by_risk = {finding["risk"]: finding for finding in data["findings"]}
    assert findings_by_risk["shared_channel_with_exec_surface"]["rule_id"] == "ASG-001"
    assert findings_by_risk["browser_private_network_allowed"]["rule_id"] == "ASG-002"
    assert findings_by_risk["persistence_available_in_untrusted_content_context"]["rule_id"] == "ASG-003"
    assert findings_by_risk["elevated_enabled_without_allowlist"]["rule_id"] == "ASG-004"
    assert findings_by_risk["exec_security_full"]["rule_id"] == "ASG-008"


def test_asg_findings_include_evidence_paths_and_best_effort_source_locations():
    payload = high_risk_payload()
    proc = run_script(pretty_json(payload))
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    asg_findings = [finding for finding in data["findings"] if finding.get("rule_id", "").startswith("ASG-")]
    assert asg_findings
    assert all(finding.get("evidence_paths") for finding in asg_findings)
    assert all(finding.get("source_locations") for finding in asg_findings)

    findings_by_risk = {finding["risk"]: finding for finding in asg_findings}
    assert findings_by_risk["browser_private_network_allowed"]["evidence_paths"] == [
        "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"
    ]
    browser_location = findings_by_risk["browser_private_network_allowed"]["source_locations"][0]
    assert browser_location == {
        "path": "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork",
        "line": 10,
    }

    composite = findings_by_risk["shared_channel_with_private_network_browser"]
    assert composite["evidence_paths"] == [
        "bindings[0].match.channel",
        "bindings[0].match.peer.kind",
        "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork",
    ]
    assert {location["line"] for location in composite["source_locations"]} >= {10, 25, 27}


def test_array_evidence_paths_use_indexes_and_unresolved_paths_fall_back_to_line_one():
    payload = {"agents": {"list": [{"id": "agent-one", "tools": {"elevated": {"enabled": True}}}]}}
    proc = run_script(pretty_json(payload))
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    finding = next(finding for finding in data["findings"] if finding["risk"] == "agent_elevated_without_allowlist")
    assert finding["evidence_paths"] == ["agents.list[0].tools.elevated.allowFrom"]
    assert finding["evidence"] == {"agent": "agent-one"}
    assert finding["source_locations"] == [{"path": "agents.list[0].tools.elevated.allowFrom", "line": 1}]


def test_binding_array_source_locations_respect_indexes():
    payload = {
        "bindings": [
            {"agentId": "dm", "match": {"channel": "discord", "peer": {"kind": "dm"}}},
            {"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}},
        ]
    }
    proc = run_script(pretty_json(payload))
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    finding = next(finding for finding in data["findings"] if finding["risk"] == "discord_channel_binding")
    assert finding["evidence_paths"] == ["bindings[1].match.channel", "bindings[1].match.peer.kind"]
    assert finding["source_locations"] == [
        {"path": "bindings[1].match.channel", "line": 15},
        {"path": "bindings[1].match.peer.kind", "line": 17},
    ]


def test_composite_evidence_paths_use_causal_exec_and_elevated_fields():
    payload = {
        "tools": {
            "exec": {"enabled": True},
            "elevated": {"allowFrom": ["owner"]},
        },
        "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
    }
    proc = run_script(pretty_json(payload))
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    findings_by_risk = {finding["risk"]: finding for finding in data["findings"]}
    assert findings_by_risk["shared_channel_with_exec_surface"]["evidence_paths"] == [
        "bindings[0].match.channel",
        "bindings[0].match.peer.kind",
        "tools.exec.enabled",
    ]
    assert findings_by_risk["shared_channel_with_elevated_surface"]["evidence_paths"] == [
        "bindings[0].match.channel",
        "bindings[0].match.peer.kind",
        "tools.elevated.allowFrom",
    ]


def test_explicit_json_format_matches_default_json_output():
    default_proc = run_script(high_risk_payload())
    json_proc = run_script(high_risk_payload(), "--format", "json")
    assert default_proc.returncode == 0
    assert json_proc.returncode == 0
    assert json.loads(json_proc.stdout) == json.loads(default_proc.stdout)


def test_markdown_format_renders_summary_counts_and_findings_table():
    proc = run_script(high_risk_payload(), "--format", "markdown")
    assert proc.returncode == 0
    assert proc.stdout.startswith("# Agent Security Config Risk Summary\n")
    assert "**Overall:** high risk findings present" in proc.stdout
    assert "**Risk count:**" in proc.stdout
    assert "- **critical:** 1" in proc.stdout
    assert "| Severity | Rule | Risk | Evidence | Recommendation |" in proc.stdout
    assert "| high | ASG-002 | browser_private_network_allowed | `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` |" in proc.stdout
    assert "| critical | ASG-006 | shared_channel_with_private_network_browser |" in proc.stdout


def test_markdown_format_escapes_table_pipes():
    proc = run_script({"agents": {"list": [{"id": "agent|one", "tools": {"elevated": {"enabled": True}}}]}}, "--format", "markdown")
    assert proc.returncode == 0
    assert "agent\\|one" in proc.stdout


def test_sarif_format_emits_parseable_rule_metadata_and_results():
    proc = run_script(high_risk_payload(), "--format", "sarif")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["version"] == "2.1.0"
    assert data["$schema"].endswith("sarif-schema-2.1.0.json")
    run = data["runs"][0]
    rules_by_id = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert "ASG-001" in rules_by_id
    assert rules_by_id["ASG-001"]["shortDescription"]["text"] == "shared_channel_with_exec_surface"
    assert rules_by_id["ASG-002"]["properties"]["default_severity"] == "high"
    results = run["results"]
    assert any(result["ruleId"] == "ASG-002" for result in results)
    assert any(result["ruleId"] == "ASG-006" for result in results)
    assert all(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "stdin" for result in results)


def test_sarif_format_uses_best_effort_source_line_and_evidence_paths_properties():
    proc = run_script(pretty_json(high_risk_payload()), "--format", "sarif")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    results = data["runs"][0]["results"]
    private_network = next(result for result in results if result["ruleId"] == "ASG-002")
    assert private_network["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert private_network["properties"]["evidence_paths"] == ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"]

    composite = next(result for result in results if result["ruleId"] == "ASG-006")
    assert composite["locations"][0]["physicalLocation"]["region"]["startLine"] == 10
    assert composite["properties"]["evidence_paths"] == [
        "bindings[0].match.channel",
        "bindings[0].match.peer.kind",
        "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork",
    ]


def test_sarif_source_line_uses_causal_elevated_field_in_composite_finding():
    payload = {
        "tools": {"elevated": {"enabled": True}},
        "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
    }
    proc = run_script(pretty_json(payload), "--format", "sarif")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    result = next(result for result in data["runs"][0]["results"] if result["ruleId"] == "ASG-007")
    assert result["properties"]["source_locations"] == [
        {"path": "bindings[0].match.channel", "line": 11},
        {"path": "bindings[0].match.peer.kind", "line": 13},
        {"path": "tools.elevated.enabled", "line": 4},
    ]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 4


def test_sarif_format_includes_all_emitted_rule_ids_in_driver_rules():
    proc = run_script(high_risk_payload(), "--format", "sarif")
    data = json.loads(proc.stdout)
    rules = {rule["id"] for rule in data["runs"][0]["tool"]["driver"]["rules"]}
    result_rule_ids = {result["ruleId"] for result in data["runs"][0]["results"] if result.get("ruleId")}
    assert result_rule_ids <= rules


def test_markdown_error_only_input_reports_error_not_high_risk():
    proc = run_script("", "--format", "markdown")
    assert proc.returncode == 0
    assert "**Overall:** scanner input error" in proc.stdout
    assert "**Overall:** high risk findings present" not in proc.stdout
    assert "| error |  | empty_input |" in proc.stdout


def test_sarif_error_only_input_defines_synthetic_rule_metadata():
    proc = run_script("not-json", "--format", "sarif")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    run = data["runs"][0]
    rules = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    results = run["results"]
    assert results[0]["ruleId"] == "invalid_json"
    assert "invalid_json" in rules
    assert results[0]["level"] == "error"
