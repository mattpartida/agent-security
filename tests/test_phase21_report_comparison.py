import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"
README = ROOT / "README.md"
ROADMAP = ROOT / "docs" / "roadmap.md"
CHANGELOG = ROOT / "CHANGELOG.md"
COMPARISON_DOC = ROOT / "docs" / "report-comparison.md"
CI_DOC = ROOT / "docs" / "ci-integration.md"
SKILL_DOC = ROOT / "skills" / "agent-security" / "SKILL.md"
COMPARE_WORKFLOW = ROOT / "examples" / "ci" / "github-actions" / "agent-security-compare-reports.yml"

SHA256_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
BROWSER_PRIVATE_NETWORK = {
    "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}}
}
SHARED_BROWSER = {
    "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
    "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
}
HARDENED_BROWSER = {
    "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": False}}
}


def run_script(*args: str, payload: dict | None = None, stdin: str | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    if payload is not None:
        stdin = json.dumps(payload)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input="" if stdin is None else stdin,
        text=True,
        capture_output=True,
        check=check,
    )


def scan(payload: dict, *args: str) -> dict:
    proc = run_script(*args, payload=payload)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def write_report(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_json_findings_include_stable_sha256_fingerprints() -> None:
    data = scan(BROWSER_PRIVATE_NETWORK)
    asg002 = [finding for finding in data["findings"] if finding.get("rule_id") == "ASG-002"]
    assert asg002, data["findings"]
    fingerprint = asg002[0]["fingerprint"]
    assert SHA256_FINGERPRINT.fullmatch(fingerprint)
    assert len(fingerprint) == 71

    again = scan(BROWSER_PRIVATE_NETWORK)
    again_asg002 = [finding for finding in again["findings"] if finding.get("rule_id") == "ASG-002"]
    assert again_asg002[0]["fingerprint"] == fingerprint


def test_fingerprint_changes_when_evidence_paths_change() -> None:
    browser_only = scan(BROWSER_PRIVATE_NETWORK)
    shared = scan(SHARED_BROWSER)
    browser_fp = next(finding["fingerprint"] for finding in browser_only["findings"] if finding.get("rule_id") == "ASG-002")
    shared_fp = next(finding["fingerprint"] for finding in shared["findings"] if finding.get("rule_id") == "ASG-006")
    assert browser_fp != shared_fp


def test_sarif_includes_fingerprint_properties_and_partial_fingerprints() -> None:
    proc = run_script("--format", "sarif", payload=BROWSER_PRIVATE_NETWORK)
    assert proc.returncode == 0, proc.stderr
    sarif = json.loads(proc.stdout)
    results = sarif["runs"][0]["results"]
    asg002 = [result for result in results if result.get("ruleId") == "ASG-002"]
    assert asg002
    fingerprint = asg002[0]["properties"]["fingerprint"]
    assert SHA256_FINGERPRINT.fullmatch(fingerprint)
    assert asg002[0]["partialFingerprints"]["agentSecurityFinding"] == fingerprint


def test_compare_reports_classifies_new_persisting_and_resolved(tmp_path: Path) -> None:
    before = write_report(tmp_path / "before.json", scan(SHARED_BROWSER))
    after = write_report(tmp_path / "after.json", scan(BROWSER_PRIVATE_NETWORK))

    proc = run_script("--compare-reports", str(before), str(after))
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["schema_version"] == "1.0"
    assert data["writes_to_reports"] is False
    assert data["counts"]["new"] >= 0
    new_ids = {finding["rule_id"] for finding in data["new_findings"]}
    persisting_ids = {finding["rule_id"] for finding in data["persisting_findings"]}
    resolved_ids = {finding["rule_id"] for finding in data["resolved_findings"]}
    assert "ASG-002" in persisting_ids
    assert "ASG-006" in resolved_ids
    assert "ASG-001" not in new_ids


def test_compare_reports_derives_fingerprints_for_legacy_reports(tmp_path: Path) -> None:
    current = scan(BROWSER_PRIVATE_NETWORK)
    legacy = json.loads(json.dumps(current))
    for finding in legacy["findings"]:
        finding.pop("fingerprint", None)
    before = write_report(tmp_path / "legacy.json", legacy)
    after = write_report(tmp_path / "current.json", current)

    proc = run_script("--compare-reports", str(before), str(after))
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["counts"]["new"] == 0
    assert data["counts"]["resolved"] == 0
    assert data["counts"]["persisting"] == len(current["findings"])
    assert all(SHA256_FINGERPRINT.fullmatch(finding["fingerprint"]) for finding in data["persisting_findings"])


def test_fail_on_new_preserves_stdout_and_exit_code(tmp_path: Path) -> None:
    before = write_report(tmp_path / "before.json", scan(HARDENED_BROWSER))
    after = write_report(tmp_path / "after.json", scan(BROWSER_PRIVATE_NETWORK))

    default_compare = run_script("--compare-reports", str(before), str(after))
    assert default_compare.returncode == 0, default_compare.stderr
    default_data = json.loads(default_compare.stdout)
    assert default_data["new_findings"]
    assert default_data["ok"] is False

    gated = run_script("--compare-reports", str(before), str(after), "--fail-on-new")
    assert gated.returncode == 1
    gated_data = json.loads(gated.stdout)
    assert gated_data["new_findings"]
    assert {finding["rule_id"] for finding in gated_data["new_findings"]} >= {"ASG-002"}

    no_new = run_script(
        "--compare-reports",
        str(after),
        str(after),
        "--fail-on-new",
    )
    assert no_new.returncode == 0, no_new.stderr
    assert json.loads(no_new.stdout)["counts"]["new"] == 0


def test_compare_reports_rejects_sarif_and_scan_flags(tmp_path: Path) -> None:
    report = write_report(tmp_path / "report.json", scan(BROWSER_PRIVATE_NETWORK))
    sarif = run_script("--compare-reports", str(report), str(report), "--format", "sarif")
    assert sarif.returncode == 2
    assert "compare-reports" in sarif.stderr.lower() or "sarif" in sarif.stderr.lower()

    mixed = run_script("--compare-reports", str(report), str(report), "--strict")
    assert mixed.returncode == 2
    assert mixed.stdout == ""


def test_compare_reports_does_not_read_stdin(tmp_path: Path) -> None:
    report = write_report(tmp_path / "report.json", scan(BROWSER_PRIVATE_NETWORK))
    proc = run_script(
        "--compare-reports",
        str(report),
        str(report),
        stdin=json.dumps(SHARED_BROWSER),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["counts"]["new"] == 0
    assert data["counts"]["resolved"] == 0


def test_compare_reports_rejects_duplicate_identities_and_missing_findings(tmp_path: Path) -> None:
    current = scan(BROWSER_PRIVATE_NETWORK)
    duplicated = json.loads(json.dumps(current))
    duplicated["findings"].append(json.loads(json.dumps(duplicated["findings"][0])))
    bad = write_report(tmp_path / "dup.json", duplicated)
    good = write_report(tmp_path / "good.json", current)
    dup = run_script("--compare-reports", str(bad), str(good))
    assert dup.returncode == 2
    assert "duplicate" in dup.stderr.lower()

    invalid = write_report(tmp_path / "invalid.json", {"schema_version": "1.0", "ok": True})
    missing = run_script("--compare-reports", str(invalid), str(good))
    assert missing.returncode == 2
    assert "findings" in missing.stderr.lower()


def test_markdown_comparison_escapes_pipes_and_mentions(tmp_path: Path) -> None:
    before_report = scan(HARDENED_BROWSER)
    after_report = scan(BROWSER_PRIVATE_NETWORK)
    after_report["findings"][0]["risk"] = "notify @everyone about a|b"
    after_report["findings"][0]["recommendation"] = "ping @here and keep C:\\path"
    after_report["findings"][0].pop("fingerprint", None)
    before = write_report(tmp_path / "before.json", before_report)
    after = write_report(tmp_path / "after.json", after_report)

    proc = run_script("--compare-reports", str(before), str(after), "--format", "markdown")
    assert proc.returncode == 0, proc.stderr
    markdown = proc.stdout
    assert "@everyone" not in markdown
    assert "@here" not in markdown
    assert "|" not in markdown.splitlines()[0] or "\\|" in markdown
    assert "\\|" in markdown or "notify" in markdown


def test_phase21_docs_examples_and_roadmap() -> None:
    readme = README.read_text(encoding="utf-8")
    roadmap = ROADMAP.read_text(encoding="utf-8")
    changelog = CHANGELOG.read_text(encoding="utf-8")
    comparison = COMPARISON_DOC.read_text(encoding="utf-8")
    ci_doc = CI_DOC.read_text(encoding="utf-8")
    skill = SKILL_DOC.read_text(encoding="utf-8")
    workflow = COMPARE_WORKFLOW.read_text(encoding="utf-8")

    assert "--compare-reports" in readme
    assert "--fail-on-new" in readme
    assert "docs/report-comparison.md" in readme
    assert "## Phase 21:" in roadmap
    assert "**Status:** Shipped" in roadmap.split("## Phase 21:", 1)[1].split("## Phase 22:", 1)[0]
    assert "**Status:** Planned" in roadmap.split("## Phase 22:", 1)[1].split("## Phase 23:", 1)[0]
    assert "--compare-reports" in changelog
    assert "--fail-on-new" in comparison
    assert "fingerprint" in comparison
    assert "writes_to_reports" in comparison
    assert "--compare-reports" in ci_doc
    assert "--compare-reports" in skill
    assert "permissions:" in workflow
    assert "contents: read" in workflow
    assert "contents: write" not in workflow
    assert "pull-requests: write" not in workflow
    assert "--fail-on-new" in workflow
    assert "python3 skills/agent-security/scripts/config_risk_summary.py" in workflow
