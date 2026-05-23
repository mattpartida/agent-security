import json
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"
BASELINE_DOC = ROOT / "docs" / "baselines.md"
EXAMPLE_BASELINE = ROOT / "examples" / "baselines" / "agent-security-baseline.json"
README = ROOT / "README.md"
ROADMAP = ROOT / "docs" / "roadmap.md"


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


def write_baseline(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "agent-security-baseline.json"
    path.write_text(json.dumps({"version": 1, "suppressions": entries}, indent=2), encoding="utf-8")
    return path


def lifecycle_metadata() -> dict[str, str]:
    return {
        "reason": "Tracked legacy browser config while the team migrates shared profiles.",
        "owner": "security-team",
        "ticket": "SEC-123",
        "expires_at": (date.today() + timedelta(days=30)).isoformat(),
    }


def test_baseline_suppresses_exact_rule_and_evidence_path(tmp_path: Path) -> None:
    baseline = write_baseline(
        tmp_path,
        [
            {
                "rule_id": "ASG-002",
                "evidence_paths": ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"],
                **lifecycle_metadata(),
            }
        ],
    )

    proc = run_script(browser_private_network_payload(), "--baseline", str(baseline), "--strict")
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["ok"] is True
    assert data["risk_count"] == 0
    assert data["findings"] == []
    assert data["suppressed_summary"] == {"count": 1, "counts": {"high": 1}}
    suppressed = data["suppressed_findings"]
    assert len(suppressed) == 1
    assert suppressed[0]["rule_id"] == "ASG-002"
    assert suppressed[0]["suppression"]["owner"] == "security-team"
    assert suppressed[0]["suppression"]["reason"].startswith("Tracked legacy")


def test_baseline_does_not_suppress_same_rule_at_different_evidence_path(tmp_path: Path) -> None:
    baseline = write_baseline(
        tmp_path,
        [
            {
                "rule_id": "ASG-006",
                "evidence_paths": ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"],
                **lifecycle_metadata(),
            }
        ],
    )

    proc = run_script(shared_browser_payload(), "--baseline", str(baseline))
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    active_rule_ids = {finding.get("rule_id") for finding in data["findings"]}
    assert "ASG-006" in active_rule_ids
    assert data["suppressed_summary"]["count"] == 0
    assert data["suppressed_findings"] == []


def test_invalid_baseline_reports_structured_error_before_suppressing(tmp_path: Path) -> None:
    bad_baseline = tmp_path / "bad-baseline.json"
    bad_baseline.write_text(json.dumps({"version": 1, "suppressions": [{"evidence_paths": []}]}), encoding="utf-8")

    proc = run_script(browser_private_network_payload(), "--baseline", str(bad_baseline), "--strict")
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["findings"][0]["severity"] == "error"
    assert data["findings"][0]["risk"] == "invalid_baseline"
    assert data["suppressed_summary"] == {"count": 0, "counts": {}}


def test_baseline_docs_example_and_roadmap_are_in_sync() -> None:
    for path in (BASELINE_DOC, EXAMPLE_BASELINE):
        assert path.exists(), f"missing {path.relative_to(ROOT)}"
        assert path.read_text(encoding="utf-8").endswith("\n")

    example = json.loads(EXAMPLE_BASELINE.read_text(encoding="utf-8"))
    assert example["version"] == 1
    assert example["suppressions"]
    assert all(entry.get("rule_id", "").startswith("ASG-") for entry in example["suppressions"])
    assert all(entry.get("evidence_paths") for entry in example["suppressions"])
    assert all(entry.get("reason") and entry.get("owner") for entry in example["suppressions"])

    doc = BASELINE_DOC.read_text(encoding="utf-8")
    for phrase in [
        "Auditable baselines",
        "exact `rule_id`",
        "evidence path",
        "suppressed_findings",
        "suppressed_summary",
        "review cadence",
        "remove suppressions",
    ]:
        assert phrase in doc

    readme = README.read_text(encoding="utf-8")
    assert "docs/baselines.md" in readme
    assert "examples/baselines/agent-security-baseline.json" in readme

    roadmap = ROADMAP.read_text(encoding="utf-8")
    assert "## Phase 9: Auditable baselines and suppressions" in roadmap
    assert "**Status:** Shipped" in roadmap
    assert "tests/test_phase9_baselines.py" in roadmap
    assert "## Phase 12: Schema adapter expansion and compatibility contract" in roadmap
