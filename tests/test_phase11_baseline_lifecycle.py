import json
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"
BASELINE_LIFECYCLE_DOC = ROOT / "docs" / "baseline-lifecycle.md"
EXAMPLE_BASELINE = ROOT / "examples" / "baselines" / "agent-security-baseline.json"
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


def write_baseline(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "agent-security-baseline.json"
    path.write_text(json.dumps({"version": 1, "suppressions": entries}, indent=2), encoding="utf-8")
    return path


def future_date() -> str:
    return (date.today() + timedelta(days=30)).isoformat()


def past_date() -> str:
    return (date.today() - timedelta(days=1)).isoformat()


def suppression(*, expires_at: str | None = None, evidence_paths: list[str] | None = None, owner: str = "platform-security") -> dict:
    return {
        "rule_id": "ASG-002",
        "evidence_paths": evidence_paths or ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"],
        "owner": owner,
        "ticket": "SEC-123",
        "reason": "Reviewed temporary local-browser exception during migration.",
        "expires_at": expires_at or future_date(),
    }


def test_generate_baseline_emits_current_findings_with_todo_lifecycle_metadata() -> None:
    proc = run_script(browser_private_network_payload(), "--generate-baseline")

    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["version"] == 1
    assert data["generated_by"] == "config_risk_summary.py"
    assert data["suppressions"]
    entry = data["suppressions"][0]
    assert entry["rule_id"] == "ASG-002"
    assert entry["evidence_paths"] == ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"]
    assert entry["owner"] == "TODO-owner"
    assert entry["ticket"] == "TODO-ticket"
    assert entry["reason"].startswith("TODO")
    date.fromisoformat(entry["expires_at"])


def test_baseline_requires_lifecycle_metadata_before_suppressing(tmp_path: Path) -> None:
    baseline = write_baseline(
        tmp_path,
        [
            {
                "rule_id": "ASG-002",
                "evidence_paths": ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"],
                "reason": "Legacy Phase 9 shape without ticket and expiry should fail closed.",
                "owner": "security-team",
            }
        ],
    )

    proc = run_script(browser_private_network_payload(), "--baseline", str(baseline), "--strict")

    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["findings"][0]["risk"] == "invalid_baseline"
    assert "requires non-empty ticket" in data["findings"][0]["message"]
    assert data["suppressed_findings"] == []


def test_expired_baseline_entry_does_not_suppress_and_is_reported_by_owner(tmp_path: Path) -> None:
    baseline = write_baseline(tmp_path, [suppression(expires_at=past_date())])

    proc = run_script(browser_private_network_payload(), "--baseline", str(baseline), "--strict")

    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["risk_count"] == 1
    assert data["findings"][0]["rule_id"] == "ASG-002"
    assert data["suppressed_findings"] == []
    assert data["baseline_lifecycle"]["expired"][0]["rule_id"] == "ASG-002"
    assert data["baseline_lifecycle"]["expired"][0]["finding"]["rule_id"] == "ASG-002"
    assert data["baseline_lifecycle"]["owner_summary"] == {
        "platform-security": {"active": 0, "expired": 1, "stale": 0}
    }


def test_stale_baseline_entry_is_distinct_from_expired_and_can_fail_cleanup_flag(tmp_path: Path) -> None:
    baseline = write_baseline(tmp_path, [suppression(evidence_paths=["browser.privateNetworkAccess"], owner="appsec")])

    normal = run_script(browser_private_network_payload(), "--baseline", str(baseline))
    assert normal.returncode == 0
    data = json.loads(normal.stdout)
    assert data["baseline_lifecycle"]["stale"][0]["rule_id"] == "ASG-002"
    assert data["baseline_lifecycle"]["expired"] == []
    assert data["baseline_lifecycle"]["owner_summary"] == {"appsec": {"active": 0, "expired": 0, "stale": 1}}

    cleanup = run_script(browser_private_network_payload(), "--baseline", str(baseline), "--fail-on-stale-baseline")
    assert cleanup.returncode == 1


def test_expired_baseline_fail_flag_is_independent_from_stale_flag(tmp_path: Path) -> None:
    baseline = write_baseline(tmp_path, [suppression(expires_at=past_date())])

    stale_only = run_script(browser_private_network_payload(), "--baseline", str(baseline), "--fail-on-stale-baseline")
    expired = run_script(browser_private_network_payload(), "--baseline", str(baseline), "--fail-on-expired-baseline")

    assert stale_only.returncode == 0
    assert expired.returncode == 1


def test_baseline_lifecycle_docs_example_changelog_and_roadmap_are_in_sync() -> None:
    for path in (BASELINE_LIFECYCLE_DOC, EXAMPLE_BASELINE):
        assert path.exists(), f"missing {path.relative_to(ROOT)}"
        assert path.read_text(encoding="utf-8").endswith("\n")

    example = json.loads(EXAMPLE_BASELINE.read_text(encoding="utf-8"))
    assert example["version"] == 1
    assert example["suppressions"]
    assert all(entry.get("owner") and entry.get("ticket") and entry.get("reason") for entry in example["suppressions"])
    assert all(date.fromisoformat(entry["expires_at"]) for entry in example["suppressions"])

    doc = BASELINE_LIFECYCLE_DOC.read_text(encoding="utf-8")
    for phrase in [
        "Baseline lifecycle tooling",
        "--generate-baseline",
        "owner",
        "ticket",
        "reason",
        "expires_at",
        "baseline_lifecycle",
        "stale",
        "expired",
        "--fail-on-stale-baseline",
        "--fail-on-expired-baseline",
        "owner_summary",
    ]:
        assert phrase in doc

    readme = README.read_text(encoding="utf-8")
    assert "--generate-baseline" in readme
    assert "docs/baseline-lifecycle.md" in readme

    changelog = CHANGELOG.read_text(encoding="utf-8")
    assert "--generate-baseline" in changelog
    assert "baseline_lifecycle" in changelog

    roadmap = ROADMAP.read_text(encoding="utf-8")
    phase11 = roadmap.split("## Phase 11:", 1)[1].split("## Phase 12:", 1)[0]
    assert "**Status:** Shipped" in phase11
    assert "tests/test_phase11_baseline_lifecycle.py" in phase11
    assert "docs/baseline-lifecycle.md" in phase11
