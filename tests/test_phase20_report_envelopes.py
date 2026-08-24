import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"
VERIFIER = ROOT / "skills" / "agent-security" / "scripts" / "verify_report_envelope.py"
DOC = ROOT / "docs" / "report-envelopes.md"

SECRET = "test-envelope-secret-0123456789abcdef"

HIGH_RISK_PAYLOAD = {
    "channels": {"discord": {"enabled": True}},
    "browser": {"enabled": True, "ssrfPolicy": {"dangerouslyAllowPrivateNetwork": True}},
    "tools": {"exec": {"security": "full"}},
    "bindings": [{"agentId": "shared", "match": {"channel": "discord", "peer": {"kind": "channel"}}}],
}


def run_script(script: Path, payload, *args: str) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [sys.executable, str(script), *args],
        input=json.dumps(payload) if not isinstance(payload, str) else payload,
        text=True,
        capture_output=True,
        check=False,
    )
    return proc


def write_secret(tmp_path: Path, value: str, name: str = "agent-security.key") -> Path:
    secret_path = tmp_path / name
    secret_path.write_text(value, encoding="utf-8")
    return secret_path


def signed_report(tmp_path: Path, payload=HIGH_RISK_PAYLOAD, secret: str = SECRET) -> dict:
    secret_path = write_secret(tmp_path, secret)
    proc = run_script(SCRIPT, payload, "--envelope-secret-file", str(secret_path))
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def verify(report: dict, *args: str) -> subprocess.CompletedProcess[str]:
    return run_script(VERIFIER, json.dumps(report), *args)


def test_envelope_absent_by_default_keeps_output_compatible():
    proc = run_script(SCRIPT, HIGH_RISK_PAYLOAD)
    data = json.loads(proc.stdout)
    assert "report_envelope" not in data
    assert data["schema_version"] == "1.0"
    assert any(f["risk"] == "shared_channel_with_private_network_browser" for f in data["findings"])


def test_envelope_secret_file_adds_hmac_envelope(tmp_path):
    secret_path = write_secret(tmp_path, SECRET)
    proc = run_script(SCRIPT, HIGH_RISK_PAYLOAD, "--envelope-secret-file", str(secret_path))
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    envelope = data["report_envelope"]
    assert envelope["algorithm"] == "hmac-sha256"
    assert len(envelope["payload_sha256"]) == 64
    assert len(envelope["signature"]) == 64
    assert "findings" in envelope["covered_fields"]
    assert "report_envelope" not in envelope["covered_fields"]


def test_envelope_signature_is_deterministic_and_stable_across_runs(tmp_path):
    secret_path = write_secret(tmp_path, SECRET)
    first = json.loads(run_script(SCRIPT, HIGH_RISK_PAYLOAD, "--envelope-secret-file", str(secret_path)).stdout)
    second = json.loads(run_script(SCRIPT, HIGH_RISK_PAYLOAD, "--envelope-secret-file", str(secret_path)).stdout)
    assert first["report_envelope"] == second["report_envelope"]


def test_envelope_ignores_one_trailing_newline_in_secret_file(tmp_path):
    padded = signed_report(tmp_path, secret=SECRET + "\n")
    plain = signed_report(tmp_path, secret=SECRET)
    assert padded["report_envelope"]["signature"] == plain["report_envelope"]["signature"]


def test_envelope_rejects_empty_secret_with_structured_finding(tmp_path):
    secret_path = write_secret(tmp_path, "\n")
    proc = run_script(SCRIPT, HIGH_RISK_PAYLOAD, "--envelope-secret-file", str(secret_path))
    data = json.loads(proc.stdout)
    assert "report_envelope" not in data
    assert any(f["risk"] == "invalid_envelope_secret" and f["severity"] == "error" for f in data["findings"])
    assert data["ok"] is False

    strict = run_script(
        SCRIPT, HIGH_RISK_PAYLOAD, "--envelope-secret-file", str(secret_path), "--strict"
    )
    assert strict.returncode == 1


def test_envelope_rejects_unreadable_secret_with_structured_finding(tmp_path):
    missing = tmp_path / "missing.key"
    proc = run_script(SCRIPT, HIGH_RISK_PAYLOAD, "--envelope-secret-file", str(missing))
    data = json.loads(proc.stdout)
    assert "report_envelope" not in data
    assert any(f["risk"] == "invalid_envelope_secret" for f in data["findings"])


def test_envelope_flag_with_non_json_format_is_a_usage_error(tmp_path):
    secret_path = write_secret(tmp_path, SECRET)
    proc = run_script(SCRIPT, HIGH_RISK_PAYLOAD, "--format", "markdown", "--envelope-secret-file", str(secret_path))
    assert proc.returncode == 2
    assert "--format json" in proc.stderr


def test_verifier_accepts_intact_report_with_secret_file(tmp_path):
    secret_path = write_secret(tmp_path, SECRET)
    report = signed_report(tmp_path)
    proc = verify(report, "--secret-file", str(secret_path))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    verdict = json.loads(proc.stdout)
    assert verdict["ok"] is True
    assert verdict["algorithm"] == "hmac-sha256"


def test_verifier_accepts_intact_report_with_secret_env(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_SECURITY_ENVELOPE_SECRET", SECRET)
    report = signed_report(tmp_path)
    proc = verify(report, "--secret-env", "AGENT_SECURITY_ENVELOPE_SECRET")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["ok"] is True


def test_verifier_detects_tampered_findings(tmp_path):
    secret_path = write_secret(tmp_path, SECRET)
    report = signed_report(tmp_path)
    report["findings"][0]["risk"] = "tampered_low_severity"
    proc = verify(report, "--secret-file", str(secret_path))
    assert proc.returncode == 1
    verdict = json.loads(proc.stdout)
    assert verdict["ok"] is False
    assert any(err["code"] == "payload_digest_mismatch" for err in verdict["errors"])


def test_verifier_detects_forged_signature(tmp_path):
    secret_path = write_secret(tmp_path, SECRET)
    report = signed_report(tmp_path)
    report["report_envelope"]["signature"] = "0" * 64
    proc = verify(report, "--secret-file", str(secret_path))
    assert proc.returncode == 1
    verdict = json.loads(proc.stdout)
    assert any(err["code"] == "signature_mismatch" for err in verdict["errors"])


def test_verifier_rejects_missing_envelope(tmp_path):
    secret_path = write_secret(tmp_path, SECRET)
    report = signed_report(tmp_path)
    report.pop("report_envelope")
    proc = verify(report, "--secret-file", str(secret_path))
    assert proc.returncode == 1
    verdict = json.loads(proc.stdout)
    assert any(err["code"] == "missing_envelope" for err in verdict["errors"])


def test_verifier_rejects_unsupported_algorithm(tmp_path):
    secret_path = write_secret(tmp_path, SECRET)
    report = signed_report(tmp_path)
    report["report_envelope"]["algorithm"] = "md5"
    proc = verify(report, "--secret-file", str(secret_path))
    assert proc.returncode == 1
    verdict = json.loads(proc.stdout)
    assert any(err["code"] == "unsupported_algorithm" for err in verdict["errors"])


def test_verifier_rejects_wrong_secret(tmp_path):
    secret_path = write_secret(tmp_path, "a-completely-different-secret", name="wrong.key")
    report = signed_report(tmp_path)
    proc = verify(report, "--secret-file", str(secret_path))
    assert proc.returncode == 1
    verdict = json.loads(proc.stdout)
    assert any(err["code"] == "signature_mismatch" for err in verdict["errors"])


def test_verifier_rejects_empty_or_missing_secret(tmp_path, monkeypatch):
    report = signed_report(tmp_path)
    empty_secret = write_secret(tmp_path, "\n", name="empty.key")
    proc = verify(report, "--secret-file", str(empty_secret))
    assert proc.returncode == 1
    assert any(err["code"] == "invalid_secret" for err in json.loads(proc.stdout)["errors"])

    monkeypatch.delenv("AGENT_SECURITY_ENVELOPE_SECRET", raising=False)
    proc = verify(report, "--secret-env", "AGENT_SECURITY_ENVELOPE_SECRET")
    assert proc.returncode == 1
    assert any(err["code"] == "invalid_secret" for err in json.loads(proc.stdout)["errors"])


def test_verifier_requires_exactly_one_secret_source(tmp_path):
    secret_path = write_secret(tmp_path, SECRET)
    proc = verify(signed_report(tmp_path), "--secret-file", str(secret_path), "--secret-env", "ANY_VAR")
    assert proc.returncode == 2

    proc = verify(signed_report(tmp_path))
    assert proc.returncode == 2


def test_phase20_docs_readme_changelog_skill_and_roadmap_are_in_sync():
    doc = DOC.read_text(encoding="utf-8")
    assert "hmac-sha256" in doc
    assert "--envelope-secret-file" in doc
    assert "verify_report_envelope.py" in doc
    assert "not encryption" in doc
    assert "rotate" in doc

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/report-envelopes.md" in readme
    assert "--envelope-secret-file" in readme

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "report authenticity envelopes" in changelog

    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    phase20 = roadmap.split("## Phase 20:", 1)[1].split("## Implementation order", 1)[0]
    assert "**Status:** Shipped (JSON report slice)" in phase20
    assert "tests/test_phase20_report_envelopes.py" in phase20

    skill = (ROOT / "skills" / "agent-security" / "SKILL.md").read_text(encoding="utf-8")
    assert "verify_report_envelope.py" in skill

    ci_doc = (ROOT / "docs" / "ci-integration.md").read_text(encoding="utf-8")
    assert "report-envelopes.md" in ci_doc
