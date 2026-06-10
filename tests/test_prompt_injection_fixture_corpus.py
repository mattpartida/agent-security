import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "prompt-injection"
MANIFEST = FIXTURE_DIR / "manifest.json"
SIGNAL_SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "flag_prompt_injection_signals.py"
SCORE_SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "score_prompt_injection_exposure.py"
SUMMARY_SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "summarize_prompt_injection_corpus.py"


def run_signal_fixture(name: str):
    text = (FIXTURE_DIR / name).read_text(encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SIGNAL_SCRIPT), "--source", "untrusted"],
        input=text,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_prompt_injection_fixture_manifest_is_complete():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    fixture_names = {
        path.name
        for pattern in ("*.txt", "*.json")
        for path in FIXTURE_DIR.glob(pattern)
        if path.name != "manifest.json"
    }
    cases = manifest["cases"]
    manifest_names = {case["file"] for case in cases}
    assert len(manifest_names) == len(cases), "manifest case files must be unique"
    assert manifest_names == fixture_names
    assert {case["kind"] for case in cases} >= {
        "direct",
        "indirect",
        "encoded",
        "obfuscated",
        "persistence",
        "tool_output",
        "benign",
    }
    for case in cases:
        path = FIXTURE_DIR / case["file"]
        assert path.parent == FIXTURE_DIR, f"fixture paths must stay in corpus dir: {case['file']}"
        if case["kind"] == "config":
            assert case["expected_severities"]
            assert case["expected_factors"]
        else:
            assert "flagged" in case
            assert "expected_signals" in case


def test_signal_scanner_detects_fixture_corpus_expected_signals():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for case in manifest["cases"]:
        if case["kind"] == "config":
            continue
        data = run_signal_fixture(case["file"])
        signals = {hit["signal"] for hit in data["signals"]}
        assert data["flagged"] is case["flagged"], case["file"]
        assert set(case["expected_signals"]).issubset(signals), case["file"]


def test_exposure_fixture_scores_high_risk_agent_config():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    config_cases = [case for case in manifest["cases"] if case["kind"] == "config"]
    assert config_cases
    for case in config_cases:
        payload = (FIXTURE_DIR / case["file"]).read_text(encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(SCORE_SCRIPT)],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        data = json.loads(proc.stdout)
        assert data["severity"] in set(case["expected_severities"]), case["file"]
        factors = {factor["factor"] for factor in data["factors"]}
        assert set(case["expected_factors"]).issubset(factors), case["file"]


def test_prompt_injection_corpus_summary_script_reports_manifest_counts():
    proc = subprocess.run(
        [sys.executable, str(SUMMARY_SCRIPT), str(MANIFEST)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data["schema_version"] == "1.0"
    assert data["manifest"] == "tests/fixtures/prompt-injection/manifest.json"
    assert data["ok"] is True
    assert data["summary"] == {"critical": 0, "warn": 0, "info": 1}
    assert data["issues"] == [
        {
            "level": "info",
            "code": "corpus_summary_generated",
            "message": "Summary is derived from manifest expectations; run the corpus tests to verify scanner behavior.",
        }
    ]
    assert data["total_cases"] == 8
    assert data["text_cases"] == 7
    assert data["config_cases"] == 1
    assert data["flagged_cases"] == 6
    assert data["benign_cases"] == 1
    assert data["kinds"]["direct"] == 1
    assert data["expected_signals"]["secret_exfiltration"] == 2
    assert data["expected_factors"]["browser_private_network_allowed"] == 1


def test_prompt_injection_corpus_summary_strict_fails_closed_on_invalid_manifest(tmp_path):
    invalid_manifest = tmp_path / "manifest.json"
    invalid_manifest.write_text(
        json.dumps(
            {
                "description": "Invalid corpus used by strict-mode regression tests.",
                "cases": [
                    {"file": "malicious.txt", "kind": "direct", "flagged": True, "expected_signals": []},
                    {"file": "negative.txt", "kind": "benign", "flagged": False, "expected_signals": ["secret_exfiltration"]},
                    {"file": "config.json", "kind": "config", "expected_severities": [], "expected_factors": []},
                ],
            }
        ),
        encoding="utf-8",
    )
    proc = subprocess.run(
        [sys.executable, str(SUMMARY_SCRIPT), "--strict", str(invalid_manifest)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["ok"] is False
    assert data["summary"]["critical"] >= 3
    assert {issue["code"] for issue in data["issues"]} >= {
        "malicious_case_missing_expected_signals",
        "benign_case_has_expected_signals",
        "config_case_missing_expected_factors",
    }


def test_prompt_injection_corpus_summary_script_emits_markdown_for_docs():
    proc = subprocess.run(
        [sys.executable, str(SUMMARY_SCRIPT), "--format", "markdown", str(MANIFEST)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    markdown = proc.stdout
    assert "# Prompt-injection fixture corpus summary" in markdown
    assert "| Total cases | 8 |" in markdown
    assert "| Flagged text cases | 6 |" in markdown
    assert "| `secret_exfiltration` | 2 |" in markdown
    assert "| `browser_private_network_allowed` | 1 |" in markdown


def test_prompt_injection_corpus_summary_include_cases_exports_stable_case_inventory():
    proc = subprocess.run(
        [sys.executable, str(SUMMARY_SCRIPT), "--include-cases", str(MANIFEST)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    cases = data["cases"]
    assert len(cases) == data["total_cases"] == 8
    first = cases[0]
    assert first == {
        "file": "benign-status-update.txt",
        "kind": "benign",
        "classification": "benign",
        "expected": [],
    }
    config_case = next(case for case in cases if case["kind"] == "config")
    assert config_case["classification"] == "config"
    assert "browser_private_network_allowed" in config_case["expected"]
    assert cases == sorted(cases, key=lambda case: case["file"])


def test_prompt_injection_corpus_summary_markdown_include_cases_renders_case_inventory():
    proc = subprocess.run(
        [sys.executable, str(SUMMARY_SCRIPT), "--format", "markdown", "--include-cases", str(MANIFEST)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    markdown = proc.stdout
    assert "## Case inventory" in markdown
    assert "| File | Kind | Classification | Expected |" in markdown
    assert "| `benign-status-update.txt` | `benign` | benign |  |" in markdown
    assert "| `high-risk-agent-config.json` | `config` | config |" in markdown


def test_detector_quality_docs_and_roadmap_phase3_status_are_shipped():
    docs_path = ROOT / "docs" / "prompt-injection-detector-quality.md"
    docs = docs_path.read_text(encoding="utf-8")
    required_phrases = [
        "false positives",
        "false negatives",
        "when to add a fixture",
        "tool-output exfiltration",
        "tests/fixtures/prompt-injection/manifest.json",
        "--strict",
        "--include-cases",
        "case inventory",
        "corpus summary",
    ]
    for phrase in required_phrases:
        assert phrase in docs.lower()

    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    phase3 = roadmap.split("## Phase 3:", 1)[1].split("## Phase 4:", 1)[0]
    assert "**Status:** Shipped" in phase3
    assert "prompt-injection-detector-quality.md" in phase3
