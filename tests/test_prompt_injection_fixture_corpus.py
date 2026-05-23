import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "prompt-injection"
MANIFEST = FIXTURE_DIR / "manifest.json"
SIGNAL_SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "flag_prompt_injection_signals.py"
SCORE_SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "score_prompt_injection_exposure.py"


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


def test_detector_quality_docs_and_roadmap_phase3_status_are_shipped():
    docs_path = ROOT / "docs" / "prompt-injection-detector-quality.md"
    docs = docs_path.read_text(encoding="utf-8")
    required_phrases = [
        "false positives",
        "false negatives",
        "when to add a fixture",
        "tool-output exfiltration",
        "tests/fixtures/prompt-injection/manifest.json",
    ]
    for phrase in required_phrases:
        assert phrase in docs.lower()

    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    phase3 = roadmap.split("## Phase 3:", 1)[1].split("## Phase 4:", 1)[0]
    assert "**Status:** Shipped" in phase3
    assert "prompt-injection-detector-quality.md" in phase3
