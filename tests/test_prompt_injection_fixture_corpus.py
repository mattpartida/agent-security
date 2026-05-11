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
    manifest_names = {case["file"] for case in manifest["cases"]}
    assert manifest_names == fixture_names
    assert {case["kind"] for case in manifest["cases"]} >= {"direct", "indirect", "encoded", "benign"}


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
