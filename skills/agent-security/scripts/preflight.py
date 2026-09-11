#!/usr/bin/env python3
"""Combined local preflight wrapping the three existing scanner CLIs."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parent
CONFIG_RISK = SCRIPTS / "config_risk_summary.py"
EXPOSURE = SCRIPTS / "score_prompt_injection_exposure.py"
SIGNALS = SCRIPTS / "flag_prompt_injection_signals.py"


def run_scanner(script: Path, data: bytes, extra_args: list[str] | None = None) -> subprocess.CompletedProcess[bytes]:
    cmd = [sys.executable, str(script), *(extra_args or [])]
    return subprocess.run(cmd, input=data, capture_output=True)


def parse_json_output(proc: subprocess.CompletedProcess[bytes]) -> dict[str, Any] | None:
    try:
        parsed = json.loads(proc.stdout.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def overall_ok(config_risk: dict[str, Any], exposure: dict[str, Any], signals: dict[str, Any]) -> bool:
    severity = str(exposure.get("severity", "")).lower()
    if config_risk.get("ok") is False:
        return False
    if signals.get("flagged"):
        return False
    if severity in {"high", "critical", "error"}:
        return False
    return True


def build_report(config_risk: dict[str, Any], exposure: dict[str, Any], signals: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": overall_ok(config_risk, exposure, signals),
        "scanner_results": {
            "config_risk": config_risk,
            "prompt_injection_exposure": exposure,
            "prompt_injection_signals": signals,
        },
        "schema_version": 1,
        "summary": {
            "config_risk": {"ok": config_risk.get("ok")},
            "prompt_injection_exposure": {"severity": exposure.get("severity")},
            "prompt_injection_signals": {"flagged": signals.get("flagged")},
        },
    }


def markdown_summary(report: dict[str, Any]) -> str:
    summary = report["summary"]
    return "\n".join(
        [
            "## Combined Preflight",
            "",
            "### Config Risk",
            f"- ok: {summary['config_risk'].get('ok')}",
            "",
            "### Prompt-Injection Exposure",
            f"- severity: {summary['prompt_injection_exposure'].get('severity', 'unknown')}",
            "",
            "### Prompt-Injection Signals",
            f"- flagged: {summary['prompt_injection_signals'].get('flagged')}",
            "",
        ]
    )


def combine_sarif(docs: list[dict[str, Any]]) -> dict[str, Any]:
    runs: list[Any] = []
    for doc in docs:
        runs.extend(doc.get("runs") or [])
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--text", type=Path)
    parser.add_argument("--format", choices=("json", "markdown", "sarif"), default="json")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    if args.config is None or args.text is None or not args.config.is_file() or not args.text.is_file():
        return 1

    config_bytes = args.config.read_bytes()
    text_bytes = args.text.read_bytes()
    extra = ["--format", "sarif"] if args.format == "sarif" else []

    config_proc = run_scanner(CONFIG_RISK, config_bytes, extra)
    exposure_proc = run_scanner(EXPOSURE, config_bytes, extra)
    signals_proc = run_scanner(SIGNALS, text_bytes, extra)

    config_doc = parse_json_output(config_proc)
    exposure_doc = parse_json_output(exposure_proc)
    signals_doc = parse_json_output(signals_proc)
    if config_doc is None or exposure_doc is None or signals_doc is None:
        return 1

    if args.format == "sarif":
        print(json.dumps(combine_sarif([config_doc, exposure_doc, signals_doc]), indent=2, sort_keys=True))
        return 0

    report = build_report(config_doc, exposure_doc, signals_doc)

    if args.format == "markdown":
        sys.stdout.write(markdown_summary(report))
    else:
        print(json.dumps(report, indent=2, sort_keys=True))

    if args.strict and not report["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
