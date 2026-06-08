#!/usr/bin/env python3
"""Summarize the prompt-injection fixture corpus manifest."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"


def _repo_relative(path: Path) -> str:
    resolved = path.resolve()
    for parent in [resolved.parent, *resolved.parents]:
        if (parent / ".git").exists():
            return resolved.relative_to(parent).as_posix()
    return path.as_posix()


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def summarize(manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    cases = manifest.get("cases", [])
    kinds: Counter[str] = Counter()
    signals: Counter[str] = Counter()
    factors: Counter[str] = Counter()
    flagged_cases = 0
    benign_cases = 0
    config_cases = 0

    for case in cases:
        kind = str(case.get("kind", "unknown"))
        kinds[kind] += 1
        if kind == "config":
            config_cases += 1
            factors.update(str(factor) for factor in case.get("expected_factors", []))
            continue
        if case.get("flagged") is True:
            flagged_cases += 1
        elif case.get("flagged") is False:
            benign_cases += 1
        signals.update(str(signal) for signal in case.get("expected_signals", []))

    total_cases = len(cases)
    return {
        "schema_version": SCHEMA_VERSION,
        "manifest": _repo_relative(manifest_path),
        "description": manifest.get("description", ""),
        "total_cases": total_cases,
        "text_cases": total_cases - config_cases,
        "config_cases": config_cases,
        "flagged_cases": flagged_cases,
        "benign_cases": benign_cases,
        "kinds": dict(sorted(kinds.items())),
        "expected_signals": dict(sorted(signals.items())),
        "expected_factors": dict(sorted(factors.items())),
        "note": "Summary is derived from manifest expectations; run the corpus tests to verify scanner behavior.",
    }


def _table(rows: list[tuple[str, int]]) -> str:
    lines = ["| Name | Count |", "| --- | ---: |"]
    lines.extend(f"| `{name}` | {count} |" for name, count in rows)
    return "\n".join(lines)


def render_markdown(summary: dict[str, Any]) -> str:
    signal_rows = list(summary["expected_signals"].items())
    factor_rows = list(summary["expected_factors"].items())
    kind_rows = list(summary["kinds"].items())
    sections = [
        "# Prompt-injection fixture corpus summary",
        "",
        f"Manifest: `{summary['manifest']}`",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Total cases | {summary['total_cases']} |",
        f"| Text cases | {summary['text_cases']} |",
        f"| Config cases | {summary['config_cases']} |",
        f"| Flagged text cases | {summary['flagged_cases']} |",
        f"| Benign text cases | {summary['benign_cases']} |",
        "",
        "## Case kinds",
        _table(kind_rows),
        "",
        "## Expected text signals",
        _table(signal_rows) if signal_rows else "No expected text signals listed.",
        "",
        "## Expected config factors",
        _table(factor_rows) if factor_rows else "No expected config factors listed.",
        "",
        summary["note"],
    ]
    return "\n".join(sections) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="path to tests/fixtures/prompt-injection/manifest.json")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON when --format json is used")
    args = parser.parse_args()

    try:
        summary = summarize(args.manifest)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: unable to summarize manifest: {exc}", file=sys.stderr)
        return 2

    if args.format == "markdown":
        print(render_markdown(summary), end="")
    else:
        print(json.dumps(summary, indent=None if args.compact else 2, separators=(",", ":") if args.compact else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
