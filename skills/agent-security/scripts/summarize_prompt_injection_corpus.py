#!/usr/bin/env python3
"""Summarize the prompt-injection fixture corpus manifest."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"

INFO_ISSUE = {
    "level": "info",
    "code": "corpus_summary_generated",
    "message": "Summary is derived from manifest expectations; run the corpus tests to verify scanner behavior.",
}


def _repo_relative(path: Path) -> str:
    resolved = path.resolve()
    for parent in [resolved.parent, *resolved.parents]:
        if (parent / ".git").exists():
            return resolved.relative_to(parent).as_posix()
    return path.as_posix()


def load_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _issue(level: str, code: str, message: str, *, case_file: str | None = None) -> dict[str, Any]:
    issue: dict[str, Any] = {"level": level, "code": code, "message": message}
    if case_file is not None:
        issue["case_file"] = case_file
    return issue


def validate_cases(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    seen_files: set[str] = set()
    has_benign = False
    has_flagged = False
    has_config = False

    for case in cases:
        case_file = str(case.get("file", "<missing>"))
        kind = str(case.get("kind", "unknown"))
        if case_file in seen_files:
            issues.append(_issue("critical", "duplicate_case_file", "Manifest case files must be unique.", case_file=case_file))
        seen_files.add(case_file)

        if kind == "config":
            has_config = True
            if not case.get("expected_factors"):
                issues.append(
                    _issue(
                        "critical",
                        "config_case_missing_expected_factors",
                        "Config corpus cases must list at least one expected exposure factor.",
                        case_file=case_file,
                    )
                )
            if not case.get("expected_severities"):
                issues.append(
                    _issue(
                        "critical",
                        "config_case_missing_expected_severities",
                        "Config corpus cases must list at least one expected exposure severity.",
                        case_file=case_file,
                    )
                )
            continue

        if case.get("flagged") is True:
            has_flagged = True
            if not case.get("expected_signals"):
                issues.append(
                    _issue(
                        "critical",
                        "malicious_case_missing_expected_signals",
                        "Flagged malicious text cases must list at least one expected signal.",
                        case_file=case_file,
                    )
                )
        elif case.get("flagged") is False:
            has_benign = True
            if case.get("expected_signals"):
                issues.append(
                    _issue(
                        "critical",
                        "benign_case_has_expected_signals",
                        "Benign text cases must keep expected_signals empty.",
                        case_file=case_file,
                    )
                )
        else:
            issues.append(
                _issue(
                    "critical",
                    "text_case_missing_flagged_boolean",
                    "Text corpus cases must set flagged to true or false.",
                    case_file=case_file,
                )
            )

    if not cases:
        issues.append(_issue("critical", "empty_corpus", "Manifest must contain at least one corpus case."))
    if cases and not has_flagged:
        issues.append(_issue("warn", "no_flagged_text_cases", "Corpus has no flagged malicious text cases."))
    if cases and not has_benign:
        issues.append(_issue("warn", "no_benign_text_cases", "Corpus has no benign negative text cases."))
    if cases and not has_config:
        issues.append(_issue("warn", "no_config_cases", "Corpus has no config exposure cases."))
    return issues


def _issue_summary(issues: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "critical": sum(1 for issue in issues if issue["level"] == "critical"),
        "warn": sum(1 for issue in issues if issue["level"] == "warn"),
        "info": sum(1 for issue in issues if issue["level"] == "info"),
    }


def _case_inventory(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for case in cases:
        kind = str(case.get("kind", "unknown"))
        if kind == "config":
            classification = "config"
            expected = [str(item) for item in case.get("expected_factors", [])]
        elif case.get("flagged") is True:
            classification = "flagged"
            expected = [str(item) for item in case.get("expected_signals", [])]
        elif case.get("flagged") is False:
            classification = "benign"
            expected = [str(item) for item in case.get("expected_signals", [])]
        else:
            classification = "unknown"
            expected = [str(item) for item in case.get("expected_signals", [])]
        inventory.append(
            {
                "file": str(case.get("file", "<missing>")),
                "kind": kind,
                "classification": classification,
                "expected": sorted(expected),
            }
        )
    return sorted(inventory, key=lambda item: item["file"])


def summarize(manifest_path: Path, *, include_cases: bool = False) -> dict[str, Any]:
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
    issues = validate_cases(cases) + [INFO_ISSUE]
    summary = _issue_summary(issues)
    result = {
        "schema_version": SCHEMA_VERSION,
        "manifest": _repo_relative(manifest_path),
        "description": manifest.get("description", ""),
        "ok": summary["critical"] == 0,
        "summary": summary,
        "issues": issues,
        "total_cases": total_cases,
        "text_cases": total_cases - config_cases,
        "config_cases": config_cases,
        "flagged_cases": flagged_cases,
        "benign_cases": benign_cases,
        "kinds": dict(sorted(kinds.items())),
        "expected_signals": dict(sorted(signals.items())),
        "expected_factors": dict(sorted(factors.items())),
        "note": INFO_ISSUE["message"],
    }
    if include_cases:
        result["cases"] = _case_inventory(cases)
    return result


def _table(rows: list[tuple[str, int]]) -> str:
    lines = ["| Name | Count |", "| --- | ---: |"]
    lines.extend(f"| `{name}` | {count} |" for name, count in rows)
    return "\n".join(lines)


def _escape_table_cell(value: str) -> str:
    return value.replace("|", "\\|")


def _case_inventory_table(cases: list[dict[str, Any]]) -> str:
    lines = ["| File | Kind | Classification | Expected |", "| --- | --- | --- | --- |"]
    for case in cases:
        expected = ", ".join(f"`{_escape_table_cell(item)}`" for item in case["expected"])
        lines.append(
            "| "
            f"`{_escape_table_cell(case['file'])}` | "
            f"`{_escape_table_cell(case['kind'])}` | "
            f"{_escape_table_cell(case['classification'])} | "
            f"{expected} |"
        )
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
        f"| Critical issues | {summary['summary']['critical']} |",
        f"| Warning issues | {summary['summary']['warn']} |",
        "",
        "## Case kinds",
        _table(kind_rows),
        "",
        "## Expected text signals",
        _table(signal_rows) if signal_rows else "No expected text signals listed.",
        "",
        "## Expected config factors",
        _table(factor_rows) if factor_rows else "No expected config factors listed.",
    ]
    if "cases" in summary:
        sections.extend(["", "## Case inventory", _case_inventory_table(summary["cases"])])
    sections.extend([
        "",
        summary["note"],
    ])
    return "\n".join(sections) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="path to tests/fixtures/prompt-injection/manifest.json")
    parser.add_argument("--format", choices=["json", "markdown"], default="json")
    parser.add_argument("--compact", action="store_true", help="emit compact JSON when --format json is used")
    parser.add_argument("--strict", action="store_true", help="exit non-zero when manifest contract issues are critical")
    parser.add_argument("--include-cases", action="store_true", help="include stable per-case inventory rows in JSON or Markdown output")
    args = parser.parse_args()

    try:
        summary = summarize(args.manifest, include_cases=args.include_cases)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: unable to summarize manifest: {exc}", file=sys.stderr)
        return 2

    if args.format == "markdown":
        print(render_markdown(summary), end="")
    else:
        print(json.dumps(summary, indent=None if args.compact else 2, separators=(",", ":") if args.compact else None, sort_keys=True))
    if args.strict and not summary["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
