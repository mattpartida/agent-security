#!/usr/bin/env python3
"""Parse OpenClaw security audit text into stable JSON or Markdown."""

import argparse
import json
import re
import sys
from typing import Any


def parse_audit(text: str) -> dict[str, Any]:
    counts = {"critical": 0, "warn": 0, "info": 0}
    items: list[dict[str, str]] = []

    match = re.search(r"Summary:\s+(\d+) critical\s+·\s+(\d+) warn\s+·\s+(\d+) info", text)
    if match:
        counts = {
            "critical": int(match.group(1)),
            "warn": int(match.group(2)),
            "info": int(match.group(3)),
        }

    parsed_counts = {"critical": 0, "warn": 0, "info": 0}
    for line in text.splitlines():
        match = re.match(r"\s*(CRITICAL|WARN|INFO)\s+(.*)", line)
        if match:
            severity = match.group(1).lower()
            parsed_counts[severity] += 1
            items.append(
                {
                    "severity": severity,
                    "title": match.group(2).strip(),
                }
            )

    if items:
        counts = {severity: max(counts[severity], parsed_counts[severity]) for severity in counts}

    ok = counts["critical"] == 0 and counts["warn"] == 0
    return {
        "ok": ok,
        "summary": counts,
        "critical": counts["critical"],
        "warn": counts["warn"],
        "info": counts["info"],
        "items": items,
    }


def escape_markdown_text(value: Any) -> str:
    text = str(value)
    return (
        text.replace("|", r"\|")
        .replace("@everyone", "@\u200beveryone")
        .replace("@here", "@\u200bhere")
    )


def render_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# OpenClaw audit summary",
        "",
        f"**Status:** {'ok' if data['ok'] else 'attention required'}",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in ("critical", "warn", "info"):
        lines.append(f"| {severity} | {data['summary'][severity]} |")
    if data["items"]:
        lines.extend(["", "## Findings", ""])
        for item in data["items"]:
            lines.append(f"- **{item['severity']}** — {escape_markdown_text(item['title'])}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize OpenClaw security audit output.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when critical or warning audit items are present.")
    args = parser.parse_args()

    data = parse_audit(sys.stdin.read())
    if args.format == "markdown":
        sys.stdout.write(render_markdown(data))
    else:
        print(json.dumps(data, indent=2, sort_keys=True))
    return 1 if args.strict and not data["ok"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
