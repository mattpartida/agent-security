#!/usr/bin/env python3
"""Parse OpenClaw posture/status text into stable JSON or Markdown."""

import argparse
import json
import re
import sys
from typing import Any


def parse_posture(text: str) -> dict[str, Any]:
    counts = {"critical": 0, "warn": 0, "info": 0}
    match = re.search(r"Summary:\s+(\d+) critical\s+·\s+(\d+) warn\s+·\s+(\d+) info", text)
    if match:
        counts = {
            "critical": int(match.group(1)),
            "warn": int(match.group(2)),
            "info": int(match.group(3)),
        }

    channel = None
    match = re.search(r"Channel\s+│\s+([^\n]+)", text)
    if match:
        channel = match.group(1).strip()

    parsed_counts = {"critical": 0, "warn": 0, "info": 0}
    for line in text.splitlines():
        item_match = re.match(r"\s*(CRITICAL|WARN|INFO)\s+", line)
        if item_match:
            parsed_counts[item_match.group(1).lower()] += 1
    if any(parsed_counts.values()):
        counts = {severity: max(counts[severity], parsed_counts[severity]) for severity in counts}

    update_available = "Update               │ available" in text or "Update available" in text
    ok = counts["critical"] == 0 and counts["warn"] == 0 and not update_available
    return {
        "ok": ok,
        "summary": counts,
        "critical": counts["critical"],
        "warn": counts["warn"],
        "info": counts["info"],
        "update_available": update_available,
        "channel": channel,
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
        "# OpenClaw posture summary",
        "",
        f"**Status:** {'ok' if data['ok'] else 'attention required'}",
        f"**Channel:** {escape_markdown_text(data['channel'] or 'unknown')}",
        f"**Update available:** {'yes' if data['update_available'] else 'no'}",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in ("critical", "warn", "info"):
        lines.append(f"| {severity} | {data['summary'][severity]} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize OpenClaw status/deep posture output.")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when warnings, critical items, or updates are present.")
    args = parser.parse_args()

    data = parse_posture(sys.stdin.read())
    if args.format == "markdown":
        sys.stdout.write(render_markdown(data))
    else:
        print(json.dumps(data, indent=2, sort_keys=True))
    return 1 if args.strict and not data["ok"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
