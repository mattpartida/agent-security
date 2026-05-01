#!/usr/bin/env python3
import json
import re
import sys

text = sys.stdin.read()
summary = {
    "critical": 0,
    "warn": 0,
    "info": 0,
    "items": []
}

m = re.search(r"Summary:\s+(\d+) critical\s+·\s+(\d+) warn\s+·\s+(\d+) info", text)
if m:
    summary["critical"] = int(m.group(1))
    summary["warn"] = int(m.group(2))
    summary["info"] = int(m.group(3))

for line in text.splitlines():
    m = re.match(r"\s*(CRITICAL|WARN|INFO)\s+(.*)", line)
    if m:
        summary["items"].append({
            "severity": m.group(1).lower(),
            "title": m.group(2).strip()
        })

print(json.dumps(summary, indent=2, sort_keys=True))
