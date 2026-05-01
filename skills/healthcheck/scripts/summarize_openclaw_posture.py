#!/usr/bin/env python3
import json
import re
import sys

text = sys.stdin.read()
summary = {
    "critical": 0,
    "warn": 0,
    "info": 0,
    "update_available": False,
    "channel": None,
}

m = re.search(r"Summary:\s+(\d+) critical\s+·\s+(\d+) warn\s+·\s+(\d+) info", text)
if m:
    summary["critical"] = int(m.group(1))
    summary["warn"] = int(m.group(2))
    summary["info"] = int(m.group(3))

m = re.search(r"Channel\s+│\s+([^\n]+)", text)
if m:
    summary["channel"] = m.group(1).strip()

if "Update               │ available" in text or "Update available" in text:
    summary["update_available"] = True

print(json.dumps(summary, indent=2, sort_keys=True))
