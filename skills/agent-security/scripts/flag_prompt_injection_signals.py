#!/usr/bin/env python3
import json
import re
import sys

text = sys.stdin.read()
patterns = [
    ("override_instructions", r"ignore (all|any|previous|prior) instructions|new system prompt|override (the )?rules"),
    ("role_redefinition", r"you are now|act as (the )?(admin|administrator|system|developer)"),
    ("prompt_exfiltration", r"reveal (your|the) (system|hidden|developer) prompt|print your instructions"),
    ("tool_coercion", r"run this command|open this url|send this message|execute this"),
    ("secrecy_or_urgency", r"do not tell the user|secretly|urgent|immediately|act now"),
    ("approval_bypass", r"this is authorized|approved by admin|bypass safety|ignore policy")
]

hits = []
for name, pattern in patterns:
    if re.search(pattern, text, flags=re.IGNORECASE):
        hits.append(name)

print(json.dumps({
    "flagged": bool(hits),
    "signals": hits,
    "note": "Heuristic only. Absence of hits does not mean content is safe."
}, indent=2))
