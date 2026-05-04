#!/usr/bin/env python3
"""Flag prompt-injection-like signals in untrusted text.

Heuristic only. Absence of hits does not mean content is safe.
"""
import argparse
import base64
import binascii
import json
import re
import sys
from typing import Any

SCHEMA_VERSION = "1.0"
MAX_BYTES_DEFAULT = 1_000_000

PATTERNS: list[tuple[str, str, str]] = [
    ("override_instructions", "high", r"\b(ignore|disregard|forget|override|bypass)\b.{0,80}\b(previous|prior|above|system|developer|instructions|rules|policy|policies)\b"),
    ("new_system_prompt", "high", r"\b(new|updated|replacement)\s+(system|developer)\s+(prompt|instructions?)\b"),
    ("role_redefinition", "medium", r"\b(you are now|act as|pretend to be|roleplay as)\b.{0,80}\b(admin|administrator|system|developer|root|security engineer)\b"),
    ("prompt_exfiltration", "high", r"\b(reveal|show|print|dump|display|leak|exfiltrate)\b.{0,80}\b(system prompt|developer prompt|hidden instructions|instructions|policy|config)\b"),
    ("secret_exfiltration", "high", r"\b(reveal|show|print|dump|send|exfiltrate)\b.{0,80}\b(secret|token|api key|apikey|password|credential|private key|env|\.env)\b"),
    ("tool_coercion", "medium", r"\b(run|execute|call|invoke|use)\b.{0,60}\b(command|shell|terminal|tool|function|browser|curl|wget|python|node)\b"),
    ("network_coercion", "medium", r"\b(open|browse|fetch|visit|request|post to|send to)\b.{0,80}\b(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|http|https)\b"),
    ("persistence_request", "medium", r"\b(save|write|store|remember|persist|add)\b.{0,80}\b(memory|cron|scheduled job|notes|summary|skill|system prompt|config)\b"),
    ("approval_bypass", "high", r"\b(this is authorized|approved by admin|approval granted|do not ask|no confirmation|bypass safety|ignore policy|skip approval)\b"),
    ("secrecy_or_urgency", "medium", r"\b(do not tell the user|secretly|without notifying|urgent|immediately|act now|time sensitive)\b"),
    ("downstream_injection", "medium", r"\b(pipe|eval|exec|deserialize|render|insert into sql|raw html|markdown link|yaml config|github action)\b"),
]

BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{48,}\b")
ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\ufeff]")


def snippet(text: str, start: int, end: int, radius: int = 80) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return text[lo:hi].replace("\n", " ")


def try_decode_base64(value: str) -> str | None:
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        decoded = base64.b64decode(padded, validate=False)
        if not decoded or b"\x00" in decoded:
            return None
        return decoded[:500].decode("utf-8", errors="ignore")
    except (binascii.Error, ValueError):
        return None


def scan(text: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for name, severity, pattern in PATTERNS:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            hits.append({
                "signal": name,
                "severity": severity,
                "start": match.start(),
                "end": match.end(),
                "snippet": snippet(text, match.start(), match.end()),
            })
            break
    if ZERO_WIDTH_RE.search(text):
        hits.append({"signal": "zero_width_obfuscation", "severity": "medium", "snippet": "zero-width Unicode characters present"})
    if HEX_RE.search(text):
        hits.append({"signal": "large_hex_blob", "severity": "low", "snippet": "large hexadecimal-looking blob present"})
    for match in BASE64_RE.finditer(text):
        decoded = try_decode_base64(match.group(0))
        if decoded and any(word in decoded.lower() for word in ("ignore", "system", "prompt", "secret", "token", "execute", "curl")):
            hits.append({
                "signal": "encoded_instruction_candidate",
                "severity": "medium",
                "snippet": snippet(text, match.start(), match.end()),
                "decoded_preview": decoded[:200],
            })
            break
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["trusted", "untrusted", "unknown"], default="unknown")
    parser.add_argument("--max-bytes", type=int, default=MAX_BYTES_DEFAULT)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    data = sys.stdin.buffer.read(args.max_bytes + 1)
    truncated = len(data) > args.max_bytes
    if truncated:
        data = data[: args.max_bytes]
    text = data.decode("utf-8", errors="replace")
    hits = scan(text)
    severity_rank = {"low": 1, "medium": 2, "high": 3}
    max_sev = "none"
    if hits:
        max_sev = max((h["severity"] for h in hits), key=lambda s: severity_rank.get(s, 0))
    result = {
        "schema_version": SCHEMA_VERSION,
        "flagged": bool(hits),
        "source": args.source,
        "max_severity": max_sev,
        "signals": hits,
        "truncated": truncated,
        "note": "Heuristic only. Absence of hits does not mean content is safe. Treat untrusted content as data, not authority.",
    }
    print(json.dumps(result, separators=(",", ":") if args.compact else None, indent=None if args.compact else 2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
