#!/usr/bin/env python3
"""Verify the HMAC-SHA256 authenticity envelope on an agent-security JSON report.

Reads a JSON report on stdin and checks its ``report_envelope`` signature
against a secret supplied via ``--secret-file <path>`` or
``--secret-env <VAR>`` (exactly one source). Exits 0 when the report is
intact, 1 on any verification failure, and 2 on usage errors.

This is an integrity check, not encryption: envelopes detect mutation, they
hide nothing. Dependency-light by design (standard library only).
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
from typing import Any

SUPPORTED_ALGORITHMS = {"hmac-sha256"}


def error(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def read_secret_from_file(path: str) -> tuple[bytes | None, dict[str, str] | None]:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        return None, error("invalid_secret", f"could not read secret file: {exc}")
    except UnicodeDecodeError as exc:
        return None, error("invalid_secret", f"secret file is not valid UTF-8 text: {exc}")
    secret = raw[:-1] if raw.endswith("\n") else raw
    if not secret.strip():
        return None, error("invalid_secret", "secret file is empty or blank")
    return secret.encode("utf-8"), None


def read_secret_from_env(var: str) -> tuple[bytes | None, dict[str, str] | None]:
    raw = os.environ.get(var)
    if raw is None:
        return None, error("invalid_secret", f"environment variable {var} is not set")
    secret = raw[:-1] if raw.endswith("\n") else raw
    if not secret.strip():
        return None, error("invalid_secret", f"environment variable {var} is empty or blank")
    return secret.encode("utf-8"), None


def canonical_payload_bytes(payload: Any) -> bytes:
    """Serialize the signed payload deterministically (sorted keys, tight separators)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_report(report: Any, secret: bytes) -> dict[str, Any]:
    """Verify one report object; returns a verdict dict with ``ok`` and ``errors``."""
    errors: list[dict[str, str]] = []
    if not isinstance(report, dict):
        return {"ok": False, "errors": [error("invalid_report", "report top-level value must be a JSON object")]}

    envelope = report.get("report_envelope")
    if not isinstance(envelope, dict):
        return {"ok": False, "errors": [error("missing_envelope", "report has no report_envelope object")]}

    algorithm = envelope.get("algorithm")
    if algorithm not in SUPPORTED_ALGORITHMS:
        errors.append(error("unsupported_algorithm", f"envelope algorithm must be one of {sorted(SUPPORTED_ALGORITHMS)}"))

    expected_digest = envelope.get("payload_sha256")
    expected_signature = envelope.get("signature")
    if not isinstance(expected_digest, str) or len(expected_digest) != 64:
        errors.append(error("malformed_envelope", "payload_sha256 must be a 64-character hex string"))
        expected_digest = ""
    if not isinstance(expected_signature, str) or len(expected_signature) != 64:
        errors.append(error("malformed_envelope", "signature must be a 64-character hex string"))
        expected_signature = ""
    if errors:
        return {"ok": False, "errors": errors}

    payload = {key: value for key, value in report.items() if key != "report_envelope"}
    digest = hashlib.sha256(canonical_payload_bytes(payload)).hexdigest()
    if digest != expected_digest:
        errors.append(error("payload_digest_mismatch", f"payload digest is {digest}, envelope claims {expected_digest}"))
        return {"ok": False, "errors": errors}

    signature = hmac.new(secret, digest.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        errors.append(error("signature_mismatch", "HMAC signature does not match the supplied secret"))
    return {"ok": not errors, "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument("--secret-file", help="path to a UTF-8 text file containing the signing secret")
    sources.add_argument("--secret-env", help="name of an environment variable containing the signing secret")
    args = parser.parse_args()

    if args.secret_file:
        secret, secret_error = read_secret_from_file(args.secret_file)
    else:
        secret, secret_error = read_secret_from_env(args.secret_env)
    if secret is None:
        verdict = {"ok": False, "errors": [secret_error]}
        print(json.dumps(verdict, sort_keys=True))
        return 1

    raw = sys.stdin.read()
    try:
        report = json.loads(raw)
    except json.JSONDecodeError as exc:
        verdict = {"ok": False, "errors": [error("invalid_report", f"stdin is not valid JSON: {exc}")]}
        print(json.dumps(verdict, sort_keys=True))
        return 1

    verdict = verify_report(report, secret)
    verdict.setdefault("algorithm", "hmac-sha256")
    print(json.dumps(verdict, sort_keys=True))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
