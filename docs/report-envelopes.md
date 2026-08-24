# Report Authenticity Envelopes

Phase 20 adds an optional, non-executable integrity envelope for exported JSON
reports so downstream consumers can detect accidental or malicious report
mutation between scan time and review time.

The envelope is **an integrity control, not encryption**. It hides nothing about
the report; it only lets a reviewer with the same secret confirm the report bytes
were produced by someone holding that secret and were not modified afterwards.

## Sign a JSON report

Pass `--envelope-secret-file` pointing at a UTF-8 text file containing the
signing secret. At most one trailing newline is stripped, so secrets written by
common CI secret-file tooling verify correctly.

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --envelope-secret-file /path/to/agent-security-report.key \
  < examples/high-risk-agent-config.json \
  > report.json
```

The JSON report gains an additive `report_envelope` object:

```json
{
  "algorithm": "hmac-sha256",
  "payload_sha256": "<64-char SHA-256 of the canonical report payload>",
  "signature": "<64-char HMAC-SHA256 of the payload digest>",
  "covered_fields": ["baseline_lifecycle", "counts", "findings", "..."]
}
```

`covered_fields` lists every top-level report field covered by the signature.
The envelope itself is never self-signed. Without the flag, output is unchanged
and fully backwards compatible.

Envelope signing requires `--format json` (the default). Passing it with
`--format markdown` or `--format sarif` is a usage error (exit code 2) instead
of silently emitting unsigned output.

## Verify a signed report

Use the dependency-light verifier with exactly one secret source — a file or an
environment variable:

```bash
python3 skills/agent-security/scripts/verify_report_envelope.py \
  --secret-file /path/to/agent-security-report.key \
  < report.json
```

```bash
python3 skills/agent-security/scripts/verify_report_envelope.py \
  --secret-env AGENT_SECURITY_ENVELOPE_SECRET \
  < report.json
```

Exit codes:

| Exit | Meaning |
| --- | --- |
| `0` | Report envelope verified; payload and signature are intact. |
| `1` | Verification failed (tampering, wrong secret, missing/malformed envelope) or the secret source was invalid. |
| `2` | Usage error: zero or multiple secret sources supplied. |

On failure the verifier prints a JSON verdict with machine-readable error codes:
`missing_envelope`, `unsupported_algorithm`, `malformed_envelope`,
`payload_digest_mismatch`, `signature_mismatch`, `invalid_secret`, or
`invalid_report`.

- `payload_digest_mismatch` means the report content changed after signing.
- `signature_mismatch` with an intact digest means the secret does not match.

## Secret handling

- Generate secrets with a CSPRNG, e.g. `openssl rand -hex 32`.
- Never commit secrets to the repo; store them in your CI secret store and
  inject them as files or environment variables at scan time.
- Treat the secret as a shared capability: anyone holding it can produce valid
  reports. Scope CI permissions so untrusted PRs cannot both read the secret and
  publish artifacts verified with it.
- To rotate a secret, generate a new one, re-sign and re-verify one report with
  the new secret, then retire the old secret. Reports signed with the old secret
  will fail verification with `signature_mismatch` until re-signed; keep the old
  secret (offline) if you need to verify historical artifacts.

## CI usage

See [`ci-integration.md`](ci-integration.md) for how envelope signing composes
with strict scans, SARIF upload, and scheduled audits in GitHub Actions, and
see [`../README.md`](../README.md) for quick-start examples.
