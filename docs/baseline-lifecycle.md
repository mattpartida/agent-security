# Baseline lifecycle tooling

Phase 11 makes baselines temporary, owned, and cleanup-friendly. Baseline entries still match findings by exact `rule_id` plus exact `evidence_paths`, but each suppression now also needs lifecycle metadata so accepted risk does not become permanent hidden risk.

## Generate a starting baseline

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --generate-baseline \
  < examples/high-risk-agent-config.json \
  > agent-security-baseline.json
```

`--generate-baseline` emits the current findings as a baseline skeleton with TODO review metadata:

- `owner`: who owns removing or renewing the suppression
- `ticket`: the tracking issue or risk-acceptance ticket
- `reason`: why this exact finding is temporarily accepted
- `expires_at`: ISO date (`YYYY-MM-DD`) when the suppression stops hiding the finding

Review and replace every TODO before using the generated file in CI.

## Required suppression metadata

Every suppression must contain:

```json
{
  "rule_id": "ASG-002",
  "evidence_paths": ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"],
  "owner": "security-team",
  "ticket": "SEC-123",
  "reason": "Temporary exception while private-network browser access is migrated.",
  "expires_at": "2026-06-30"
}
```

The scanner fails closed with an `invalid_baseline` finding if `owner`, `ticket`, `reason`, or a valid ISO `expires_at` value is missing.

## `baseline_lifecycle` output

JSON output includes a `baseline_lifecycle` object when a baseline is supplied:

- `active`: non-expired suppressions that matched a current finding and moved it into `suppressed_findings`
- `expired`: expired suppressions; matching findings remain active and can fail `--strict`
- `stale`: non-expired suppressions that no longer match any current finding
- `owner_summary`: owner-grouped counts for `active`, `expired`, and `stale` entries

Expired and stale entries are intentionally distinct. Expired entries represent risk-acceptance debt that needs renewal or removal; stale entries usually mean the finding was fixed or its evidence path changed and the suppression can be deleted or regenerated.

## Cleanup fail flags

Use these flags in scheduled or cleanup-only CI jobs:

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --baseline examples/baselines/agent-security-baseline.json \
  --fail-on-stale-baseline \
  < examples/high-risk-agent-config.json

python3 skills/agent-security/scripts/config_risk_summary.py \
  --baseline examples/baselines/agent-security-baseline.json \
  --fail-on-expired-baseline \
  < examples/high-risk-agent-config.json
```

`--fail-on-stale-baseline` fails only for stale entries. `--fail-on-expired-baseline` fails only for expired entries. Normal scanner validation errors and `--strict` / `--fail-on` behavior remain separate, so cleanup automation can distinguish stale cleanup from expired risk acceptance.

## Review pattern

1. Generate or update a baseline only after reviewing the active findings.
2. Assign a real owner and ticket before committing the baseline.
3. Pick short `expires_at` dates for high/critical findings.
4. Review `owner_summary` in CI output and chase owners with expired entries first.
5. Remove stale entries promptly so baselines reflect current risk, not historical findings.
