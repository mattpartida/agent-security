# Auditable baselines

Auditable baselines let existing deployments adopt `config_risk_summary.py` without turning off rules or hiding known findings. A baseline suppression is intentionally narrow: it must match the exact `rule_id` and the exact evidence path set emitted by a finding.

## Use a baseline

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --baseline examples/baselines/agent-security-baseline.json \
  --strict \
  < examples/high-risk-agent-config.json
```

Without a matching baseline entry, `--strict` still fails on high or critical active findings. With a matching entry, the finding moves from `findings` into `suppressed_findings`, and strict/fail-on behavior is recomputed from only the active findings.

## Baseline file shape

```json
{
  "version": 1,
  "suppressions": [
    {
      "rule_id": "ASG-002",
      "evidence_paths": ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"],
      "owner": "security-team",
      "reason": "Temporary exception while the shared browser profile is being split.",
      "ticket": "SEC-123",
      "expires_at": "2026-06-30"
    }
  ]
}
```

Required fields:

- exact `rule_id`, such as `ASG-002`
- at least one exact `evidence_paths` entry
- non-empty `owner`, `ticket`, and `reason`
- valid ISO `expires_at` date (`YYYY-MM-DD`)

See [`baseline-lifecycle.md`](baseline-lifecycle.md) for `--generate-baseline`, expired/stale suppression handling, owner-grouped lifecycle output, and cleanup fail flags.

## Output contract

When a baseline is supplied, JSON output contains active and suppressed findings separately:

- `findings` — active findings that still affect `ok`, `risk_count`, `counts`, `--strict`, and `--fail-on`
- `suppressed_findings` — matching findings retained for audit, each with a `suppression` object copied from baseline metadata
- `suppressed_summary` — suppressed count and severity counts
- `baseline_lifecycle` — active, expired, and stale suppression entries plus `owner_summary` counts

A suppression never deletes evidence. It moves a finding into an explicit audit field.

## Exact matching rules

Baseline matching is deliberately strict:

1. The finding `rule_id` must equal the baseline `rule_id`.
2. The finding evidence path set must equal the baseline evidence path set.
3. A baseline for one evidence path does not suppress the same rule at a different path.
4. Composite findings require the full composite evidence path set, not only one causal field.

This prevents a reviewed exception for one config path from accidentally suppressing the same rule somewhere else.

## Review cadence

The review cadence should be explicit and tied to scanner/config changes.
Review baselines whenever:

- scanner rules or evidence paths change
- a finding is mitigated
- an owner, ticket, or expiry date changes
- a deployment moves from personal to shared use
- CI begins passing only because of baseline suppressions

## Remove suppressions

Use this section to remove suppressions as soon as their underlying findings are fixed.

Remove suppressions as soon as the underlying finding is fixed. Treat `suppressed_summary.count` as adoption debt: it should trend down over time, not become a permanent blind spot.
