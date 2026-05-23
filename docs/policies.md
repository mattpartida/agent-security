# Policy files

Policy files let teams adapt `config_risk_summary.py` to organization-specific review decisions without changing default `ASG-###` rule metadata. They are intended for staged adoption: defaults stay conservative, while local exceptions remain visible in output.

## Use a policy

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --policy examples/policies/agent-security-policy.json \
  --strict \
  < examples/high-risk-agent-config.json
```

Policies are JSON and dependency-light. Invalid policies fail before scanning with an `invalid_policy` finding so CI does not proceed with ambiguous review rules.

## Policy file shape

```json
{
  "version": 1,
  "metadata": {
    "owner": "security-team",
    "reason": "Staged scanner adoption policy.",
    "ticket": "SEC-123"
  },
  "severity_overrides": {
    "ASG-002": "warn"
  },
  "disabled_rules": ["ASG-014"],
  "allowlists": [
    {
      "rule_id": "ASG-002",
      "evidence_paths": ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"],
      "reason": "Temporary exception for an isolated local browser-only profile.",
      "owner": "platform-security",
      "ticket": "SEC-456"
    }
  ]
}
```

Supported fields:

- `severity_overrides` — map stable `ASG-###` rule IDs to one of `error`, `critical`, `high`, `warn`, or `info`.
- `disabled_rules` — list of stable `ASG-###` rule IDs to suppress explicitly for this policy.
- `allowlists` — exact `rule_id` plus exact `evidence_paths` matches, scoped like baselines.
- `metadata` — optional default `owner`, `reason`, `ticket`, and `expires_at` copied into policy suppression audit records.

## Output contract

Policy decisions never silently delete findings:

- `findings` — active findings after policy severity overrides and policy/baseline suppression.
- `policy_suppressed_findings` — findings suppressed by `disabled_rules` or exact `allowlists`, each with a `policy` object that names the suppression type and copied review metadata.
- `policy_suppressed_summary` — count and severity counts for policy-suppressed findings.
- `suppressed_findings` and `suppressed_summary` — baseline-suppressed findings, applied after policy suppression.

Severity overrides are also auditable. JSON and SARIF findings include `policy.severity_override` with the original and effective severity. SARIF rule metadata continues to report the static default severity so downstream consumers can distinguish defaults from local policy.

## Policy precedence

Policy precedence is intentionally simple:

1. Validate policy and baseline files before scanning.
2. Apply policy `severity_overrides` to emitted findings.
3. Apply policy `disabled_rules` and exact `allowlists`, moving matches into `policy_suppressed_findings`.
4. Apply baseline suppressions to the remaining active findings.
5. Recompute `ok`, `risk_count`, severity counts, `--strict`, and `--fail-on` from the final active findings.

This means organization policy can narrow or downgrade known local context before a per-repository baseline handles already-reviewed findings.

## Safe review patterns

Use these review patterns to keep policies auditable:

- Prefer exact `allowlists` for one reviewed evidence path over broad `disabled_rules`.
- Keep default severities unchanged unless a team can explain the compensating control.
- Include `owner`, `reason`, and `ticket` metadata for every durable exception.
- Review policies whenever rule documentation, evidence paths, or deployment trust boundaries change.
- Treat `policy_suppressed_summary.count` as security debt in the same way as baseline suppressions.
