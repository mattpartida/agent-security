# Config risk report comparison

Phase 21 adds deterministic finding fingerprints and a stored-report comparison mode to `config_risk_summary.py`. The comparison is report-only: it never rewrites the input reports (`writes_to_reports: false`) and it does not scan stdin.

## Finding fingerprints

Each JSON finding includes an additive `fingerprint` field:

```text
sha256:<64 lowercase hex>
```

The digest covers a canonical identity of:

- `rule_id`
- `risk`
- sorted unique `evidence_paths`

Severity, recommendations, and source line numbers are not part of the identity, so the same active finding stays comparable across report metadata changes. SARIF results copy the same fingerprint into result `properties` and `partialFingerprints.agentSecurityFinding`. `schema_version` remains `1.0`.

Legacy JSON reports that omit `fingerprint` are still comparable. The comparison recomputes identity fingerprints from `rule_id`, `risk`, and `evidence_paths`.

## Compare stored reports

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --compare-reports before.json after.json
```

The command classifies active `findings` as:

- `new_findings`
- `persisting_findings`
- `resolved_findings`

Default comparison exits `0` even when new findings exist. JSON `ok` is `false` when new findings are present.

## Fail on new findings

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --compare-reports before.json after.json \
  --fail-on-new
```

`--fail-on-new` exits `1` only when new active findings exist. The complete comparison JSON or Markdown still goes to stdout. Validation and usage errors go to stderr and exit `2`.

## Markdown

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --compare-reports before.json after.json \
  --format markdown
```

Markdown output is intended for PR comments or review notes. Table cells escape pipes and neutralize `@everyone` / `@here` mentions. SARIF is not a comparison format.

## Guardrails

- Do not combine `--compare-reports` with scan flags such as `--strict`, `--baseline`, `--policy`, or `--generate-baseline`.
- Duplicate finding identities in either report fail closed.
- Missing `findings` arrays fail closed.
- Reports larger than 2,000,000 bytes fail closed.
- Comparison reads only the two supplied JSON files and does not mutate them.
