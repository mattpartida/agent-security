# CI and downstream integration examples

Phase 6 shows how to run the `agent-security` config scanner in downstream repositories without broad automation permissions. The examples are intentionally copyable but conservative: start with read-only repository access, add write permissions only for the integration that needs them, and keep high-risk findings visible in both human and machine-readable outputs.

## Strict config scanning

Use [`examples/ci/github-actions/agent-security-strict.yml`](../examples/ci/github-actions/agent-security-strict.yml) when the config being scanned should block merges on high or critical findings. It runs:

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --strict \
  < examples/high-risk-agent-config.json
```

`--strict` exits non-zero for high and critical findings. Replace the example input path with the checked-in config/status JSON your repository wants to enforce.

## Optional SARIF upload

Use [`examples/ci/github-actions/agent-security-sarif.yml`](../examples/ci/github-actions/agent-security-sarif.yml) when you want GitHub Code Scanning annotations. The workflow writes `agent-security.sarif` and uploads it with `github/codeql-action/upload-sarif@v4`.

SARIF upload requires:

```yaml
permissions:
  contents: read
  security-events: write
```

Do not add broader write permissions for SARIF-only scans.

Prompt-injection signal and exposure scanners can emit SARIF the same way:

```bash
python3 skills/agent-security/scripts/flag_prompt_injection_signals.py --format sarif
python3 skills/agent-security/scripts/score_prompt_injection_exposure.py --format sarif
```

See [`examples/ci/github-actions/agent-security-prompt-sarif.yml`](../examples/ci/github-actions/agent-security-prompt-sarif.yml) for a copyable upload workflow. JSON remains the default for both scanners.

## PR comment markdown

For a human-readable PR comment, render Markdown and post it with an existing review/comment action or your platform's bot token:

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --format markdown \
  < path/to/agent-config.json \
  > agent-security.md
```

Minimal permissions for this pattern are `contents: read` plus `pull-requests: write` only when posting PR comments. If the workflow only uploads `agent-security.md` as an artifact, keep repository permissions read-only.

## Scheduled audits

A scheduled audit can run the same strict or SARIF command nightly or weekly against production-like config exports. Prefer a read-only token that can fetch the config artifact and write only the destination you need:

- `contents: read` for checked-in configs.
- `security-events: write` only when uploading SARIF.
- No `contents: write`, `actions: write`, or broad organization tokens for scanner-only jobs.

## Local preflight checks

Before pushing config changes, run the same command locally:

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --format markdown \
  < path/to/agent-config.json
```

To smoke all three scanners in one command, wrap config-risk, exposure scoring, and prompt-injection signals:

```bash
python3 skills/agent-security/scripts/preflight.py \
  --config path/to/agent-config.json \
  --text path/to/untrusted-content.txt
```

For release branches or security-sensitive config changes, run `--strict` locally so high or critical findings fail before CI does:

```bash
python3 skills/agent-security/scripts/preflight.py \
  --strict \
  --config path/to/agent-config.json \
  --text path/to/untrusted-content.txt
```

## Stored report comparison

Use [`examples/ci/github-actions/agent-security-compare-reports.yml`](../examples/ci/github-actions/agent-security-compare-reports.yml) when a previous JSON report is stored as a baseline artifact. Replace the placeholder paths with the previous and current `config_risk_summary.py` JSON outputs:

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --compare-reports before.json after.json \
  --fail-on-new
```

`--fail-on-new` exits non-zero only for new active findings. Default comparison remains exit `0` and does not rewrite the input reports. See [`docs/report-comparison.md`](report-comparison.md) for fingerprint identity and validation failures.

## Minimal permissions

| Integration | Minimum permissions | Notes |
| --- | --- | --- |
| Strict config scanning | `contents: read` | Blocks with the scanner exit code; no write permissions needed. |
| Optional SARIF upload | `contents: read`, `security-events: write` | Required by GitHub Code Scanning upload. |
| PR comment markdown | `contents: read`, `pull-requests: write` | Add `pull-requests: write` only when posting PR comments. |
| Scheduled audits | Depends on destination | Keep scanner token read-only unless the destination requires a narrow write scope. |
| Local preflight checks | None | Run before CI to catch high/critical findings early. |

## Failure modes

High or critical findings should block merges for shared, production, or privileged agent configs. Treat a failing strict scan as a security review request, not as a flaky CI failure. Common next steps:

1. Read the JSON/Markdown/SARIF finding and its `rule_id`.
2. Follow the `recommendation` field or [`docs/rule-coverage.md`](rule-coverage.md) compensating controls.
3. Re-run locally with `--format markdown` for a reviewer-friendly summary.
4. If the risk is intentionally accepted, document the compensating controls outside this scanner before weakening CI.

Warnings and info findings can be non-blocking in early adoption, but they should still be reviewed when they involve shared channels, persistence, browser access, shell access, or sandboxing.
