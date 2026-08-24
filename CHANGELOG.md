# Changelog

All notable changes to this project will be documented in this file.

This project follows semantic-versioning guidance once recurring releases are tagged. Until then, unreleased changes are grouped by impact so users can distinguish scanner behavior changes from documentation-only polish.

## Unreleased

### Rule or schema changes

- Added Phase 12 schema adapter reporting (`schema.adapter`, Markdown, and SARIF properties) plus adapter normalization for OpenAI-compatible tools, Claude Desktop/MCP server configs, and GitHub Actions snippets.
- Markdown config risk summaries now include policy/baseline suppression counts and baseline owner lifecycle tables when suppression inputs are supplied.
- Added additive JSON output field `baseline_lifecycle` with active, expired, stale, and owner-grouped baseline suppression lifecycle state.
- Baseline suppressions now require lifecycle metadata (`owner`, `ticket`, `reason`, and ISO `expires_at`) and expired entries no longer suppress active findings.
- Added additive JSON output fields `policy_suppressed_findings` and `policy_suppressed_summary` for Phase 10 policy suppressions.
- Added additive JSON/SARIF `policy.severity_override` metadata when a policy changes a finding's effective severity.
- Added additive JSON output fields `suppressed_findings` and `suppressed_summary` for Phase 9 baseline suppressions.
- No rule ID or default severity changes in the Phase 10 policy batch; static rule metadata remains unchanged when local policies override effective severity.
- No rule ID or default severity changes in the Phase 9 baseline batch.

### Script CLI changes

- Added `--envelope-secret-file` to `skills/agent-security/scripts/config_risk_summary.py` for optional HMAC-SHA256 report authenticity envelopes on JSON output, plus the dependency-light `skills/agent-security/scripts/verify_report_envelope.py` verifier with `--secret-file`/`--secret-env` sources and machine-readable failure codes.
- Replaced ad-hoc ZIP packaging with reproducible `scripts/package_skills.py`, deterministic `dist/MANIFEST.json` release metadata, and a non-mutating `--check` drift gate while preserving `./package-skills.sh`.
- Added `--format json|markdown` to `skills/agent-security/scripts/flag_prompt_injection_signals.py` for review-friendly prompt-injection signal summaries while keeping JSON as the default.
- Added `--output-dir` to `skills/agent-security/scripts/summarize_prompt_injection_corpus.py` for paired JSON/Markdown prompt-corpus review packets with no manifest or fixture mutation.
- Added non-fatal `undocumented_case_kind` warnings to prompt-injection corpus summaries for unknown fixture categories.
- Added `ok`, `summary`, `issues`, and `--strict` to `skills/agent-security/scripts/summarize_prompt_injection_corpus.py` for prompt-injection corpus quality gates.
- Added `--include-cases` to `skills/agent-security/scripts/summarize_prompt_injection_corpus.py` for stable JSON/Markdown per-fixture inventory exports.
- Added Phase 13 healthcheck helper `--format json|markdown` and `--strict` options to `skills/healthcheck/scripts/parse_openclaw_audit.py` and `skills/healthcheck/scripts/summarize_openclaw_posture.py`.
- Added `--generate-baseline`, `--fail-on-stale-baseline`, and `--fail-on-expired-baseline` to `skills/agent-security/scripts/config_risk_summary.py` for baseline lifecycle cleanup workflows.
- Added `--policy <path>` to `skills/agent-security/scripts/config_risk_summary.py` for dependency-light organization policy files with severity overrides, disabled rules, and exact evidence-path allowlists.
- Added `--baseline <path>` to `skills/agent-security/scripts/config_risk_summary.py` for exact, auditable `rule_id` + evidence-path suppressions.

### Documentation-only updates

- Added `docs/schema-adapters.md` and Phase 12 regression coverage in `tests/test_phase12_schema_adapters.py` for adapter fixtures, explicit ignored fields, SARIF/Markdown adapter reporting, and cross-platform path serialization.
- Added `docs/baseline-lifecycle.md` and Phase 11 regression coverage in `tests/test_phase11_baseline_lifecycle.py` for generated baselines, required lifecycle metadata, stale/expired cleanup, and owner summaries.
- Added `docs/policies.md` and `examples/policies/agent-security-policy.json` for Phase 10 policy validation, precedence, and safe review patterns.
- Added Phase 10 regression coverage in `tests/test_phase10_policies.py`.
- Added `docs/baselines.md` and `examples/baselines/agent-security-baseline.json` for baseline usage, review cadence, and suppression removal guidance.
- Added a post-Phase-8 roadmap covering Phase 9 through Phase 12 adoption-at-scale work.
- Added Phase 9 regression coverage in `tests/test_phase9_baselines.py`.
