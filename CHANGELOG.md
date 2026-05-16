# Changelog

All notable changes to this project will be documented in this file.

This project follows semantic-versioning guidance once recurring releases are tagged. Until then, unreleased changes are grouped by impact so users can distinguish scanner behavior changes from documentation-only polish.

## Unreleased

### Rule or schema changes

- Added additive JSON output fields `policy_suppressed_findings` and `policy_suppressed_summary` for Phase 10 policy suppressions.
- Added additive JSON/SARIF `policy.severity_override` metadata when a policy changes a finding's effective severity.
- Added additive JSON output fields `suppressed_findings` and `suppressed_summary` for Phase 9 baseline suppressions.
- No rule ID or default severity changes in the Phase 10 policy batch; static rule metadata remains unchanged when local policies override effective severity.
- No rule ID or default severity changes in the Phase 9 baseline batch.

### Script CLI changes

- Added `--policy <path>` to `skills/agent-security/scripts/config_risk_summary.py` for dependency-light organization policy files with severity overrides, disabled rules, and exact evidence-path allowlists.
- Added `--baseline <path>` to `skills/agent-security/scripts/config_risk_summary.py` for exact, auditable `rule_id` + evidence-path suppressions.

### Documentation-only updates

- Added `docs/policies.md` and `examples/policies/agent-security-policy.json` for Phase 10 policy validation, precedence, and safe review patterns.
- Added Phase 10 regression coverage in `tests/test_phase10_policies.py`.
- Added `docs/baselines.md` and `examples/baselines/agent-security-baseline.json` for baseline usage, review cadence, and suppression removal guidance.
- Added a post-Phase-8 roadmap covering Phase 9 through Phase 12 adoption-at-scale work.
- Added Phase 9 regression coverage in `tests/test_phase9_baselines.py`.
