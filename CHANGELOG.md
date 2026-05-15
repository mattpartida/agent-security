# Changelog

All notable changes to this project will be documented in this file.

This project follows semantic-versioning guidance once recurring releases are tagged. Until then, unreleased changes are grouped by impact so users can distinguish scanner behavior changes from documentation-only polish.

## Unreleased

### Rule or schema changes

- Added additive JSON output fields `suppressed_findings` and `suppressed_summary` for Phase 9 baseline suppressions.
- No rule ID or default severity changes in the Phase 9 baseline batch.

### Script CLI changes

- Added `--baseline <path>` to `skills/agent-security/scripts/config_risk_summary.py` for exact, auditable `rule_id` + evidence-path suppressions.

### Documentation-only updates

- Added `docs/baselines.md` and `examples/baselines/agent-security-baseline.json` for baseline usage, review cadence, and suppression removal guidance.
- Added a post-Phase-8 roadmap covering Phase 9 through Phase 12 adoption-at-scale work.
- Added Phase 9 regression coverage in `tests/test_phase9_baselines.py`.
