# Contributing

Thanks for improving the OpenClaw Agent Security Skillpack. This repository is intentionally dependency-light and should stay easy to audit.

## Development setup

```bash
python3 -m compileall -q skills tests
python3 -m pytest -q
ruff check .
./package-skills.sh
```

If `pytest` is unavailable locally, you can still run individual script checks with `python` and rely on CI for the full matrix.

## Adding or changing a rule

1. Add or update the detection in `skills/agent-security/scripts/config_risk_summary.py`.
2. Assign a stable `ASG-###` rule ID in the script's `RULE_IDS` map.
3. Document the rule in `skills/agent-security/references/rules.md`.
4. Add a test in `tests/test_config_risk_summary.py` proving the rule appears for a representative config.
5. Include a recommended mitigation and, where useful, the relevant config field.

Rule IDs should remain stable once published. If a rule is split, keep the old ID documented and add new IDs for the narrower cases.

## Adding prompt-injection examples

Prompt-injection examples must be safe and clearly marked as test data.

Good examples:

- use fake secrets and fake attacker URLs
- include `TEST ONLY` when practical
- demonstrate one behavior at a time
- assert that the correct behavior is to treat the text as untrusted data

Avoid:

- real credentials or real private URLs
- working malware commands
- instructions that could cause harm if copied into a live unsandboxed agent

## Documentation standards

For checklist or reference changes, prefer concrete operational guidance:

- affected trust boundary
- exploit path
- severity rationale
- mitigation
- verification test
- rollback notes for config changes

Avoid presenting prompts as security boundaries. Guidance should prefer enforced controls: permissions, sandboxes, allowlists, egress gates, logging, and regression tests.

## Pull request checklist

- [ ] Tests added or updated for behavior changes
- [ ] `python3 -m compileall -q skills tests` passes
- [ ] `python3 -m pytest -q` passes, or CI is expected to run it
- [ ] `ruff check .` passes, or changes are limited to documentation
- [ ] `./package-skills.sh` succeeds if skill contents changed
- [ ] Documentation and examples do not contain real secrets
