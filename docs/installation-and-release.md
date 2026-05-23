# Installation and Release Guide

Phase 7 makes the skillpack straightforward to install, inspect, version, and release without adding runtime dependencies.

## Install from packaged archives

Build the distributable archives from a clean checkout:

```bash
./package-skills.sh
```

The command writes:

```text
dist/agent-security.skill
dist/healthcheck.skill
```

Import those `.skill` archives with the AgentSkills-compatible import flow for your agent runtime. If your runtime supports importing local files, select the archive from `dist/`. If it expects unpacked source, unzip the archive into the runtime's skills directory while preserving the top-level skill folder name.

## Inspect a packaged archive before importing

Treat skill archives like executable dependencies. Inspect contents before importing them into a real agent environment:

```bash
python3 - <<'PY'
from pathlib import Path
from zipfile import ZipFile

for archive in sorted(Path('dist').glob('*.skill')):
    print(f'## {archive}')
    with ZipFile(archive) as zf:
        bad = zf.testzip()
        if bad:
            raise SystemExit(f'{archive} has corrupt member: {bad}')
        for name in zf.namelist():
            print(name)
PY
```

Expected top-level archives:

- `agent-security.skill` contains `agent-security/SKILL.md`, `references/`, and `scripts/`.
- `healthcheck.skill` contains `healthcheck/SKILL.md`, `references/`, and `scripts/`.

## Use from the source tree

For local development or read-only inspection, you can use the source tree directly:

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  --strict \
  < examples/hardened-agent-config.json

python3 skills/agent-security/scripts/score_prompt_injection_exposure.py \
  < examples/high-risk-agent-config.json

python3 skills/healthcheck/scripts/parse_openclaw_audit.py \
  < path/to/audit-output.json
```

Source-tree usage is best for development, CI examples, and validating a config before packaging. Packaged archives are best for sharing or importing into an agent runtime.

## Archive integrity

Local tests verify required files exist inside generated skill archives and that each archive can be opened by Python's `zipfile` module:

```bash
python3 -m pytest tests/test_phase7_packaging_release.py -q
```

The integrity test checks for required `SKILL.md`, `references/`, and `scripts/` members, rejects corrupt zip members, and guards against unsafe absolute or parent-directory archive paths.

## Release checklist

Before tagging or publishing a release, complete this checklist from a clean checkout:

1. Rebuild archives:
   ```bash
   ./package-skills.sh
   ```
2. Run the local quality gate:
   ```bash
   python3 -m compileall -q skills tests
   python3 -m pytest -q
   ruff check .
   ./package-skills.sh
   git diff --check
   ```
3. Review rule docs:
   - `skills/agent-security/references/rules.md`
   - `docs/rule-coverage.md`
   - new or changed `ASG-###` metadata in `config_risk_summary.py`
4. Review prompt-injection and config fixtures:
   - `tests/fixtures/prompt-injection/manifest.json`
   - `examples/config-shapes/*.json`
   - `examples/high-risk-agent-config.json`
   - `examples/hardened-agent-config.json`
5. Run a No-real-secret scan over changed docs, fixtures, and archives. Do not publish real credentials, private URLs, customer data, tokens, cookies, or live exploit infrastructure.
6. Inspect archive contents with the command in this guide and confirm only intended skill files are packaged.
7. Update `CHANGELOG.md` with release notes under the correct categories.
8. Confirm GitHub Actions is green for the release commit before tagging.

## Versioning guidance

Use semantic versioning for recurring releases. Until formal tags are used, keep `CHANGELOG.md` entries under `Unreleased`.

### Rule or schema changes

Use a minor version bump when adding a new `ASG-###` rule, adding new output fields, or expanding supported config shapes in a backwards-compatible way. Use a major version bump if a published rule ID is removed, a field is renamed, or detection semantics change in a way that can break downstream consumers.

Every rule or schema change should update:

- `skills/agent-security/references/rules.md`
- `docs/rule-coverage.md`
- focused tests for risky and safe cases
- `CHANGELOG.md` under `Rule or schema changes`

### Script CLI changes

Use a minor version bump for backwards-compatible CLI additions such as a new optional flag or output format. Use a patch version for bug fixes that preserve the CLI contract. Use a major version bump for renamed flags, changed default formats, or changed exit-code behavior.

Document script CLI changes in `CHANGELOG.md` under `Script CLI changes`.

### Documentation-only updates

Use a patch version or no version bump for docs-only corrections, example clarifications, typo fixes, and checklist polish. Record meaningful docs changes under `Documentation-only updates` so users can distinguish guidance changes from scanner behavior changes.
