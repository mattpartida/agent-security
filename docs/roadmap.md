# Agent Security Roadmap

This roadmap is the source of truth for planned `mattpartida/agent-security` improvements. It favors small, auditable batches that keep the skillpack dependency-light while making the scanners, examples, and packaged skills more useful in real agent deployments.

## Current baseline

- Two packaged skills: `agent-security` for runtime/tool/prompt-injection review and `healthcheck` for host/deployment posture.
- CI runs ruff, compileall, pytest, and skill packaging on push and PR.
- `config_risk_summary.py` emits stable `ASG-###` rule IDs for JSON config/status posture findings.
- `score_prompt_injection_exposure.py` scores risky combinations across channels, browser, exec, filesystem, models, bindings, and persistence.
- `flag_prompt_injection_signals.py` detects direct, indirect, encoded, persistence, approval-bypass, and tool-coercion prompt-injection signals.
- Example hardened/high-risk configs and a high-risk report example demonstrate intended output.

## Active pull requests that affect the roadmap

- PR #2, `feat: add markdown config risk summaries`, overlaps with **Phase 1**.
- PR #3, `test: add prompt injection fixture corpus`, overlaps with **Phase 3**.

Do not duplicate those branches when implementing roadmap work. If either PR merges, update this roadmap's baseline and mark the relevant accepted scope as shipped.

## Phase 1: Human-readable and machine-readable output formats

**Status:** Shipped
**Goal:** Make scanner output easy to use in PR comments, Discord updates, issue triage, and GitHub Code Scanning.

### Shipped scope

1. Added `--format json|markdown|sarif` to `skills/agent-security/scripts/config_risk_summary.py` while keeping JSON as the default.
2. Added markdown output with severity counts, stable rule IDs, evidence fields, and remediation guidance.
3. Added SARIF 2.1.0 output with emitted rule metadata and findings as SARIF results.
4. Added tests that parse JSON/markdown/SARIF outputs and assert stable `ASG-###` rule IDs.
5. Added README examples for markdown output and SARIF generation.

### Acceptance criteria

- `python -m pytest tests/test_config_risk_summary.py -q` covers JSON, markdown, and SARIF output.
- SARIF validates as JSON and contains `runs[].tool.driver.rules` entries for all emitted rule IDs.
- Existing JSON consumers continue to work without flags.

## Phase 2: Evidence paths and source locations

**Status:** Shipped
**Goal:** Help users trace each finding back to the relevant config field instead of manually hunting through large status dumps.

### Shipped scope

1. Added `evidence_paths` to every `ASG-###` `config_risk_summary.py` finding, including composite risks like shared channel + private-network browser.
2. Added structured `evidence` objects for useful observed details such as agent IDs, array indexes, model names, expected schema types, and observed values.
3. Added best-effort source-location mapping that resolves evidence paths to approximate one-based line numbers in JSON/YAML/TOML-like input text, with line `1` fallback when unresolved.
4. Included evidence paths and source locations in JSON and SARIF output, and evidence paths in Markdown output.
5. Documented evidence-path semantics in `skills/agent-security/references/rules.md`.

### Acceptance criteria

- Every `ASG-###` finding includes at least one non-empty `evidence_paths` entry.
- Composite findings include all contributing fields, not just the final risk key.
- Tests cover nested dictionaries, arrays such as `agents.list[]` and `bindings[]`, and fallback behavior when a line cannot be resolved.

## Phase 3: Prompt-injection fixture corpus and detector evaluation

**Status:** Shipped
**Goal:** Turn prompt-injection examples into a reusable regression suite with clear expected signals and known limitations.

### Tasks

1. Maintain a manifest-backed corpus under `tests/fixtures/prompt-injection/`.
2. Cover direct override, indirect webpage content, encoded/base64 text, zero-width obfuscation, fake approvals, memory poisoning, tool-output exfiltration, benign negatives, and high-risk config examples.
3. Add corpus tests that replay every text fixture through `flag_prompt_injection_signals.py` and every config fixture through exposure scoring.
4. Add detector-quality documentation in [`docs/prompt-injection-detector-quality.md`](prompt-injection-detector-quality.md) that names false positives, false negatives, and when to add a new fixture.
5. Add a small corpus summary command or script once the manifest grows beyond a handful of cases.

### Acceptance criteria

- The manifest must be complete, unique, and path-contained.
- Every malicious fixture asserts at least one expected signal.
- At least one benign fixture verifies the scanner does not flag normal project/status prose.
- CI fails if a detector regression drops an expected signal.

## Phase 4: Real-world config-shape coverage

**Status:** Shipped
**Goal:** Make the scripts resilient across Hermes/OpenClaw-style config shapes without hard-coding one schema.

### Tasks

1. Add `examples/config-shapes/` with representative personal-local, Discord-shared, browser-agent, cron-memory-agent, and CI-only scanner configs.
2. Add tests that run both config scripts across every example shape.
3. Document canonical fields, aliases, and best-effort compatibility paths in [`docs/config-shapes.md`](config-shapes.md).
4. Add malformed-but-safe examples for wrong types, missing optional sections, and unknown future keys.
5. Keep invalid schema behavior non-crashing and explicit.

### Acceptance criteria

- Every example config is covered by a test.
- Wrong-type and missing-key inputs return structured errors/findings instead of tracebacks.
- README documents how users can adapt their own config/status JSON to the expected shape.

## Phase 5: Rule coverage and severity calibration

**Status:** Shipped
**Goal:** Make each `ASG-###` rule testable, explainable, and calibrated against both risky and hardened configurations.

### Shipped scope

1. Added [`docs/rule-coverage.md`](rule-coverage.md), mapping every `ASG-###` rule to focused risky and safe/negative coverage.
2. Added `tests/test_phase5_rule_coverage.py` with a focused risky and safe case for every stable rule ID from `ASG-001` through `ASG-015`, plus variant checks for multi-risk IDs `ASG-004` and `ASG-005`.
3. Asserted each risky case emits the expected rule ID, severity, evidence path, and mitigation/recommendation field.
4. Documented severity rationale and compensating-control guidance for every rule.
5. No severity or detection semantics changed in Phase 5; JSON output gained additive metadata-backed `recommendation` text for ASG findings, so no changelog note was required.

### Acceptance criteria

- No `ASG-###` rule lacks both risky and safe coverage.
- Tests assert rule IDs, severity, and at least one mitigation/recommendation field.
- Severity changes require explicit documentation updates.

## Phase 6: CI and downstream integration examples

**Status:** Shipped
**Goal:** Show users how to run the skillpack in their own repos and automation without granting unnecessary permissions.

### Shipped scope

1. Added [`examples/ci/github-actions/agent-security-strict.yml`](../examples/ci/github-actions/agent-security-strict.yml) for read-only, strict merge-blocking config scans.
2. Added [`examples/ci/github-actions/agent-security-sarif.yml`](../examples/ci/github-actions/agent-security-sarif.yml) for optional SARIF upload with the required `security-events: write` permission.
3. Added [`docs/ci-integration.md`](ci-integration.md) covering PR comment markdown, scheduled audits, local preflight checks, minimal permissions, and failure-mode triage.
4. Added `tests/test_phase6_ci_integration_examples.py` to validate workflow example shape, expected commands, SARIF upload wiring, safe permissions, README links, and roadmap status.
5. Kept quick-start documentation compact by pointing README readers to the dedicated integration guide and `examples/ci/github-actions/` directory.

### Acceptance criteria

- Workflow examples are syntactically valid YAML.
- Tests assert no workflow example uses broad write permissions unless required and documented.
- README points users to the integration examples without bloating quick start.

## Phase 7: Packaging, release, and installation polish

**Status:** Shipped
**Goal:** Make the skillpack straightforward to install, verify, version, and release.

### Shipped scope

1. Added [`docs/installation-and-release.md`](installation-and-release.md) with installation/import instructions for packaged `.skill` archives and source-tree usage.
2. Added a release checklist covering packaging, CI, rule-doc review, fixture review, archive inspection, and no-real-secret scans.
3. Added `tests/test_phase7_packaging_release.py` to rebuild `dist/*.skill` archives and assert required files, zip integrity, safe archive paths, README links, roadmap status, and release-note categories.
4. Added versioning guidance for rule/schema changes, script CLI changes, and documentation-only updates.
5. Added [`CHANGELOG.md`](../CHANGELOG.md) with release-note categories that distinguish rule/schema changes, script CLI changes, and documentation-only updates.

### Acceptance criteria

- A new user can install or inspect the packaged skills from documented steps.
- CI or local tests verify required files exist inside generated skill archives.
- Release notes distinguish rule changes, script CLI changes, and documentation-only updates.

## Phase 8: Healthcheck and agent-security boundary cleanup

**Status:** Shipped
**Goal:** Clarify when to use `agent-security`, `healthcheck`, or both, especially for private-network/browser and host-exposure issues.

### Shipped scope

1. Added concise decision tables to `skills/README.md` and the root README so users can choose `agent-security`, `healthcheck`, or both from one table.
2. Added [`docs/skill-boundary.md`](skill-boundary.md) with shared-concept ownership for SSRF, exposed services, cron, rollback, cross-skill handoff rules, and non-duplication guidance.
3. Added [`examples/reports/combined-browser-private-network-boundary.md`](../examples/reports/combined-browser-private-network-boundary.md), a combined report snippet for browser private-network exposure on a shared host.
4. Updated `skills/agent-security/SKILL.md` and `skills/healthcheck/SKILL.md` with cross-links and explicit `ASG-###` ownership boundaries so healthcheck references agent findings without duplicating them.
5. Added `tests/test_phase8_skill_boundary.py` to verify decision tables, cross-links, combined report coverage, roadmap status, and dependency-light markdown link integrity.

### Acceptance criteria

- Users can choose the right skill from a single table.
- Shared concepts such as SSRF, exposed services, cron, and rollback have clear ownership.
- No conflicting mitigation language appears between the two skills.

## Implementation order

1. Finish or merge PRs that already cover roadmap work before starting duplicate branches.
2. Ship Phase 1 and Phase 2 together only if the diff stays small; otherwise do markdown/SARIF first, then evidence paths.
3. Expand Phase 3 as new prompt-injection bypasses are found.
4. Use Phases 4 and 5 to prevent schema and rule drift after output formats stabilize.
5. Treat Phases 6 through 8 as repo credibility and adoption polish once scanner outputs are stable.

## Verification checklist for roadmap changes

For docs-only roadmap edits:

```bash
python -m compileall -q skills tests
python -m pytest -q
ruff check .
./package-skills.sh
```

For implementation phases, also run the most focused touched test file first, then the full checklist above.
