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

**Status:** Planned  
**Goal:** Help users trace each finding back to the relevant config field instead of manually hunting through large status dumps.

### Tasks

1. Add `evidence_paths` to every `config_risk_summary.py` finding, including composite risks like shared channel + private-network browser.
2. Add `evidence` objects where useful, including observed values, binding IDs, agent IDs, and model names.
3. Add a helper that maps evidence paths to approximate line numbers for JSON, YAML, and TOML examples where feasible.
4. Include evidence paths in markdown and SARIF output from Phase 1.
5. Document evidence-path semantics in `skills/agent-security/references/rules.md`.

### Acceptance criteria

- Every `ASG-###` finding includes at least one non-empty `evidence_paths` entry.
- Composite findings include all contributing fields, not just the final risk key.
- Tests cover nested dictionaries, arrays such as `agents.list[]` and `bindings[]`, and fallback behavior when a line cannot be resolved.

## Phase 3: Prompt-injection fixture corpus and detector evaluation

**Status:** Planned  
**Goal:** Turn prompt-injection examples into a reusable regression suite with clear expected signals and known limitations.

### Tasks

1. Maintain a manifest-backed corpus under `tests/fixtures/prompt-injection/`.
2. Cover direct override, indirect webpage content, encoded/base64 text, zero-width obfuscation, fake approvals, memory poisoning, tool-output exfiltration, benign negatives, and high-risk config examples.
3. Add corpus tests that replay every text fixture through `flag_prompt_injection_signals.py` and every config fixture through exposure scoring.
4. Add detector-quality documentation that names false positives, false negatives, and when to add a new fixture.
5. Add a small corpus summary command or script once the manifest grows beyond a handful of cases.

### Acceptance criteria

- The manifest must be complete, unique, and path-contained.
- Every malicious fixture asserts at least one expected signal.
- At least one benign fixture verifies the scanner does not flag normal project/status prose.
- CI fails if a detector regression drops an expected signal.

## Phase 4: Real-world config-shape coverage

**Status:** Planned  
**Goal:** Make the scripts resilient across Hermes/OpenClaw-style config shapes without hard-coding one schema.

### Tasks

1. Add `examples/config-shapes/` with representative personal-local, Discord-shared, browser-agent, cron-memory-agent, and CI-only scanner configs.
2. Add tests that run both config scripts across every example shape.
3. Document which fields are canonical, aliases, and best-effort compatibility paths.
4. Add malformed-but-safe examples for wrong types, missing optional sections, and unknown future keys.
5. Keep invalid schema behavior non-crashing and explicit.

### Acceptance criteria

- Every example config is covered by a test.
- Wrong-type and missing-key inputs return structured errors/findings instead of tracebacks.
- README documents how users can adapt their own config/status JSON to the expected shape.

## Phase 5: Rule coverage and severity calibration

**Status:** Planned  
**Goal:** Make each `ASG-###` rule testable, explainable, and calibrated against both risky and hardened configurations.

### Tasks

1. Add a rule-coverage table, likely `docs/rule-coverage.md`, mapping each `ASG-###` rule to risky and safe/negative fixtures.
2. Add a focused test for every rule ID, including safe negative coverage where the risky field is absent or mitigated.
3. Split broad rules only when the current `risk` key hides materially different mitigations.
4. Add severity rationale and compensating-control guidance for each rule.
5. Add a changelog note when a rule's severity or detection semantics changes.

### Acceptance criteria

- No `ASG-###` rule lacks both risky and safe coverage.
- Tests assert rule IDs, severity, and at least one mitigation/recommendation field.
- Severity changes require explicit documentation updates.

## Phase 6: CI and downstream integration examples

**Status:** Planned  
**Goal:** Show users how to run the skillpack in their own repos and automation without granting unnecessary permissions.

### Tasks

1. Add a GitHub Actions workflow example for strict config scanning and optional SARIF upload.
2. Add examples for PR comment markdown, scheduled audits, and local preflight checks.
3. Document minimal permissions for each workflow, especially `security-events: write` when SARIF upload is enabled.
4. Add tests that parse workflow examples and assert safe permissions and expected commands.
5. Add failure-mode notes for CI users, including when a high finding should block merges.

### Acceptance criteria

- Workflow examples are syntactically valid YAML.
- Tests assert no workflow example uses broad write permissions unless required and documented.
- README points users to the integration examples without bloating quick start.

## Phase 7: Packaging, release, and installation polish

**Status:** Planned  
**Goal:** Make the skillpack straightforward to install, verify, version, and release.

### Tasks

1. Add installation/import instructions for packaged `.skill` archives and source-tree usage.
2. Add a release checklist that includes packaging, CI, rule-doc review, fixture review, and no-real-secret scans.
3. Add package integrity checks such as archive contents tests for `dist/*.skill` outputs.
4. Add versioning guidance for rule/schema changes.
5. Add a `CHANGELOG.md` once releases become recurring.

### Acceptance criteria

- A new user can install or inspect the packaged skills from documented steps.
- CI or local tests verify required files exist inside generated skill archives.
- Release notes distinguish rule changes, script CLI changes, and documentation-only updates.

## Phase 8: Healthcheck and agent-security boundary cleanup

**Status:** Planned  
**Goal:** Clarify when to use `agent-security`, `healthcheck`, or both, especially for private-network/browser and host-exposure issues.

### Tasks

1. Add a concise decision table to `skills/README.md` and the root README.
2. Add cross-links between agent runtime findings and host hardening checks.
3. Add example combined report snippets for browser private-network exposure on a shared host.
4. Ensure healthcheck references do not duplicate agent-security rules unnecessarily.
5. Add tests or text checks for broken cross-links if references grow.

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
