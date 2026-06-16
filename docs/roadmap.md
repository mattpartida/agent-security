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

## Phase 9: Auditable baselines and suppressions

**Status:** Shipped
**Goal:** Let users adopt the scanner in existing repositories without hiding known findings or weakening default policy.

### Shipped scope

1. Added a `--baseline` flag for `config_risk_summary.py` that reads a dependency-light JSON baseline file.
2. Suppresses only exact, auditable matches by stable `rule_id` and exact evidence path set.
3. Preserves suppressed findings in machine-readable output under explicit `suppressed_findings` and `suppressed_summary` fields instead of deleting them silently.
4. Recomputes `ok`, `risk_count`, severity counts, strict mode, and `--fail-on` behavior from active unsuppressed findings.
5. Added [`docs/baselines.md`](baselines.md), [`examples/baselines/agent-security-baseline.json`](../examples/baselines/agent-security-baseline.json), README examples, and `tests/test_phase9_baselines.py`.

### Acceptance criteria

- A baseline entry for one evidence path does not suppress the same rule at a different path.
- JSON output separates active findings from suppressed findings and includes suppression metadata.
- Strict mode succeeds only when all high/critical findings are suppressed by exact baseline matches.

## Phase 10: Policy files and severity overrides

**Status:** Shipped
**Goal:** Support organization-specific rule policy while preserving stable default severities and auditability.

### Shipped scope

1. Added a `--policy` flag for dependency-light JSON policy files with validation for `severity_overrides`, `disabled_rules`, and exact evidence-path `allowlists`.
2. Kept default rule metadata unchanged when no policy is supplied; policy severity overrides are visible on findings as additive `policy.severity_override` metadata while SARIF rule metadata still reports default severity.
3. Reported policy-suppressed findings separately from baseline suppressions under `policy_suppressed_findings` and `policy_suppressed_summary`.
4. Documented policy precedence and safe review patterns in [`docs/policies.md`](policies.md), with an example at [`examples/policies/agent-security-policy.json`](../examples/policies/agent-security-policy.json).
5. Added `tests/test_phase10_policies.py` covering severity overrides, disabled-rule suppression, exact allowlist matching, invalid policy failures, docs/examples, and roadmap status.

### Acceptance criteria

- Invalid policy files fail before scanning with structured `invalid_policy` findings.
- Severity overrides are visible in output and do not mutate static rule metadata.
- Policy suppression is explicit and auditable.

## Phase 11: Baseline lifecycle tooling

**Status:** Shipped
**Goal:** Prevent suppressions from becoming permanent hidden risk.

### Shipped scope

1. Added `--generate-baseline` to emit current findings as a baseline skeleton with TODO owner, ticket, reason, and ISO expiry metadata.
2. Required lifecycle metadata (`owner`, `ticket`, `reason`, and `expires_at`) for baseline suppressions, failing closed with structured `invalid_baseline` findings when metadata is missing or malformed.
3. Added `baseline_lifecycle` JSON output with distinct `active`, `expired`, `stale`, and owner-grouped `owner_summary` sections.
4. Ensured expired entries do not suppress matching active findings, while stale non-expired entries are reported separately for cleanup.
5. Added cleanup fail flags `--fail-on-stale-baseline` and `--fail-on-expired-baseline`, plus [`docs/baseline-lifecycle.md`](baseline-lifecycle.md) and `tests/test_phase11_baseline_lifecycle.py`.

### Acceptance criteria

- Expired entries do not suppress active findings.
- Stale entries are reported when they no longer match active findings.
- Lifecycle fail flags only fail for their own condition.

## Phase 12: Schema adapter expansion and compatibility contract

**Status:** Shipped
**Goal:** Make scanner normalization explicit as support expands beyond current Hermes/OpenClaw-style shapes.

### Shipped scope

1. Reported the selected schema adapter in JSON (`schema.adapter`), Markdown, and SARIF run/result properties.
2. Added adapter-backed risky and safe fixtures for OpenAI-compatible tool arrays, Claude Desktop/MCP server configs, and GitHub Actions automation snippets under `examples/schema-adapters/`.
3. Documented unsupported/ignored fields and the non-executable trust boundary in `docs/schema-adapters.md`.
4. Added report stability guidance for `schema_version`, stable `ASG-###` rule IDs, canonical evidence paths, and URI-style path serialization.
5. Added cross-platform path serialization regression coverage for POSIX paths and Windows `PureWindowsPath` values.

### Acceptance criteria

- Every adapter fixture asserts adapter name, expected findings, and safe negative coverage in `tests/test_phase12_schema_adapters.py`.
- Unsupported fields are documented instead of guessed.
- Report path serialization remains stable across platforms.

## Phase 13: Healthcheck helper output and strict gates

**Status:** Shipped
**Goal:** Make the healthcheck helper scripts useful in scheduled checks, CI smoke jobs, PR comments, and Discord updates without requiring callers to scrape ad-hoc JSON.

### Shipped scope

1. Added `--format json|markdown` to `skills/healthcheck/scripts/parse_openclaw_audit.py` and `skills/healthcheck/scripts/summarize_openclaw_posture.py`, keeping JSON as the default.
2. Added `ok` and nested `summary` fields while preserving top-level `critical`, `warn`, and `info` counts for older consumers.
3. Added `--strict` exit-code behavior so audit/posture helper checks can fail scheduled jobs or CI smoke runs when actionable issues are present.
4. Added [`docs/healthcheck-helper-output.md`](healthcheck-helper-output.md) and README links for the reusable helper output contract.
5. Added `tests/test_phase13_healthcheck_outputs.py` covering JSON, Markdown, strict mode, docs, changelog, and roadmap status.

### Acceptance criteria

- Both healthcheck helper scripts emit stable JSON by default and compact Markdown with `--format markdown`.
- Strict mode exits non-zero only when the parsed posture requires attention.
- Documentation states that the helpers parse stdin only and do not modify host state.

## Phase 14: Prompt-injection corpus summary quality gates

**Status:** Shipped
**Goal:** Make prompt-injection fixture maintenance usable in CI and scheduled detector-quality checks without scraping ad-hoc output.

### Shipped scope

1. Added `ok`, `summary`, and `issues` fields to `skills/agent-security/scripts/summarize_prompt_injection_corpus.py` while keeping existing count fields stable.
2. Added `--strict` so critical manifest-contract issues fail closed for CI or scheduled corpus-quality gates.
3. Validated high-signal corpus contract issues such as flagged cases without expected signals, benign cases with expected signals, config cases without factors/severities, duplicate case files, and empty corpora.
4. Kept Markdown inventory output human-readable by adding critical and warning issue counts to the metrics table.
5. Updated README, skill usage notes, detector-quality docs, changelog, and corpus regression tests.

### Acceptance criteria

- JSON output preserves existing inventory fields and adds machine-readable `ok`, `summary`, and `issues` fields.
- `--strict` exits non-zero when critical corpus-contract issues are present and succeeds for the shipped manifest.
- Detector-quality documentation explains when to use strict corpus summary checks.

## Phase 15: Prompt-injection case inventory exports

**Status:** Shipped
**Goal:** Make corpus review packets useful for humans and machines without forcing reviewers to open the manifest manually.

### Shipped scope

1. Added `--include-cases` to `skills/agent-security/scripts/summarize_prompt_injection_corpus.py`.
2. Added stable JSON `cases` rows with `file`, `kind`, `classification`, and sorted `expected` fields.
3. Added a Markdown `Case inventory` table for copyable review artifacts.
4. Kept default summaries compact unless `--include-cases` is explicitly supplied.
5. Updated README, skill usage notes, detector-quality docs, changelog, and regression tests.

### Acceptance criteria

- JSON case inventory rows are sorted by fixture file for stable diffs.
- Markdown output includes a per-fixture table only when `--include-cases` is supplied.
- The default summary output remains backward-compatible and compact.

## Phase 16: Prompt-injection corpus category guidance

**Status:** Shipped
**Goal:** Add maintainer guidance for when to split a new prompt-injection fixture into a new category versus extending an existing category.

### Shipped scope

1. Added a category decision table to [`docs/prompt-injection-detector-quality.md`](prompt-injection-detector-quality.md) covering the documented manifest `kind` values.
2. Added non-fatal `undocumented_case_kind` warnings to `skills/agent-security/scripts/summarize_prompt_injection_corpus.py` when fixtures use unknown category names.
3. Kept unknown kinds as warnings, even under `--strict`, so exploratory fixtures can land before maintainers promote the category into documented guidance.
4. Added regression coverage for unknown-kind warnings, docs guidance, and roadmap status in `tests/test_prompt_injection_fixture_corpus.py`.

### Acceptance criteria

- Detector-quality docs explain when to split versus extend prompt-injection categories.
- Corpus summaries warn on unknown or undocumented fixture `kind` values.
- Unknown kinds remain non-fatal unless a future strict policy promotes them.

## Phase 17: Prompt-injection corpus review packet exports

**Status:** Shipped
**Goal:** Let maintainers generate copyable, paired JSON and Markdown review packets for corpus audits without manually redirecting multiple commands or mutating fixture state.

### Shipped scope

1. Added `--output-dir` to `skills/agent-security/scripts/summarize_prompt_injection_corpus.py` to write `prompt-injection-corpus-summary.json` and `prompt-injection-corpus-summary.md` together.
2. Preserved stdout behavior while adding machine-readable `artifact_paths`, `writes_to_manifest: false`, and `writes_to_fixtures: false` guardrails to packet-enabled runs.
3. Reused `--include-cases` so generated packets can include stable per-fixture inventory rows for reviewer handoff.
4. Updated README, skill usage notes, changelog, and regression tests for the review-packet workflow.

### Acceptance criteria

- `--output-dir` creates deterministic JSON and Markdown artifact names in the requested directory.
- Packet generation reports artifact paths and explicit no-mutation guardrails.
- The JSON packet matches stdout summary content, and the Markdown packet includes the case inventory when requested.

## Implementation order

1. Finish or merge PRs that already cover roadmap work before starting duplicate branches.
2. Ship Phase 1 and Phase 2 together only if the diff stays small; otherwise do markdown/SARIF first, then evidence paths.
3. Expand Phase 3 as new prompt-injection bypasses are found.
4. Use Phases 4 and 5 to prevent schema and rule drift after output formats stabilize.
5. Treat Phases 6 through 8 as repo credibility and adoption polish once scanner outputs are stable.
6. Treat Phases 9 through 12 as adoption-at-scale work: baselines first, then policy, lifecycle cleanup, and broader schema adapters.
7. Treat Phases 14 through 17 as prompt-corpus maintenance polish: strict gates, review inventories, category guidance, and export packets.

## Verification checklist for roadmap changes

For docs-only roadmap edits:

```bash
python -m compileall -q skills tests
python -m pytest -q
ruff check .
./package-skills.sh
```

For implementation phases, also run the most focused touched test file first, then the full checklist above.
