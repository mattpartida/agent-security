# Prompt-injection detector quality

The prompt-injection scanner is a heuristic regression detector, not a security boundary. The fixture corpus in `tests/fixtures/prompt-injection/manifest.json` exists to keep known prompt-injection signals from silently regressing while making detector limits explicit. Use `skills/agent-security/scripts/summarize_prompt_injection_corpus.py` to produce JSON or Markdown inventory summaries from the manifest. Add `--strict` in CI or scheduled checks when the corpus summary should fail closed on critical manifest-contract issues. Add `--include-cases` when review artifacts need a stable per-fixture case inventory.

## Corpus contract

- Every malicious text fixture in the manifest sets `flagged: true` and lists at least one `expected_signals` value.
- Benign fixtures set `flagged: false` and keep `expected_signals` empty.
- Config fixtures list the expected exposure `severity` values and scoring `factors` for `score_prompt_injection_exposure.py`.
- Fixture file paths stay inside `tests/fixtures/prompt-injection/`; the manifest test rejects missing, duplicate, or unlisted fixtures.

## Covered attack shapes

Current fixtures cover direct instruction override, indirect webpage exfiltration, encoded/base64 instruction candidates, zero-width obfuscation, fake approvals plus memory poisoning, tool-output exfiltration, benign project/status prose, and high-risk agent config exposure.

## Known false positives

The scanner intentionally favors recall for untrusted content. Expected false positives include:

- security training text that quotes phrases such as “ignore previous instructions”;
- incident reports that mention tokens, secrets, or private network URLs as examples;
- documentation about raw HTML, YAML config, GitHub Actions, or other downstream execution contexts;
- benign admin runbooks that say approval was already granted.

Treat hits as review prompts. Do not automatically block trusted documentation without context.

## Known false negatives

Absence of a signal does not mean text is safe. Known false negatives include:

- novel paraphrases that avoid the scanner’s keyword windows;
- short or fragmented attacks split across multiple messages or tool outputs;
- encoded payloads that are not base64/hex or decode to compressed/binary content;
- multilingual or typo-heavy attacks;
- attacks that rely on model-specific social engineering rather than explicit tool or secret language.

Runtime controls still need allowlists, approval gates, sandboxing, and least-privilege tool access.

## When to add a fixture

Add or update a fixture when:

1. a real prompt-injection attempt, red-team case, or bypass pattern is discovered;
2. a detector pattern changes and could drop an existing signal;
3. a benign document triggers a noisy false positive worth pinning as a negative fixture;
4. a config-shape change affects exposure scoring;
5. a new attack category appears in the roadmap or security notes.

For malicious text fixtures, add the inert input file, add a manifest entry with `flagged: true`, and list the minimal stable `expected_signals`. For benign fixtures, add `flagged: false` with an empty expected-signal list. Keep payloads fake and non-operational; do not commit real secrets, live tokens, or working exploit infrastructure.

## Category decision table

Use this table when deciding whether a new fixture should extend an existing manifest `kind` or introduce a new category:

| Manifest `kind` | Use when the fixture primarily tests | Extend instead of splitting when |
| --- | --- | --- |
| `direct` | first-person or imperative instructions that tell the model to ignore, override, or replace trusted instructions | the payload is just a new wording of an instruction override or tool coercion |
| `indirect` | untrusted web/page/document content that tries to influence later agent behavior, network access, or secret handling | the key risk is still content crossing from retrieval/browser context into agent control |
| `encoded` | base64, hex, or similar encoded instruction candidates | the detector should recognize the encoding shape rather than a new social-engineering theme |
| `obfuscated` | zero-width, spacing, homoglyph, or punctuation tricks that hide known attack text | the same underlying attack would fit an existing category without obfuscation |
| `persistence` | fake approvals, memory poisoning, durable state writes, or future-turn triggers | the payload asks the agent to remember, schedule, or preserve untrusted instructions |
| `tool_output` | malicious text that arrives as command/tool/API output and attempts downstream tool use or exfiltration | the source is a tool transcript or API response, not a user/browser document |
| `benign` | negative fixtures for normal project notes, docs, status updates, or training text | the expected behavior is no prompt-injection signal |
| `config` | high-risk agent capability combinations for exposure scoring, not text-signal detection | the fixture is JSON/YAML-like agent configuration rather than prose |

Add a new `kind` only when a fixture would otherwise blur review ownership or require a new detector-quality section. Unknown kinds are warnings (`undocumented_case_kind`) in the corpus summary, not strict failures, so maintainers can land exploratory fixtures before promoting the category into documented guidance.
