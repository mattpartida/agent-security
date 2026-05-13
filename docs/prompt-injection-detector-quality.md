# Prompt-injection detector quality

The prompt-injection scanner is a heuristic regression detector, not a security boundary. The fixture corpus in `tests/fixtures/prompt-injection/manifest.json` exists to keep known prompt-injection signals from silently regressing while making detector limits explicit.

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
