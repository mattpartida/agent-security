# Healthcheck helper output

The `healthcheck` skill includes two dependency-light helpers for turning copied OpenClaw command output into stable summaries that can be used in PR comments, Discord updates, scheduled checks, or CI smoke jobs.

## Helpers

- `skills/healthcheck/scripts/summarize_openclaw_posture.py` parses `openclaw status --deep` style output.
- `skills/healthcheck/scripts/parse_openclaw_audit.py` parses `openclaw security audit --deep` style output.

Both helpers read from standard input and default to JSON:

```bash
openclaw security audit --deep \
  | python3 skills/healthcheck/scripts/parse_openclaw_audit.py

openclaw status --deep \
  | python3 skills/healthcheck/scripts/summarize_openclaw_posture.py
```

## JSON contract

Both scripts emit an additive compatibility shape:

- `ok` — `true` only when the parsed posture has no blocking attention items.
- `summary` — counts for `critical`, `warn`, and `info`.
- top-level `critical`, `warn`, and `info` — retained for older consumers.

`parse_openclaw_audit.py` also emits `items[]` with parsed severity/title pairs. `summarize_openclaw_posture.py` also emits `channel` and `update_available`.

## Markdown output

Use `--format markdown` for human-readable reports:

```bash
openclaw security audit --deep \
  | python3 skills/healthcheck/scripts/parse_openclaw_audit.py --format markdown

openclaw status --deep \
  | python3 skills/healthcheck/scripts/summarize_openclaw_posture.py --format markdown
```

Markdown output is intentionally compact: a status line, severity-count table, and any parsed audit findings.

## Strict mode

Use `--strict` when a scheduled check or CI smoke should fail on actionable posture issues:

```bash
openclaw security audit --deep \
  | python3 skills/healthcheck/scripts/parse_openclaw_audit.py --strict

openclaw status --deep \
  | python3 skills/healthcheck/scripts/summarize_openclaw_posture.py --strict
```

Strict audit mode exits non-zero when critical or warning audit items are present. Strict posture mode exits non-zero when critical/warning posture items are present or an OpenClaw update is available.

## Safety boundary

These helpers only parse text from standard input. They do not run OpenClaw commands, modify host settings, fetch network resources, or inspect credentials. State-changing host hardening still requires the approval workflow in `skills/healthcheck/SKILL.md`.
