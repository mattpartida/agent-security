# Config shape compatibility

`config_risk_summary.py` and `score_prompt_injection_exposure.py` use a small canonical JSON shape, but real agent runtimes often expose nearby aliases. Phase 4 keeps those scripts dependency-light while making common Hermes/OpenClaw-style configs testable.

## Canonical fields

Prefer these fields when adapting your own config/status JSON:

- `tools.exec.enabled` or `tools.exec.security` for shell/runtime execution.
- `tools.elevated.enabled` plus `tools.elevated.allowFrom` for privileged actions.
- `tools.fs.workspaceOnly` for filesystem scope.
- `browser.enabled` and `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` for browser/network posture.
- `channels.discord.enabled`, `channels.discord.groupPolicy`, and `channels.discord.execApprovals` for Discord exposure.
- `bindings[].match.channel` plus `bindings[].match.peer.kind` for shared-channel bindings.
- `agents.defaults.model`, `agents.defaults.model.fallbacks`, and `agents.list[].model` for model-risk checks.
- `memory.enabled`, `cron.enabled`, `tools.memory.enabled`, `tools.cron.enabled`, or `notes.enabled` for persistence surfaces.

## Aliases and best-effort compatibility

The scripts currently normalize these aliases before scanning:

- `enabled_toolsets` or `toolsets` entries such as `terminal`, `shell`, `exec`, or `code_execution` imply `tools.exec.enabled`.
- `enabled_toolsets` entries such as `browser`, `web`, or `web_browser` imply `browser.enabled`.
- `enabled_toolsets` entries such as `memory` or `cron` imply the matching persistence tools.
- Root-level `model` maps to `agents.defaults.model` when the canonical field is absent.
- `platforms.discord` maps to `channels.discord`; `group_policy` maps to `groupPolicy`; `exec_approvals` maps to `execApprovals`.
- `browser.allowPrivateNetwork`, `browser.privateNetworkAccess`, or `browser.dangerouslyAllowPrivateNetwork` map to `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`.

Canonical fields win over aliases. Unknown future sections are ignored unless fixture-backed tests define their meaning.

## Fixture coverage

Every JSON file in `examples/config-shapes/` is exercised by both config scripts:

- `personal-local.json` — root model plus Hermes-like `enabled_toolsets` aliases.
- `discord-shared.json` — shared Discord channel via `platforms.discord` aliases.
- `browser-agent.json` — private-network browser alias with a shared binding.
- `cron-memory-agent.json` — persistence reachable from an untrusted Discord context.
- `ci-only-scanner.json` — read-only CI scanner config that should not create runtime-tool risk findings.
- `malformed-safe.json` — wrong-type optional sections that should return structured findings instead of tracebacks.

When adding a new config shape, add a durable example fixture and update `tests/test_config_shape_coverage.py` with the expected config-risk findings and exposure factors.
