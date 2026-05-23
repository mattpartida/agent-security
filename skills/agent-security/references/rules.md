# Agent Security Rule Reference

Stable rule IDs are emitted by `scripts/config_risk_summary.py` when a finding maps to a documented agent-security risk. IDs are intended for CI baselines, issue tracking, reports, and future SARIF/code-scanning output.

## Rule index

| Rule | Risk key | Severity | What it flags | Preferred mitigation |
| --- | --- | ---: | --- | --- |
| ASG-001 | `shared_channel_with_exec_surface` | High | A shared Discord/channel binding can reach shell/runtime execution. | Separate shared agents from exec tools, or require strict sender-specific approvals and sandboxing. |
| ASG-002 | `browser_private_network_allowed` | High | Browser SSRF policy allows localhost/RFC1918/private-network access. | Disable private-network browser access unless explicitly required and isolated. |
| ASG-003 | `persistence_available_in_untrusted_content_context` | Warn | Memory, cron, notes, or similar persistence is available where untrusted content may be present. | Require human review before persistence and isolate untrusted-content workflows. |
| ASG-004 | `elevated_enabled_without_allowlist`, `agent_elevated_without_allowlist` | High | Elevated tools are enabled without a specific sender/resource allowlist. | Add narrow sender-specific allowlists or disable elevated tools. |
| ASG-005 | `risky_default_model`, `risky_agent_model_with_tools` | Warn | Small, local, cheap, custom, or unknown models are combined with defaults or tool-enabled agents. | Use stronger models for high-risk tools, remove risky fallbacks, or narrow/sandbox tools. |
| ASG-006 | `shared_channel_with_private_network_browser` | Critical | Shared channel binding combines with private-network browser access. | Split the runtime or disable private-network browsing for shared agents. |
| ASG-007 | `shared_channel_with_elevated_surface` | High | Shared channel binding can reach elevated tools. | Separate shared runtimes from elevated tools and use explicit sender approvals. |
| ASG-008 | `exec_security_full` | High | Shell/runtime execution is configured as full/unrestricted. | Use approval-gated or sandboxed execution, preferably workspace-scoped. |
| ASG-009 | `discord_exec_approvals_enabled_without_approvers` | High | Discord exec approvals are enabled without explicit approvers. | Configure explicit approvers by sender identity. |
| ASG-010 | `discord_exec_approvals_missing` | Warn | Discord is enabled with exec surface but no exec approval config was found. | Add clear exec approval policy or remove exec from Discord-bound agents. |
| ASG-011 | `filesystem_not_workspace_only` | Warn | Filesystem access is broader than workspace-only. | Prefer workspace-only file access for project and shared agents. |
| ASG-012 | `sandbox_disabled` | Warn | Sandbox config is present and explicitly disabled. | Enable sandboxing for runtime, browser, and filesystem access where available. |
| ASG-013 | `exec_or_commands_without_owner_allow_from` | Warn | Exec/command surface exists without owner approver config. | Configure owner/sender-specific approval sources. |
| ASG-014 | `discord_group_chat_surface` | Info | Discord group/channel surface is enabled. | Treat group content as untrusted and tighten tools/approvals. |
| ASG-015 | `discord_channel_binding` | Info | An agent is bound to a Discord channel peer. | Confirm the channel trust boundary and avoid ambient private credentials. |

## Evidence paths and source locations

Every `ASG-###` finding emitted by `scripts/config_risk_summary.py` includes at
least one `evidence_paths` entry that points to the config/status field that
caused the finding. Paths use dot notation for nested objects and zero-based
array indexes for list entries, for example:

- `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`
- `bindings[0].match.channel`
- `agents.list[0].tools.elevated.allowFrom`

Composite findings include all contributing fields, not just the final combined
risk. For example, `ASG-006` combines a shared Discord channel binding path with
the private-network browser path.

Machine-readable JSON and SARIF outputs also include `source_locations` entries
with each evidence path and an approximate one-based line number. The resolver is
best-effort and dependency-light: it scans the original input text for
JSON/YAML/TOML-like key names in path order. If a path cannot be resolved, such
as a missing allowlist field that triggered a finding, the line falls back to
`1` so downstream tools still receive a valid location. SARIF results choose the
lowest resolved evidence line as `locations[].physicalLocation.region.startLine`
and copy all paths into `properties.evidence_paths`.

## Severity guidance

- **Critical** — dangerous cross-boundary combination likely to enable private-network access, exfiltration, or privileged action from a shared/untrusted surface.
- **High** — high-impact tool, approval, or isolation weakness that should be fixed before production/shared use.
- **Warn** — meaningful hardening gap or risky combination that may be acceptable only with compensating controls.
- **Info** — context that helps classify trust boundaries and review scope.

## Adding new rules

When adding a rule:

1. choose the next unused `ASG-###` ID;
2. emit `rule_id` from `config_risk_summary.py`;
3. add or update a representative test;
4. document severity, risk key, exploit path, and mitigation here;
5. keep the ID stable after release.
