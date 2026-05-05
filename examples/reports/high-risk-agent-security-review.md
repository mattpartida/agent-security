# Example Agent Security Review: High-Risk Shared Agent

This is a sample report for `examples/high-risk-agent-config.json`. It demonstrates the expected shape and level of detail for an agent-security review. The example config is intentionally unsafe test data.

## Executive summary

- **Overall posture:** Critical
- **Highest-risk issue:** Shared Discord/channel runtime can combine private-network browser access, unrestricted exec, broad filesystem access, elevated tools, and persistence.
- **Trust boundary:** Mixed/shared channel with untrusted or semi-trusted content.
- **Recommended next action:** Disable private-network browser access and full exec for the shared runtime, then split untrusted-content handling from privileged/local credentials.

## Findings

| Severity | Rule | Area | Evidence | Risk | Recommendation |
| --- | --- | --- | --- | --- | --- |
| Critical | ASG-006 | Browser / channel binding | Shared Discord channel binding plus `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork=true` | A malicious webpage, chat message, or tool result could steer the browser toward localhost or private-network services. | Disable private-network browsing for shared agents or move browser work to an isolated runtime. |
| High | ASG-001 | Runtime execution | Shared channel binding plus exec surface | Shared-channel content can influence shell/runtime actions. | Remove exec from shared-channel agents or require strict sender-specific approvals and sandboxing. |
| High | ASG-004 | Elevated tools | Elevated tools enabled without a narrow allowlist | Privileged actions may be reachable from a broad or ambiguous approval surface. | Disable elevated tools or configure explicit sender/resource allowlists. |
| High | ASG-008 | Exec policy | `tools.exec.security=full` | Commands can run without sufficient containment or review. | Use approval-gated and sandboxed execution; avoid full exec for shared agents. |
| Warn | ASG-003 | Persistence | Memory/cron/notes persistence reachable in a context with untrusted content | Prompt injection can become cross-turn or delayed. | Require review before memory/cron writes sourced from web, documents, email, or group chat. |

## Immediate risks

- Private-network/SSRF exposure from browser tools.
- Confused-deputy path from shared chat or remote content to shell/runtime tools.
- Persistent prompt injection through memory, notes, summaries, skills, config, or cron.
- Ambiguous approval authority if group participants can influence approval text.

## Reversible config hardening

- **Field:** `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork`
  - **Current:** `true`
  - **Recommended:** `false`
  - **Effect:** Blocks browser access to localhost/RFC1918/private network targets.
  - **Rollback:** Re-enable only for a dedicated, isolated internal-network agent.
  - **Restart required:** Usually yes, depending on runtime config reload behavior.

- **Field:** `tools.exec.security`
  - **Current:** `full`
  - **Recommended:** `approval` or sandboxed execution; remove from shared agents where possible.
  - **Effect:** Prevents unreviewed command execution.
  - **Rollback:** Restore previous setting only after documenting the trusted-user boundary.
  - **Restart required:** Usually yes.

- **Field:** `tools.elevated.allowFrom`
  - **Current:** missing or broad
  - **Recommended:** explicit sender-specific approvers only.
  - **Effect:** Prevents channel-wide or spoofable privileged action.
  - **Rollback:** Remove elevated tools rather than broadening allowlists.
  - **Restart required:** Usually yes.

## Prompt-injection paths

- **Source:** Webpage or search result
  - **Path:** browser result -> model -> browser/private-network request or shell tool
  - **Possible impact:** SSRF, local service exposure, command execution, credential discovery
  - **Containment:** Disable private-network browser access and require approval before shell/runtime use.

- **Source:** Discord/group chat content
  - **Path:** chat message -> model -> exec/elevated/persistence tool
  - **Possible impact:** unauthorized commands, social-engineered approvals, persistent memory poisoning
  - **Containment:** Sender-specific approvers, minimal shared-agent tools, no blind persistence.

- **Source:** Tool output
  - **Path:** shell/browser/MCP output -> model -> outbound message or config change
  - **Possible impact:** exfiltration or security weakening by following tool-output instructions
  - **Containment:** Treat tool output as data, inspect before action, require outbound/config-change approvals.

## Structural recommendations

1. Split shared channel agents from personal/private-data agents.
2. Keep browser/web research agents read-only by default.
3. Put outbound actions, repo writes, email, deploys, and config edits behind explicit confirmation gates.
4. Store prompt-injection probes as regression tests whenever a new exploit path is found.

## Deferred items / unknowns

- Whether actual sender identity checks are enforced by the gateway.
- Whether filesystem access is workspace-only at runtime.
- Whether secrets are available in environment variables or local dotfiles.
- Whether logs redact prompts, tool inputs, and credentials.

## Verification performed

For this example report:

```bash
python3 skills/agent-security/scripts/config_risk_summary.py \
  < examples/high-risk-agent-config.json
python3 skills/agent-security/scripts/score_prompt_injection_exposure.py \
  < examples/high-risk-agent-config.json
```

Expected result: high/critical findings with stable `ASG-###` rule IDs.
