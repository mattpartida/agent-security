# Skill Boundary: agent-security vs healthcheck

Use this guide when a review touches both agent runtime controls and host or network hardening. The goal is clear ownership without duplicate findings or conflicting mitigation language.

## Ownership model

| Surface | Primary owner | Use the other skill when |
| --- | --- | --- |
| Agent runtime / tool permissions | `agent-security` | Host exposure changes the blast radius of the runtime. |
| Prompt injection and untrusted content | `agent-security` | Untrusted content can reach host services or credentials through network exposure. |
| Browser, web, SSRF, and private-network policy | `agent-security` owns browser policy | The host exposes private services, metadata endpoints, or admin panels reachable from the browser runtime. |
| Host OS / network exposure | `healthcheck` | Agent tools, browser, cron, memory, or approvals can reach those exposed services. |
| SSH, firewall, package updates, disk encryption, backups | `healthcheck` | Agent runtime changes need rollback or approval planning. |
| Combined shared-runtime risk | Use both | A shared or group-chat agent can trigger browser, shell, or host-reaching actions. |

## Shared-concept ownership

| Shared concept | `agent-security` owns | `healthcheck` owns | Avoid duplicating |
| --- | --- | --- | --- |
| SSRF | agent-security owns browser policy, private-network exceptions, URL-fetching tools, and `ASG-002` / `ASG-006` runtime findings. | healthcheck owns listening services, cloud metadata exposure, local admin panels, and network segmentation. | Do not restate `ASG-###` rule findings as host findings. Link to the agent finding and add host impact. |
| exposed services | agent-security owns whether agent tools can reach or call them. | healthcheck owns listening services, firewall policy, bind addresses, TLS, and authentication. | Do not claim OpenClaw changes host firewall settings; recommend a host hardening plan instead. |
| cron | agent-security owns agent scheduled jobs, memory-to-cron persistence, and delayed tool execution. | healthcheck owns system cron, launchd/systemd timers, audit cadence, and host update schedules. | Separate agent-scheduled actions from OS scheduling. |
| rollback | agent-security owns rollback of agent config, tool allowlists, prompts, and approval policy. | healthcheck owns host rollback, firewall rollback, SSH access preservation, backups, and recovery paths. | Do not mix reversible agent config edits with lockout-prone host changes. |

## Cross-skill handoff rules

1. Start with `agent-security` when the main question is whether an agent can perform a risky action: shell, browser, filesystem, outbound messaging, persistence, approvals, or prompt injection.
2. Start with `healthcheck` when the main question is whether the host is safely exposed: firewall, SSH, OS updates, disk encryption, backups, exposed ports, or rollback.
3. Use both when agent reachability and host exposure multiply each other, especially browser private-network access on a shared host or internet-facing VPS.
4. Keep rule IDs in one place: `agent-security` emits and documents `ASG-###` runtime findings; `healthcheck` should reference those IDs instead of creating duplicate host-language copies.
5. Keep mitigation language scoped: agent mitigations should mention tool restrictions, approvals, browser policy, sandboxing, and separation; host mitigations should mention firewall, bind address, SSH, OS updates, backups, network segmentation, and rollback.

## Combined-review example

When a shared Discord agent has private-network browser access on an internet-facing VPS:

- `agent-security` reports the runtime issue: shared channel plus private-network browser access (`ASG-002` / `ASG-006`), approval gaps, and trust-boundary separation.
- `healthcheck` reports the host issue: exposed services, firewall rules, SSH posture, update posture, and whether rollback preserves access.
- The final recommendation should show both tracks side by side: disable private-network browser access or split the shared agent first, then reduce host exposure and verify firewall/SSH rollback.

See [`../examples/reports/combined-browser-private-network-boundary.md`](../examples/reports/combined-browser-private-network-boundary.md) for a copyable report snippet.

## Non-duplication rules

- `healthcheck` may cite `ASG-###` findings for context, but it should not define, own, or re-score those rules.
- `agent-security` may note that host exposure increases impact, but it should not prescribe firewall or SSH changes without handing off to `healthcheck`.
- If the same concept appears in both skills, name the owner and the reason it appears in the other skill.
- If mitigation wording conflicts, prefer the ownership table above and update the skill that drifted.
