# Skills

This directory contains the security-focused OpenClaw skills in this repo.

- `healthcheck/` for host and deployment hardening
- `agent-security/` for runtime, approvals, prompt-injection, and trust-boundary security

## Which skill should I use?

| Situation | Use | Why |
| --- | --- | --- |
| Agent runtime / tool permissions, approvals, browser policy, prompt injection, filesystem scope, memory, or shared-channel trust boundaries | `agent-security` | These risks live inside the agent runtime and map to `ASG-###` findings. |
| Host OS / network exposure, SSH, firewall, updates, backups, disk encryption, exposed services, or rollback | `healthcheck` | These are host hardening and access-preservation controls. |
| Use both: browser private-network / SSRF risk on a shared or internet-facing host | `agent-security` + `healthcheck` | `agent-security` owns browser private-network policy and SSRF runtime findings; `healthcheck` owns exposed services and host network exposure. |
| Use both: cron or scheduled automation can run agent tools on a host with rollback requirements | `agent-security` + `healthcheck` | `agent-security` owns agent cron, persistence, and tool execution; `healthcheck` owns system cron, backups, and rollback. |

See [`../docs/skill-boundary.md`](../docs/skill-boundary.md) for the ownership model, cross-skill handoff rules, and non-duplication guidance.
