# Combined browser private-network boundary review

This snippet shows how to report a case that needs both `agent-security` and `healthcheck` without duplicating findings.

## Scenario

A shared Discord agent runs on an internet-facing VPS. The agent has browser access with private-network requests allowed, and the host also exposes local admin or service ports that could be reached from the runtime.

## Ownership split

| Area | Owner | Why |
| --- | --- | --- |
| Private-network browser access | `agent-security` | The risky capability is inside the agent runtime and maps to `ASG-002`. |
| Shared channel plus private-network browser access | `agent-security` | The trust-boundary combination maps to `ASG-006`. |
| Host network exposure | `healthcheck` | Firewall, bind addresses, SSH, and exposed services are host controls. |
| Rollback and access preservation | `healthcheck` | Firewall and SSH changes can lock out operators and need a host rollback path. |

## Agent-security findings

- `ASG-002` — Private-network browser access is enabled. Disable private-network browser access unless the agent is isolated from shared or untrusted channels.
- `ASG-006` — Shared channel binding combines with private-network browser access. Split the runtime or disable browser private-network access for the shared profile.
- Review approval boundaries for browser, filesystem, shell, and persistence before allowing untrusted group-chat content to influence tools.

## Healthcheck findings

- Host network exposure should be reviewed separately: listening services, firewall rules, bind addresses, SSH posture, update status, backups, and rollback.
- Do not treat the `ASG-###` runtime findings as firewall findings. Instead, use them as impact context for host hardening priority.
- Confirm any firewall or SSH remediation preserves operator access and has a rollback path.

## Recommended order

1. Reduce agent blast radius first: disable private-network browser access for shared profiles or separate the shared agent from private-data/browser-capable runtimes.
2. Then run a host `healthcheck` review for exposed services, SSH, firewall, update posture, backups, and rollback.
3. Re-run `agent-security` config scanning and host checks after changes.

## Report wording

> This is a combined boundary issue. `agent-security` owns the private-network browser and shared-channel runtime findings (`ASG-002`, `ASG-006`). `healthcheck` owns host network exposure and rollback. Fix the runtime trust-boundary issue first, then harden exposed host services with an access-preserving rollback plan.
