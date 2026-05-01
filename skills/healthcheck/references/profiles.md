# Risk Profiles

## How to use this file

Read this only after system context is known. Use it to map the machine and OpenClaw deployment to a target posture.

## Deployment decision tree

1. Local workstation or laptop
   - Prioritize usability, backups, disk encryption, automatic updates, and limiting remote exposure.
   - Prefer loopback-only Control UI and LAN or tailnet-only remote access.

2. Dedicated local always-on machine
   - Prioritize least privilege, minimal open ports, automatic updates, and clear service inventory.
   - Prefer firewall-on defaults and narrow remote-access paths.

3. Internet-exposed VPS or remote host
   - Prioritize deny-by-default inbound rules, minimal services, hardened SSH, automatic security updates, and rollback planning.
   - Be extra careful with remote lockout risk.

4. Shared or multi-user bot runtime
   - Prioritize trust-boundary separation over convenience.
   - Prefer separate gateways, separate OS users/hosts, sandbox mode for all sessions, workspace-only file access, and denying unnecessary runtime/fs/web tools.

## Suggested profiles

### 1. Home or Workstation Balanced
- Firewall on with reasonable defaults.
- Remote access restricted to LAN or tailnet when possible.
- Disk encryption on.
- Automatic security updates on.
- Browser and web tools allowed only when needed.
- OpenClaw Control UI kept local-only unless explicitly required.

### 2. VPS Hardened
- Deny-by-default inbound firewall.
- Minimal open ports.
- Key-only SSH.
- No root login.
- Automatic security updates on.
- Clear rollback path before any network-policy changes.
- Prefer service accounts and least privilege.

### 3. Developer Convenience
- More local services may remain open.
- Explicitly call out exposure tradeoffs.
- Keep audits frequent.
- Prefer reversible changes and documented exceptions.

### 4. Custom Constraints
Capture:
- required services and ports
- access method
- update cadence
- backup expectations
- whether this runtime is personal or shared

## Agent-security overlays

Apply these regardless of host profile when OpenClaw is in scope.

### Personal single-user assistant
- Tight allowlists for elevated actions and exec approvals.
- Keep private credentials and memory only on trusted machines.
- Prefer top-tier models for inboxes and tools.

### Shared/group-chat assistant
- Treat this as a different risk class from a personal assistant.
- Prefer sandbox mode for all sessions.
- Keep tools.fs.workspaceOnly=true.
- Deny runtime, fs, browser, and broad web tools unless explicitly needed.
- Avoid exposing personal memory or credentials to that runtime.

### Local/small-model fallback enabled
- Treat small models as higher risk for prompt injection and tool misuse.
- Prefer sandboxing for all sessions.
- Disable browser/web tools for those runtimes unless there is a strong reason not to.
