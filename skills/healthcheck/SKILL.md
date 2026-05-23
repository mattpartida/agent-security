---
name: healthcheck
description: Audit and harden hosts running OpenClaw for SSH, firewall, updates, exposed services, backups, OS posture, system scheduling, rollback, and network risk. Use alongside agent-security when host exposure and agent runtime permissions interact.
---

# OpenClaw Security and Host Hardening

Read only what you need:
- `references/os-checks.md` for host command packs
- `references/profiles.md` for deployment profiles and trust-boundary choices
- `references/openclaw-hardening.md` for OpenClaw-specific hardening
- [`../../docs/skill-boundary.md`](../../docs/skill-boundary.md) for deciding when to use `healthcheck`, `agent-security`, or both

When a host review touches agent runtime findings, cite `agent-security` for runtime rule IDs. Do not duplicate `ASG-###` ownership in this skill; use those findings as impact context while `healthcheck` owns host network exposure, SSH, firewall, backups, system scheduling, and rollback.

## Core rules

- Recommend a top-tier model for security-sensitive work, but do not block execution.
- Require explicit approval before any state-changing action.
- Separate host hardening from OpenClaw hardening.
- Never imply OpenClaw itself changes host firewall, SSH, or OS update policy.
- Do not modify remote-access settings without confirming the access path.
- Prefer reversible, staged changes with a rollback plan.
- If identity, role, or trust boundary is unclear, stay read-only and provide recommendations.
- Number user choices so the user can reply with a single digit.

## Threat-model first

Classify the machine:
1. local workstation or laptop
2. dedicated local always-on machine
3. internet-exposed VPS or remote host
4. shared or multi-user bot runtime

Classify OpenClaw usage:
1. personal single-user assistant
2. shared or group-chat assistant
3. mixed or unclear trust boundary

If the runtime is shared or unclear, treat it as higher risk and emphasize sandboxing, minimal tools, and separation of personal credentials or memory.

## Workflow

### 0) Model self-check
Check the current model. If it is below current top-tier tool-use standards, recommend switching.

### 1) Read-only context gathering
Ask once for permission to run read-only checks. Infer what you can before asking follow-up questions.

Determine:
1. OS and version, and whether this is host, container, or app-managed local runtime
2. privilege level
3. access path
4. network exposure
5. OpenClaw gateway status, bind mode, channel exposure, and update status
6. backups, disk encryption, and OS automatic security updates
7. whether the OpenClaw runtime is personal, shared, or mixed

Read `references/os-checks.md` only if you need concrete host commands.

### 2) OpenClaw-specific read-only review
Always treat OpenClaw security as its own workstream.

Run by default:
- `openclaw status --deep`
- `openclaw security audit --deep`
- `openclaw update status`

Then inspect relevant config areas before recommending changes. Read `references/openclaw-hardening.md` if needed.

Pay special attention to:
- elevated permissions
- exec approval paths
- sender vs channel allowlists
- sandbox mode
- tool exposure, especially browser and web
- small or local model fallbacks with tools
- shared or group-chat trust boundaries

### 3) Determine target posture
After context is known, ask the user to choose or confirm a target posture. Read `references/profiles.md` if needed.

Suggested profiles:
1. Home or Workstation Balanced
2. VPS Hardened
3. Developer Convenience
4. Custom Constraints

### 4) Produce a remediation plan
Always show the plan before making changes.

Include:
- target profile
- current posture summary
- host-security findings
- OpenClaw-security findings
- gaps vs target
- exact commands or config edits
- rollback path
- lockout or trust-boundary risks

Group recommendations into:
1. read-only findings
2. reversible OpenClaw config changes
3. higher-risk host or network changes

### 5) Execute carefully
For each state-changing step:
- show the exact command or config edit
- explain impact
- explain rollback
- confirm access preservation when relevant
- stop on unexpected output

### 6) Verify and report
Re-check the changed surface, then summarize:
- what was verified
- what changed
- what remains deferred
- whether periodic audits should be scheduled

## Required confirmations

Always require explicit approval for:
- firewall changes
- opening or closing ports
- SSH or RDP changes
- package installs or removals
- enabling or disabling services
- user or group changes
- scheduled tasks or startup persistence
- update policy changes
- access to sensitive credentials
- broadening elevated permissions or approver scope

## Periodic checks
After any audit or hardening pass, offer scheduling explicitly:
1. schedule periodic security audits
2. schedule periodic update-status checks
3. do not schedule anything

Use stable job names:
- `healthcheck:security-audit`
- `healthcheck:update-status`

## Command accuracy
Use only supported OpenClaw commands and flags:
- `openclaw security audit [--deep] [--fix] [--json]`
- `openclaw status` or `openclaw status --deep`
- `openclaw health --json`
- `openclaw update status`
- `openclaw cron add|list|runs|run`

## Reusable helpers
- `scripts/summarize_openclaw_posture.py` for compact posture summaries
- `scripts/parse_openclaw_audit.py` for compact audit summaries
