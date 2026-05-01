# OpenClaw Security Skills

Security-focused AgentSkills for OpenClaw.

This repo packages two complementary skills:

- **healthcheck**
  - Host hardening and OpenClaw deployment review
  - Covers OS posture, exposure, updates, backups, and OpenClaw-specific hardening touchpoints
- **agent-security**
  - Agent/runtime security review
  - Covers approvals, allowlists, sandboxing, tool exposure, prompt injection, and trust boundaries

## Included skills

### `healthcheck`
Use for:
- host hardening reviews
- OpenClaw deployment posture checks
- firewall, SSH, update, exposure, and rollback planning
- OpenClaw configuration review when it intersects with host risk

### `agent-security`
Use for:
- runtime and approval-surface reviews
- prompt-injection risk analysis
- browser/web/tool exposure review
- sandboxing and small-model risk
- personal vs shared runtime trust-boundary analysis

## Repository layout

```text
skills/
  healthcheck/
  agent-security/
dist/
  healthcheck.skill
  agent-security.skill
```

## Packaging

Rebuild distributable archives with:

```bash
./package-skills.sh
```

This writes packaged `.skill` archives into `dist/`.

## Notes

- These skills are designed for OpenClaw-style AgentSkills.
- They include helper scripts and reference material for progressive disclosure.
- The skills are intentionally split so host security and agent/runtime security can evolve independently.

## License

MIT
