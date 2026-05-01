#!/usr/bin/env python3
import json
import sys

cfg = json.load(sys.stdin)
risks = []

agents = cfg.get('agents', {}).get('list', [])
default_fallbacks = cfg.get('agents', {}).get('defaults', {}).get('model', {}).get('fallbacks', []) or []
small_model_markers = ['haiku', '8b', '70b', 'mistral', 'gemma', 'llama', 'ollama']

def add(severity, risk, **extra):
    item = {'severity': severity, 'risk': risk}
    item.update(extra)
    risks.append(item)

if cfg.get('tools', {}).get('exec', {}).get('security') == 'full':
    add('warn', 'exec_security_full')

if cfg.get('browser', {}).get('ssrfPolicy', {}).get('dangerouslyAllowPrivateNetwork') is True:
    add('warn', 'browser_private_network_allowed')

if not cfg.get('commands', {}).get('ownerAllowFrom'):
    add('warn', 'missing_owner_allow_from')

if not cfg.get('tools', {}).get('elevated', {}).get('allowFrom'):
    add('warn', 'missing_global_elevated_allowlist')

if any(any(marker in model.lower() for marker in small_model_markers) for model in default_fallbacks):
    add('warn', 'small_model_fallbacks_present', models=default_fallbacks)

if cfg.get('channels', {}).get('discord', {}).get('groupPolicy') == 'allowlist':
    add('info', 'discord_group_chat_enabled')

exec_approvals = cfg.get('channels', {}).get('discord', {}).get('execApprovals', {})
if not exec_approvals:
    add('warn', 'discord_exec_approvals_missing')
elif exec_approvals.get('enabled') and not exec_approvals.get('approvers'):
    add('warn', 'discord_exec_approvals_enabled_without_approvers')

for agent in agents:
    aid = agent.get('id', 'unknown')
    elevated = agent.get('tools', {}).get('elevated', {})
    if elevated.get('enabled') and not elevated.get('allowFrom'):
        add('warn', 'agent_elevated_without_allowlist', agent=aid)

bindings = cfg.get('bindings', []) or []
for b in bindings:
    match = b.get('match', {})
    if match.get('channel') == 'discord' and match.get('peer', {}).get('kind') == 'channel':
        add('info', 'discord_channel_binding', agent=b.get('agentId'))

summary = {
    'risk_count': len(risks),
    'risks': risks
}

print(json.dumps(summary, indent=2, sort_keys=True))
