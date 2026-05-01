#!/usr/bin/env python3
import json
import sys

cfg = json.load(sys.stdin)
score = 0
factors = []

def add(points, name):
    global score
    score += points
    factors.append({'points': points, 'factor': name})

channels = cfg.get('channels', {})
if channels.get('discord', {}).get('enabled'):
    add(1, 'discord_enabled')
    if channels.get('discord', {}).get('groupPolicy') in ('allowlist', 'all'):
        add(2, 'discord_group_chat_surface')

if cfg.get('browser', {}).get('enabled'):
    add(2, 'browser_enabled')
if cfg.get('browser', {}).get('ssrfPolicy', {}).get('dangerouslyAllowPrivateNetwork') is True:
    add(3, 'browser_private_network_allowed')

web = cfg.get('tools', {}).get('web', {})
if web.get('search', {}).get('enabled'):
    add(1, 'web_search_enabled')
if web.get('fetch', {}).get('enabled'):
    add(2, 'web_fetch_enabled')

fallbacks = cfg.get('agents', {}).get('defaults', {}).get('model', {}).get('fallbacks', []) or []
markers = ['haiku', '8b', '70b', 'mistral', 'gemma', 'llama', 'ollama']
if any(any(m in model.lower() for m in markers) for model in fallbacks):
    add(2, 'small_model_fallbacks_present')

if cfg.get('tools', {}).get('exec', {}).get('security') == 'full':
    add(2, 'exec_security_full')

if cfg.get('tools', {}).get('elevated', {}).get('enabled'):
    add(1, 'elevated_enabled')

severity = 'low'
if score >= 10:
    severity = 'high'
elif score >= 5:
    severity = 'medium'

print(json.dumps({'score': score, 'severity': severity, 'factors': factors}, indent=2))
