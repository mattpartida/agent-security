# Schema adapter compatibility

Phase 12 makes config normalization explicit instead of silently guessing at every possible runtime shape. `config_risk_summary.py` reports the selected adapter in JSON (`schema.adapter`), Markdown (`Schema adapter`), and SARIF (`runs[].properties.schema_adapter` plus each result's `properties.schema_adapter`).

## Supported adapters

| Adapter | Fixture coverage | What is normalized |
| --- | --- | --- |
| `canonical` | Existing `examples/config-shapes/*.json` | Native agent-security/Hermes-style `tools`, `browser`, `channels`, `agents`, and `bindings` fields. |
| `openai_tools` | `openai-tools-risky.json`, `openai-tools-safe.json` | OpenAI-compatible `tools` arrays. `code_interpreter`, `computer_use`, and outbound-looking function tools are normalized to the canonical exec surface. Small/cheap model detection still uses the existing model heuristics. |
| `claude_desktop_mcp` | `claude-desktop-mcp-risky.json`, `claude-desktop-mcp-safe.json` | Claude Desktop-style `mcpServers` objects. Filesystem/shell/exec/command server names are normalized to canonical exec; filesystem servers pointed at broad roots such as `/`, `~`, `$HOME`, or Windows drive roots are normalized to broad filesystem access. |
| `github_actions` | `github-actions-risky.json`, `github-actions-safe.json` | GitHub Actions-like JSON snippets. Jobs with shell `run` steps plus broad write permissions are normalized to canonical exec exposure. |

## Unsupported fields

Unsupported fields are deliberately documented instead of guessed:

- `openai_tools`: `tool_choice`, `response_format`, and `parallel_tool_calls` are informational and do not currently affect findings.
- `claude_desktop_mcp`: `env`, `disabled`, and `autoApprove` are not treated as security controls until fixture-backed semantics are added.
- `github_actions`: workflow triggers, `env`, matrix expansion, and service containers are not interpreted by this adapter.

These adapters are **non-executable**. They inspect local JSON only; they do not start MCP servers, call OpenAI-compatible APIs, run GitHub Actions workflows, or resolve remote action references.

## Report stability

- `schema_version` remains `1.0` for this additive Phase 12 change.
- Rule IDs remain stable (`ASG-###`); adapter normalization maps into the existing canonical rules rather than creating duplicate adapter-specific rules.
- Evidence paths remain canonical so baselines and policies continue to match scanner findings consistently.
- Report paths should serialize as URI-style forward-slash paths across operating systems. Tests cover both POSIX `Path` and Windows `PureWindowsPath` inputs.

## Adding an adapter

1. Add one risky fixture and one safe fixture under `examples/schema-adapters/`.
2. Add test expectations in `tests/test_phase12_schema_adapters.py` for adapter name, findings, safe negative coverage, Markdown/SARIF adapter reporting, and path serialization if new path types are introduced.
3. Normalize into existing canonical fields before adding new detection rules.
4. Document ignored fields before broadening interpretation.
