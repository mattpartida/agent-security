#!/usr/bin/env python3
"""Summarize agent-security risks from a JSON config/status object.

The script is intentionally schema-tolerant: OpenClaw/Hermes config shapes can drift,
so wrong-type fields become findings instead of Python tracebacks.
"""
import argparse
import json
import re
import sys
from typing import Any

SCHEMA_VERSION = "1.0"
SMALL_MODEL_RE = re.compile(r"(^|[^0-9])([1-9]|1[0-4])b([^0-9]|$)", re.I)
LOCAL_MODEL_MARKERS = ("ollama", "llama.cpp", "llamacpp", "mlx", "gguf", "local")
SMALL_MODEL_MARKERS = ("haiku", "mini", "nano", "gemma", "phi", "qwen", "mistral")
UNKNOWN_MODEL_MARKERS = ("custom", "unknown")

RULE_IDS = {
    "shared_channel_with_exec_surface": "ASG-001",
    "browser_private_network_allowed": "ASG-002",
    "persistence_available_in_untrusted_content_context": "ASG-003",
    "elevated_enabled_without_allowlist": "ASG-004",
    "agent_elevated_without_allowlist": "ASG-004",
    "risky_agent_model_with_tools": "ASG-005",
    "risky_default_model": "ASG-005",
    "shared_channel_with_private_network_browser": "ASG-006",
    "shared_channel_with_elevated_surface": "ASG-007",
    "exec_security_full": "ASG-008",
    "discord_exec_approvals_enabled_without_approvers": "ASG-009",
    "discord_exec_approvals_missing": "ASG-010",
    "filesystem_not_workspace_only": "ASG-011",
    "sandbox_disabled": "ASG-012",
    "exec_or_commands_without_owner_allow_from": "ASG-013",
    "discord_group_chat_surface": "ASG-014",
    "discord_channel_binding": "ASG-015",
}


def load_json() -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    raw = sys.stdin.read()
    if not raw.strip():
        return None, [{"severity": "error", "risk": "empty_input", "message": "expected JSON on stdin"}]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, [{"severity": "error", "risk": "invalid_json", "message": str(exc)}]
    if not isinstance(data, dict):
        return None, [{"severity": "error", "risk": "invalid_schema", "message": "top-level JSON value must be an object"}]
    return data, []


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def get_path(obj: dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part, default)
    return cur


def model_to_str(model: Any) -> str:
    if isinstance(model, str):
        return model
    if isinstance(model, dict):
        for key in ("model", "name", "id"):
            if isinstance(model.get(key), str):
                return model[key]
    return ""


def classify_model(model: Any) -> tuple[str, str] | None:
    text = model_to_str(model).lower()
    if not text:
        return None
    if any(m in text for m in LOCAL_MODEL_MARKERS):
        return "local", "model name/provider suggests local inference"
    if SMALL_MODEL_RE.search(text) or any(m in text for m in SMALL_MODEL_MARKERS):
        return "small_or_cheap", "model name suggests smaller/cheaper model class"
    if any(m in text for m in UNKNOWN_MODEL_MARKERS):
        return "unknown", "custom or unknown model class"
    return None


def truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() in {"true", "yes", "enabled", "on"})


def markdown_cell(value: Any, *, code: bool = False) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        text = ", ".join(str(item) for item in value)
    else:
        text = str(value)
    text = text.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")
    if code and text:
        return f"`{text}`"
    return text


def render_markdown(summary: dict[str, Any]) -> str:
    lines = ["# Agent Security Config Risk Summary", ""]
    if summary["ok"]:
        lines.append("**Overall:** no high/critical findings")
    else:
        lines.append("**Overall:** high risk findings present")
    lines.append(f"**Risk count:** {summary['risk_count']}")
    lines.append("")
    lines.append("## Severity counts")
    lines.append("")
    if summary["counts"]:
        for severity in ("error", "critical", "high", "warn", "info"):
            count = summary["counts"].get(severity)
            if count:
                lines.append(f"- **{severity}:** {count}")
    else:
        lines.append("- No findings")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    findings = summary["findings"]
    if not findings:
        lines.append("No findings.")
        lines.append("")
        return "\n".join(lines)

    lines.append("| Severity | Rule | Risk | Field | Recommendation |")
    lines.append("| --- | --- | --- | --- | --- |")
    for finding in findings:
        field = finding.get("field") or finding.get("fields") or ""
        recommendation = finding.get("recommendation") or finding.get("reason") or ""
        details = []
        for key in ("agent", "index", "risk_class", "value", "expected"):
            if key in finding:
                details.append(f"{key}={finding[key]}")
        if details:
            recommendation = " — ".join(part for part in [str(recommendation), "; ".join(details)] if part)
        lines.append(
            "| "
            + " | ".join(
                [
                    markdown_cell(finding.get("severity")),
                    markdown_cell(finding.get("rule_id")),
                    markdown_cell(finding.get("risk")),
                    markdown_cell(field, code=bool(field)),
                    markdown_cell(recommendation),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="exit nonzero on error/high/critical findings")
    parser.add_argument("--fail-on", choices=["error", "critical", "high", "warn", "info"], default=None)
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="output format (default: json)")
    args = parser.parse_args()

    cfg, initial_findings = load_json()
    findings: list[dict[str, Any]] = list(initial_findings)

    def add(severity: str, risk: str, **extra: Any) -> None:
        item = {"severity": severity, "risk": risk}
        rule_id = RULE_IDS.get(risk)
        if rule_id:
            item["rule_id"] = rule_id
        item.update(extra)
        findings.append(item)

    if cfg is not None:
        tools = as_dict(cfg.get("tools"))
        browser = as_dict(cfg.get("browser"))
        commands = as_dict(cfg.get("commands"))
        channels = as_dict(cfg.get("channels"))
        agents_root = as_dict(cfg.get("agents"))

        exec_cfg = as_dict(tools.get("exec"))
        exec_security = exec_cfg.get("security")
        exec_enabled = truthy(exec_cfg.get("enabled")) or exec_security in {"full", "approval", "ask"}
        if exec_security == "full":
            add("high", "exec_security_full", field="tools.exec.security", recommendation="Use approval-gated or sandboxed exec where possible")

        elevated = as_dict(tools.get("elevated"))
        elevated_enabled = truthy(elevated.get("enabled")) or bool(elevated.get("allowFrom"))
        if elevated_enabled and not elevated.get("allowFrom"):
            add("high", "elevated_enabled_without_allowlist", field="tools.elevated.allowFrom")

        fs_cfg = as_dict(tools.get("fs"))
        if fs_cfg and fs_cfg.get("workspaceOnly") is False:
            add("warn", "filesystem_not_workspace_only", field="tools.fs.workspaceOnly")

        sandbox = as_dict(tools.get("sandbox")) or as_dict(cfg.get("sandbox"))
        if sandbox and sandbox.get("enabled") is False:
            add("warn", "sandbox_disabled", field="sandbox.enabled")

        browser_enabled = truthy(browser.get("enabled"))
        private_network = get_path(cfg, "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork") is True
        if private_network:
            add("high", "browser_private_network_allowed", field="browser.ssrfPolicy.dangerouslyAllowPrivateNetwork")

        if exec_enabled and not commands.get("ownerAllowFrom"):
            add("warn", "exec_or_commands_without_owner_allow_from", field="commands.ownerAllowFrom")

        discord = as_dict(channels.get("discord"))
        discord_enabled = truthy(discord.get("enabled")) or bool(discord)
        group_policy = discord.get("groupPolicy")
        if discord_enabled and group_policy in ("allowlist", "all"):
            add("info", "discord_group_chat_surface", field="channels.discord.groupPolicy", value=group_policy)

        exec_approvals = as_dict(discord.get("execApprovals"))
        if discord_enabled and exec_enabled:
            if not exec_approvals:
                add("warn", "discord_exec_approvals_missing", field="channels.discord.execApprovals")
            elif truthy(exec_approvals.get("enabled")) and not exec_approvals.get("approvers"):
                add("high", "discord_exec_approvals_enabled_without_approvers", field="channels.discord.execApprovals.approvers")

        default_models = []
        default_model = get_path(cfg, "agents.defaults.model.default") or get_path(cfg, "agents.defaults.model.name") or get_path(cfg, "agents.defaults.model")
        default_models.append(default_model)
        default_models.extend(as_list(get_path(cfg, "agents.defaults.model.fallbacks", [])))
        for model in default_models:
            cls = classify_model(model)
            if cls:
                add("warn", "risky_default_model", model=model_to_str(model), risk_class=cls[0], reason=cls[1])

        agents = as_list(agents_root.get("list"))
        if agents_root.get("list") is not None and not isinstance(agents_root.get("list"), list):
            add("warn", "invalid_agents_list_schema", field="agents.list", expected="list")
        for idx, agent_raw in enumerate(agents):
            if not isinstance(agent_raw, dict):
                add("warn", "invalid_agent_schema", index=idx, expected="object")
                continue
            aid = agent_raw.get("id", f"index:{idx}")
            agent_tools = as_dict(agent_raw.get("tools"))
            agent_elevated = as_dict(agent_tools.get("elevated"))
            if truthy(agent_elevated.get("enabled")) and not agent_elevated.get("allowFrom"):
                add("high", "agent_elevated_without_allowlist", agent=aid, field="agents.list[].tools.elevated.allowFrom")
            agent_model = agent_raw.get("model") or get_path(agent_raw, "model.default")
            cls = classify_model(agent_model)
            if cls and agent_tools:
                add("warn", "risky_agent_model_with_tools", agent=aid, model=model_to_str(agent_model), risk_class=cls[0])

        bindings = as_list(cfg.get("bindings"))
        if cfg.get("bindings") is not None and not isinstance(cfg.get("bindings"), list):
            add("warn", "invalid_bindings_schema", field="bindings", expected="list")
        shared_binding = False
        for b in bindings:
            if not isinstance(b, dict):
                continue
            match = as_dict(b.get("match"))
            peer = as_dict(match.get("peer"))
            if match.get("channel") == "discord" and peer.get("kind") == "channel":
                shared_binding = True
                add("info", "discord_channel_binding", agent=b.get("agentId"), field="bindings")
        if shared_binding and private_network:
            add("critical", "shared_channel_with_private_network_browser")
        if shared_binding and exec_enabled:
            add("high", "shared_channel_with_exec_surface")
        if shared_binding and elevated_enabled:
            add("high", "shared_channel_with_elevated_surface")

        persistence_paths = []
        for path in ("memory.enabled", "cron.enabled", "tools.memory.enabled", "tools.cron.enabled", "notes.enabled"):
            if truthy(get_path(cfg, path)):
                persistence_paths.append(path)
        if persistence_paths and (shared_binding or browser_enabled or discord_enabled):
            add("warn", "persistence_available_in_untrusted_content_context", fields=persistence_paths)

    severity_order = {"error": 5, "critical": 4, "high": 3, "warn": 2, "info": 1}
    summary = {
        "schema_version": SCHEMA_VERSION,
        "ok": not any(f["severity"] in {"error", "critical", "high"} for f in findings),
        "risk_count": len(findings),
        "counts": {},
        "findings": findings,
    }
    for f in findings:
        summary["counts"][f["severity"]] = summary["counts"].get(f["severity"], 0) + 1
    if args.format == "markdown":
        print(render_markdown(summary))
    else:
        print(json.dumps(summary, separators=(",", ":") if args.compact else None, indent=None if args.compact else 2, sort_keys=True))

    fail_on = args.fail_on or ("high" if args.strict else None)
    if fail_on:
        threshold = severity_order[fail_on]
        if any(severity_order.get(f["severity"], 0) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
