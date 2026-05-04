#!/usr/bin/env python3
"""Score prompt-injection exposure from a JSON config/status object."""
import argparse
import json
import re
import sys
from typing import Any

SCHEMA_VERSION = "1.0"
SMALL_MODEL_RE = re.compile(r"(^|[^0-9])([1-9]|1[0-4])b([^0-9]|$)", re.I)
MODEL_MARKERS = ("haiku", "mini", "nano", "gemma", "phi", "qwen", "mistral", "ollama", "mlx", "gguf", "local")


def load_json() -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    raw = sys.stdin.read()
    if not raw.strip():
        return None, [{"points": 0, "factor": "empty_input", "severity": "error"}]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, [{"points": 0, "factor": "invalid_json", "severity": "error", "message": str(exc)}]
    if not isinstance(data, dict):
        return None, [{"points": 0, "factor": "invalid_schema", "severity": "error", "message": "top-level JSON value must be an object"}]
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


def truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.lower() in {"true", "yes", "enabled", "on"})


def model_to_str(model: Any) -> str:
    if isinstance(model, str):
        return model
    if isinstance(model, dict):
        for key in ("model", "name", "id"):
            if isinstance(model.get(key), str):
                return model[key]
    return ""


def risky_model(model: Any) -> bool:
    text = model_to_str(model).lower()
    return bool(text and (SMALL_MODEL_RE.search(text) or any(m in text for m in MODEL_MARKERS)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    args = parser.parse_args()

    cfg, factors = load_json()
    score = 0

    def add(points: int, name: str, **extra: Any) -> None:
        nonlocal score
        score += points
        item = {"points": points, "factor": name}
        item.update(extra)
        factors.append(item)

    if cfg is not None:
        channels = as_dict(cfg.get("channels"))
        discord = as_dict(channels.get("discord"))
        discord_enabled = truthy(discord.get("enabled")) or bool(discord)
        group_surface = discord.get("groupPolicy") in ("allowlist", "all")
        if discord_enabled:
            add(1, "discord_enabled")
            if group_surface:
                add(2, "discord_group_chat_surface")

        browser = as_dict(cfg.get("browser"))
        browser_enabled = truthy(browser.get("enabled"))
        if browser_enabled:
            add(2, "browser_enabled")
        if get_path(cfg, "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork") is True:
            add(4, "browser_private_network_allowed")

        tools = as_dict(cfg.get("tools"))
        web = as_dict(tools.get("web"))
        if truthy(get_path(web, "search.enabled")):
            add(1, "web_search_enabled")
        if truthy(get_path(web, "fetch.enabled")):
            add(2, "web_fetch_enabled")

        exec_cfg = as_dict(tools.get("exec"))
        exec_enabled = truthy(exec_cfg.get("enabled")) or exec_cfg.get("security") in {"full", "approval", "ask"}
        if exec_cfg.get("security") == "full":
            add(3, "exec_security_full")
        elif exec_enabled:
            add(1, "exec_surface_present")

        fs_cfg = as_dict(tools.get("fs"))
        if fs_cfg.get("workspaceOnly") is False:
            add(2, "filesystem_not_workspace_only")

        elevated = as_dict(tools.get("elevated"))
        elevated_enabled = truthy(elevated.get("enabled")) or bool(elevated.get("allowFrom"))
        if elevated_enabled:
            add(2, "elevated_enabled")
            if not elevated.get("allowFrom"):
                add(2, "elevated_without_allowlist")

        sandbox = as_dict(tools.get("sandbox")) or as_dict(cfg.get("sandbox"))
        if sandbox and sandbox.get("enabled") is False:
            add(2, "sandbox_disabled")

        models = []
        models.append(get_path(cfg, "agents.defaults.model.default") or get_path(cfg, "agents.defaults.model.name") or get_path(cfg, "agents.defaults.model"))
        models.extend(as_list(get_path(cfg, "agents.defaults.model.fallbacks", [])))
        for agent in as_list(get_path(cfg, "agents.list", [])):
            if isinstance(agent, dict):
                models.append(agent.get("model") or get_path(agent, "model.default"))
        if any(risky_model(model) for model in models):
            add(2, "small_or_local_model_present")

        bindings = as_list(cfg.get("bindings"))
        shared_binding = False
        for b in bindings:
            if not isinstance(b, dict):
                continue
            match = as_dict(b.get("match"))
            peer = as_dict(match.get("peer"))
            if match.get("channel") == "discord" and peer.get("kind") == "channel":
                shared_binding = True
                add(2, "shared_channel_binding")
                break
        if shared_binding and (browser_enabled or exec_enabled or elevated_enabled):
            add(3, "shared_channel_with_high_impact_tools")

        persistence = [path for path in ("memory.enabled", "cron.enabled", "tools.memory.enabled", "tools.cron.enabled", "notes.enabled") if truthy(get_path(cfg, path))]
        if persistence:
            add(2, "persistence_surface_present", fields=persistence)
            if shared_binding or browser_enabled or discord_enabled:
                add(2, "persistence_reachable_from_untrusted_content_context")

    severity = "low"
    if any(f.get("severity") == "error" for f in factors):
        severity = "error"
    elif score >= 14:
        severity = "critical"
    elif score >= 10:
        severity = "high"
    elif score >= 5:
        severity = "medium"

    result = {"schema_version": SCHEMA_VERSION, "score": score, "severity": severity, "factors": factors}
    print(json.dumps(result, separators=(",", ":") if args.compact else None, indent=None if args.compact else 2, sort_keys=True))
    return 1 if severity == "error" else 0


if __name__ == "__main__":
    raise SystemExit(main())
