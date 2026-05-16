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

RULE_METADATA = {
    "ASG-001": {
        "risk": "shared_channel_with_exec_surface",
        "severity": "high",
        "description": "A shared Discord/channel binding can reach shell/runtime execution.",
        "help": "Separate shared agents from exec tools, or require strict sender-specific approvals and sandboxing.",
    },
    "ASG-002": {
        "risk": "browser_private_network_allowed",
        "severity": "high",
        "description": "Browser SSRF policy allows localhost/RFC1918/private-network access.",
        "help": "Disable private-network browser access unless explicitly required and isolated.",
    },
    "ASG-003": {
        "risk": "persistence_available_in_untrusted_content_context",
        "severity": "warn",
        "description": "Persistence is available where untrusted content may be present.",
        "help": "Require human review before persistence and isolate untrusted-content workflows.",
    },
    "ASG-004": {
        "risk": "elevated_enabled_without_allowlist",
        "severity": "high",
        "description": "Elevated tools are enabled without a specific sender/resource allowlist.",
        "help": "Add narrow sender-specific allowlists or disable elevated tools.",
    },
    "ASG-005": {
        "risk": "risky_default_model",
        "severity": "warn",
        "description": "Small, local, cheap, custom, or unknown models are combined with defaults or tools.",
        "help": "Use stronger models for high-risk tools, remove risky fallbacks, or narrow/sandbox tools.",
    },
    "ASG-006": {
        "risk": "shared_channel_with_private_network_browser",
        "severity": "critical",
        "description": "Shared channel binding combines with private-network browser access.",
        "help": "Split the runtime or disable private-network browsing for shared agents.",
    },
    "ASG-007": {
        "risk": "shared_channel_with_elevated_surface",
        "severity": "high",
        "description": "Shared channel binding can reach elevated tools.",
        "help": "Separate shared runtimes from elevated tools and use explicit sender approvals.",
    },
    "ASG-008": {
        "risk": "exec_security_full",
        "severity": "high",
        "description": "Shell/runtime execution is configured as full/unrestricted.",
        "help": "Use approval-gated or sandboxed execution, preferably workspace-scoped.",
    },
    "ASG-009": {
        "risk": "discord_exec_approvals_enabled_without_approvers",
        "severity": "high",
        "description": "Discord exec approvals are enabled without explicit approvers.",
        "help": "Configure explicit approvers by sender identity.",
    },
    "ASG-010": {
        "risk": "discord_exec_approvals_missing",
        "severity": "warn",
        "description": "Discord is enabled with exec surface but no exec approval config was found.",
        "help": "Add clear exec approval policy or remove exec from Discord-bound agents.",
    },
    "ASG-011": {
        "risk": "filesystem_not_workspace_only",
        "severity": "warn",
        "description": "Filesystem access is broader than workspace-only.",
        "help": "Prefer workspace-only file access for project and shared agents.",
    },
    "ASG-012": {
        "risk": "sandbox_disabled",
        "severity": "warn",
        "description": "Sandbox config is present and explicitly disabled.",
        "help": "Enable sandboxing for runtime, browser, and filesystem access where available.",
    },
    "ASG-013": {
        "risk": "exec_or_commands_without_owner_allow_from",
        "severity": "warn",
        "description": "Exec/command surface exists without owner approver config.",
        "help": "Configure owner/sender-specific approval sources.",
    },
    "ASG-014": {
        "risk": "discord_group_chat_surface",
        "severity": "info",
        "description": "Discord group/channel surface is enabled.",
        "help": "Treat group content as untrusted and tighten tools/approvals.",
    },
    "ASG-015": {
        "risk": "discord_channel_binding",
        "severity": "info",
        "description": "An agent is bound to a Discord channel peer.",
        "help": "Confirm the channel trust boundary and avoid ambient private credentials.",
    },
}


def load_json() -> tuple[dict[str, Any] | None, list[dict[str, Any]], str]:
    raw = sys.stdin.read()
    if not raw.strip():
        return None, [{"severity": "error", "risk": "empty_input", "message": "expected JSON on stdin"}], raw
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, [{"severity": "error", "risk": "invalid_json", "message": str(exc)}], raw
    if not isinstance(data, dict):
        return None, [{"severity": "error", "risk": "invalid_schema", "message": "top-level JSON value must be an object"}], raw
    return data, [], raw


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


def set_path_default(obj: dict[str, Any], path: str, value: Any) -> None:
    cur = obj
    parts = path.split(".")
    for part in parts[:-1]:
        existing = cur.get(part)
        if not isinstance(existing, dict):
            existing = {}
            cur[part] = existing
        cur = existing
    cur.setdefault(parts[-1], value)


def normalize_config_shape(config: dict[str, Any]) -> dict[str, Any]:
    """Normalize common real-world aliases into the canonical scanner shape.

    The original object is left untouched. Canonical fields win over aliases so
    users can migrate gradually without surprising overrides.
    """
    normalized = json.loads(json.dumps(config))

    platforms = as_dict(normalized.get("platforms"))
    platform_discord = as_dict(platforms.get("discord"))
    if platform_discord:
        discord = as_dict(get_path(normalized, "channels.discord", {})).copy()
        for key, value in platform_discord.items():
            discord.setdefault(key, value)
        if "group_policy" in discord and "groupPolicy" not in discord:
            discord["groupPolicy"] = discord["group_policy"]
        if "exec_approvals" in discord and "execApprovals" not in discord:
            discord["execApprovals"] = discord["exec_approvals"]
        channels = as_dict(normalized.get("channels")).copy()
        channels["discord"] = discord
        normalized["channels"] = channels

    browser = as_dict(normalized.get("browser"))
    for alias in ("allowPrivateNetwork", "privateNetworkAccess", "dangerouslyAllowPrivateNetwork"):
        if browser.get(alias) is True:
            set_path_default(normalized, "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork", True)
            break

    toolset_values = as_list(normalized.get("enabled_toolsets")) + as_list(normalized.get("toolsets"))
    toolset_names = {str(item).lower().replace("-", "_") for item in toolset_values}
    if toolset_names & {"terminal", "shell", "exec", "command", "commands", "code", "code_execution"}:
        set_path_default(normalized, "tools.exec.enabled", True)
    if toolset_names & {"browser", "web", "web_browser"}:
        set_path_default(normalized, "browser.enabled", True)
    if toolset_names & {"memory", "persistent_memory"}:
        set_path_default(normalized, "tools.memory.enabled", True)
    if toolset_names & {"cron", "scheduled_jobs", "scheduler"}:
        set_path_default(normalized, "tools.cron.enabled", True)

    if normalized.get("model") is not None:
        set_path_default(normalized, "agents.defaults.model", normalized["model"])

    return normalized


def evidence_paths_from_finding(finding: dict[str, Any]) -> list[str]:
    paths = finding.get("evidence_paths") or finding.get("fields") or finding.get("field") or []
    if isinstance(paths, str):
        return [paths]
    if isinstance(paths, list):
        return [path for path in paths if isinstance(path, str) and path]
    return []


def split_path_part(part: str) -> tuple[str, int | None]:
    match = re.fullmatch(r"([^\[]+)(?:\[(\d+)\])?", part)
    if not match:
        return part, None
    index = int(match.group(2)) if match.group(2) is not None else None
    return match.group(1), index


def find_key(raw: str, key: str, start: int) -> re.Match[str] | None:
    patterns = (f'"{re.escape(key)}"', rf"(?m)^\s*{re.escape(key)}\s*[:=]")
    best_match = None
    for pattern in patterns:
        match = re.search(pattern, raw[start:])
        if match and (best_match is None or match.start() < best_match.start()):
            best_match = match
    return best_match


def find_array_item_start(raw: str, array_value_start: int, index: int) -> int | None:
    bracket_start = raw.find("[", array_value_start)
    if bracket_start == -1:
        return None
    bracket_depth = 0
    object_depth = 0
    item_index = -1
    in_string = False
    escaped = False
    for pos in range(bracket_start, len(raw)):
        char = raw[pos]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "[":
            bracket_depth += 1
        elif char == "]":
            bracket_depth -= 1
            if bracket_depth == 0:
                return None
        elif char == "{":
            if bracket_depth == 1 and object_depth == 0:
                item_index += 1
                if item_index == index:
                    return pos + 1
            object_depth += 1
        elif char == "}" and object_depth:
            object_depth -= 1
    return None


def source_line_for_path(raw: str, path: str) -> int:
    """Best-effort line resolver for JSON/YAML/TOML-like key paths.

    This intentionally avoids adding parser dependencies. It walks path components in
    order and resolves to the final component when the raw input text contains it;
    unresolved paths fall back to line 1 so SARIF/JSON remain well-formed.
    """

    def resolve(candidate: str) -> int:
        if not raw.strip() or not candidate:
            return 1
        search_from = 0
        matched_at: int | None = None
        for part in candidate.split("."):
            key, index = split_path_part(part)
            if not key:
                continue
            match = find_key(raw, key, search_from)
            if match is None:
                return 1
            matched_at = search_from + match.start()
            search_from = search_from + match.end()
            if index is not None:
                item_start = find_array_item_start(raw, search_from, index)
                if item_start is None:
                    return 1
                search_from = item_start
        if matched_at is None:
            return 1
        return raw.count("\n", 0, matched_at) + 1

    direct_line = resolve(path)
    if direct_line > 1:
        return direct_line
    alias_paths = {
        "browser.ssrfPolicy.dangerouslyAllowPrivateNetwork": [
            "browser.allowPrivateNetwork",
            "browser.privateNetworkAccess",
            "browser.dangerouslyAllowPrivateNetwork",
        ],
        "channels.discord.groupPolicy": ["platforms.discord.group_policy"],
        "channels.discord.execApprovals": ["platforms.discord.exec_approvals"],
        "channels.discord.execApprovals.approvers": ["platforms.discord.exec_approvals.approvers"],
        "tools.exec.enabled": ["enabled_toolsets", "toolsets"],
        "tools.memory.enabled": ["enabled_toolsets", "toolsets"],
        "tools.cron.enabled": ["enabled_toolsets", "toolsets"],
        "browser.enabled": ["enabled_toolsets", "toolsets"],
        "agents.defaults.model": ["model"],
    }
    for alias_path in alias_paths.get(path, []):
        alias_line = resolve(alias_path)
        if alias_line > 1:
            return alias_line
    return direct_line


def attach_evidence_metadata(finding: dict[str, Any], raw: str) -> dict[str, Any]:
    paths = evidence_paths_from_finding(finding)
    if paths:
        finding["evidence_paths"] = paths
        finding["source_locations"] = [{"path": path, "line": source_line_for_path(raw, path)} for path in paths]
    evidence = {key: finding[key] for key in ("agent", "index", "risk_class", "value", "expected", "model") if key in finding}
    if evidence:
        finding["evidence"] = evidence
    return finding


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


def finding_evidence(finding: dict[str, Any]) -> Any:
    return finding.get("evidence_paths") or finding.get("field") or finding.get("fields") or ""


def finding_recommendation(finding: dict[str, Any]) -> str:
    recommendation = finding.get("recommendation") or finding.get("reason") or ""
    details = []
    for key in ("agent", "index", "risk_class", "value", "expected", "model"):
        if key in finding:
            details.append(f"{key}={finding[key]}")
    if details:
        return " — ".join(part for part in [str(recommendation), "; ".join(details)] if part)
    if finding.get("rule_id") in RULE_METADATA:
        return RULE_METADATA[finding["rule_id"]]["help"]
    return str(recommendation)


def render_markdown(summary: dict[str, Any]) -> str:
    lines = ["# Agent Security Config Risk Summary", ""]
    counts = summary["counts"]
    if counts.get("error") and not (counts.get("critical") or counts.get("high")):
        lines.append("**Overall:** scanner input error")
    else:
        lines.append("**Overall:** no high/critical findings" if summary["ok"] else "**Overall:** high risk findings present")
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

    lines.append("| Severity | Rule | Risk | Evidence | Recommendation |")
    lines.append("| --- | --- | --- | --- | --- |")
    for finding in findings:
        evidence = finding_evidence(finding)
        lines.append(
            "| "
            + " | ".join(
                [
                    markdown_cell(finding.get("severity")),
                    markdown_cell(finding.get("rule_id")),
                    markdown_cell(finding.get("risk")),
                    markdown_cell(evidence, code=bool(evidence)),
                    markdown_cell(finding_recommendation(finding)),
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def sarif_level(severity: str) -> str:
    return {
        "error": "error",
        "critical": "error",
        "high": "error",
        "warn": "warning",
        "info": "note",
    }.get(severity, "warning")


def sarif_rule_id(finding: dict[str, Any]) -> str:
    return finding.get("rule_id") or finding.get("risk", "agent-security-finding")


def sarif_rule_metadata(rule_id: str, finding: dict[str, Any] | None = None) -> dict[str, str]:
    if rule_id in RULE_METADATA:
        return RULE_METADATA[rule_id]
    risk = finding.get("risk", rule_id) if finding else rule_id
    severity = finding.get("severity", "warn") if finding else "warn"
    message = finding.get("message", risk) if finding else risk
    return {"risk": risk, "severity": severity, "description": str(message), "help": "Review the scanner input and finding details."}


VALID_SEVERITIES = {"error", "critical", "high", "warn", "info"}


def structured_error(risk: str, message: str, path: str | None = None) -> dict[str, Any]:
    finding: dict[str, Any] = {"severity": "error", "risk": risk, "message": message}
    if path:
        finding["field"] = path
    return finding


def baseline_error(message: str, path: str | None = None) -> dict[str, Any]:
    return structured_error("invalid_baseline", message, path)


def policy_error(message: str, path: str | None = None) -> dict[str, Any]:
    return structured_error("invalid_policy", message, path)


def load_baseline(path: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not path:
        return [], []
    try:
        with open(path, encoding="utf-8") as fh:
            baseline = json.load(fh)
    except OSError as exc:
        return [], [baseline_error(f"could not read baseline: {exc}", path)]
    except json.JSONDecodeError as exc:
        return [], [baseline_error(f"invalid baseline JSON: {exc}", path)]

    if not isinstance(baseline, dict):
        return [], [baseline_error("baseline top-level value must be an object", path)]
    suppressions = baseline.get("suppressions")
    if not isinstance(suppressions, list):
        return [], [baseline_error("baseline must contain a suppressions list", "suppressions")]

    valid: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for idx, entry in enumerate(suppressions):
        entry_path = f"suppressions[{idx}]"
        if not isinstance(entry, dict):
            errors.append(baseline_error("baseline suppression must be an object", entry_path))
            continue
        rule_id = entry.get("rule_id")
        evidence_paths = entry.get("evidence_paths")
        if not isinstance(rule_id, str) or not rule_id.startswith("ASG-"):
            errors.append(baseline_error("baseline suppression requires stable ASG rule_id", f"{entry_path}.rule_id"))
            continue
        if not isinstance(evidence_paths, list) or not all(isinstance(item, str) and item for item in evidence_paths):
            errors.append(baseline_error("baseline suppression requires non-empty evidence_paths list", f"{entry_path}.evidence_paths"))
            continue
        valid.append(entry)
    return valid, errors


def load_policy(path: str | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    empty = {"severity_overrides": {}, "disabled_rules": [], "allowlists": [], "metadata": {}}
    if not path:
        return empty, []
    try:
        with open(path, encoding="utf-8") as fh:
            policy = json.load(fh)
    except OSError as exc:
        return empty, [policy_error(f"could not read policy: {exc}", path)]
    except json.JSONDecodeError as exc:
        return empty, [policy_error(f"invalid policy JSON: {exc}", path)]

    if not isinstance(policy, dict):
        return empty, [policy_error("policy top-level value must be an object", path)]

    errors: list[dict[str, Any]] = []
    severity_overrides = policy.get("severity_overrides", {})
    if not isinstance(severity_overrides, dict):
        errors.append(policy_error("policy severity_overrides must be an object", "severity_overrides"))
        severity_overrides = {}
    else:
        for rule_id, severity in severity_overrides.items():
            if not isinstance(rule_id, str) or not rule_id.startswith("ASG-"):
                errors.append(policy_error("policy severity override keys must be stable ASG rule IDs", f"severity_overrides.{rule_id}"))
                continue
            if severity not in VALID_SEVERITIES:
                choices = ", ".join(sorted(VALID_SEVERITIES))
                errors.append(policy_error(f"policy severity override for {rule_id} must be one of: {choices}", f"severity_overrides.{rule_id}"))

    disabled_rules = policy.get("disabled_rules", [])
    if not isinstance(disabled_rules, list) or not all(isinstance(item, str) and item.startswith("ASG-") for item in disabled_rules):
        errors.append(policy_error("policy disabled_rules must be a list of ASG rule IDs", "disabled_rules"))
        disabled_rules = []

    allowlists = policy.get("allowlists", [])
    if not isinstance(allowlists, list):
        errors.append(policy_error("policy allowlists must be a list", "allowlists"))
        allowlists = []
    else:
        for idx, entry in enumerate(allowlists):
            entry_path = f"allowlists[{idx}]"
            if not isinstance(entry, dict):
                errors.append(policy_error("policy allowlist entry must be an object", entry_path))
                continue
            rule_id = entry.get("rule_id")
            evidence_paths = entry.get("evidence_paths")
            if not isinstance(rule_id, str) or not rule_id.startswith("ASG-"):
                errors.append(policy_error("policy allowlist entry requires stable ASG rule_id", f"{entry_path}.rule_id"))
            if not isinstance(evidence_paths, list) or not all(isinstance(item, str) and item for item in evidence_paths):
                errors.append(policy_error("policy allowlist entry requires non-empty evidence_paths list", f"{entry_path}.evidence_paths"))

    metadata = policy.get("metadata", {})
    if not isinstance(metadata, dict):
        errors.append(policy_error("policy metadata must be an object", "metadata"))
        metadata = {}

    normalized = {
        "severity_overrides": severity_overrides,
        "disabled_rules": disabled_rules,
        "allowlists": allowlists,
        "metadata": metadata,
    }
    return normalized, errors


def suppression_matches(finding: dict[str, Any], suppression: dict[str, Any]) -> bool:
    if finding.get("rule_id") != suppression.get("rule_id"):
        return False
    finding_paths = set(evidence_paths_from_finding(finding))
    suppression_paths = set(suppression.get("evidence_paths", []))
    return bool(finding_paths) and finding_paths == suppression_paths


def apply_policy_severity_overrides(findings: list[dict[str, Any]], policy: dict[str, Any]) -> list[dict[str, Any]]:
    overrides = policy.get("severity_overrides", {})
    updated: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = finding.get("rule_id")
        override = overrides.get(rule_id)
        if override and finding.get("severity") != override:
            item = dict(finding)
            previous = item.get("severity")
            item["severity"] = override
            policy_meta = dict(item.get("policy", {}))
            policy_meta["severity_override"] = {"from": previous, "to": override}
            item["policy"] = policy_meta
            updated.append(item)
        else:
            updated.append(finding)
    return updated


def policy_suppression_metadata(suppression_type: str, source: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    metadata = {"suppression_type": suppression_type}
    for key in ("owner", "reason", "ticket", "expires_at"):
        if key in source:
            metadata[key] = source[key]
        elif key in policy.get("metadata", {}):
            metadata[key] = policy["metadata"][key]
    return metadata


def apply_policy_suppressions(
    findings: list[dict[str, Any]], policy: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    disabled_rules = set(policy.get("disabled_rules", []))
    allowlists = policy.get("allowlists", [])
    active: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        matched: tuple[str, dict[str, Any]] | None = None
        rule_id = finding.get("rule_id")
        if rule_id in disabled_rules:
            matched = ("disabled_rule", {"rule_id": rule_id})
        else:
            allowlist = next((entry for entry in allowlists if suppression_matches(finding, entry)), None)
            if allowlist:
                matched = ("allowlist", allowlist)
        if matched:
            item = dict(finding)
            suppression_type, source = matched
            item["policy"] = policy_suppression_metadata(suppression_type, source, policy)
            suppressed.append(item)
        else:
            active.append(finding)
    return active, suppressed


def apply_baseline_suppressions(
    findings: list[dict[str, Any]], suppressions: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        matched = next((suppression for suppression in suppressions if suppression_matches(finding, suppression)), None)
        if matched:
            item = dict(finding)
            item["suppression"] = {
                key: matched[key]
                for key in ("owner", "reason", "ticket", "expires_at")
                if key in matched
            }
            suppressed.append(item)
        else:
            active.append(finding)
    return active, suppressed


def count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity")
        if isinstance(severity, str):
            counts[severity] = counts.get(severity, 0) + 1
    return counts


def render_sarif(summary: dict[str, Any]) -> dict[str, Any]:
    findings_by_rule_id = {sarif_rule_id(finding): finding for finding in summary["findings"]}
    rules = []
    for rule_id in sorted(findings_by_rule_id):
        metadata = sarif_rule_metadata(rule_id, findings_by_rule_id[rule_id])
        rules.append(
            {
                "id": rule_id,
                "name": metadata["risk"],
                "shortDescription": {"text": metadata["risk"]},
                "fullDescription": {"text": metadata["description"]},
                "help": {"text": metadata["help"]},
                "properties": {"default_severity": metadata["severity"]},
            }
        )
    results = []
    for finding in summary["findings"]:
        rule_id = sarif_rule_id(finding)
        message_parts = [finding.get("risk", "unknown risk")]
        recommendation = finding_recommendation(finding)
        if recommendation:
            message_parts.append(recommendation)
        source_locations = finding.get("source_locations") or []
        resolved_lines = [location.get("line", 1) for location in source_locations if isinstance(location, dict) and location.get("line", 1) > 1]
        source_line = min(resolved_lines) if resolved_lines else 1
        result = {
            "ruleId": rule_id or finding.get("risk", "agent-security-finding"),
            "level": sarif_level(finding.get("severity", "warn")),
            "message": {"text": ": ".join(message_parts)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "stdin"},
                        "region": {"startLine": source_line},
                    }
                }
            ],
            "properties": {
                "severity": finding.get("severity"),
                "risk": finding.get("risk"),
                "evidence_paths": evidence_paths_from_finding(finding),
                "source_locations": source_locations,
            },
        }
        if finding.get("policy"):
            result["properties"]["policy"] = finding["policy"]
        if rule_id:
            result["properties"]["rule_id"] = rule_id
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-security config_risk_summary.py",
                        "informationUri": "https://github.com/mattpartida/agent-security",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="exit nonzero on error/high/critical findings")
    parser.add_argument("--fail-on", choices=["error", "critical", "high", "warn", "info"], default=None)
    parser.add_argument("--compact", action="store_true", help="emit compact JSON")
    parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="json", help="output format")
    parser.add_argument("--baseline", help="path to an auditable JSON baseline of exact rule/evidence suppressions")
    parser.add_argument("--policy", help="path to an auditable JSON policy for severity overrides, disabled rules, and allowlists")
    args = parser.parse_args()

    policy, policy_errors = load_policy(args.policy)
    baseline_suppressions, baseline_errors = load_baseline(args.baseline)
    cfg, initial_findings, raw_input = load_json()
    if cfg is not None and not policy_errors:
        cfg = normalize_config_shape(cfg)
    findings: list[dict[str, Any]] = list(policy_errors) + list(baseline_errors) + list(initial_findings)

    def add(severity: str, risk: str, **extra: Any) -> None:
        item = {"severity": severity, "risk": risk}
        rule_id = RULE_IDS.get(risk)
        if rule_id:
            item["rule_id"] = rule_id
        item.update(extra)
        if rule_id and "recommendation" not in item:
            item["recommendation"] = RULE_METADATA[rule_id]["help"]
        attach_evidence_metadata(item, raw_input)
        findings.append(item)

    if cfg is not None and not policy_errors:
        tools = as_dict(cfg.get("tools"))
        browser = as_dict(cfg.get("browser"))
        commands = as_dict(cfg.get("commands"))
        channels = as_dict(cfg.get("channels"))
        agents_root = as_dict(cfg.get("agents"))

        exec_cfg = as_dict(tools.get("exec"))
        exec_security = exec_cfg.get("security")
        exec_enabled_paths = []
        if truthy(exec_cfg.get("enabled")):
            exec_enabled_paths.append("tools.exec.enabled")
        if exec_security in {"full", "approval", "ask"}:
            exec_enabled_paths.append("tools.exec.security")
        exec_enabled = bool(exec_enabled_paths)
        if exec_security == "full":
            add("high", "exec_security_full", field="tools.exec.security", recommendation="Use approval-gated or sandboxed exec where possible")

        elevated = as_dict(tools.get("elevated"))
        elevated_paths = []
        if truthy(elevated.get("enabled")):
            elevated_paths.append("tools.elevated.enabled")
        if elevated.get("allowFrom"):
            elevated_paths.append("tools.elevated.allowFrom")
        elevated_enabled = bool(elevated_paths)
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
        if default_model:
            default_models.append((default_model, "agents.defaults.model"))
        for idx, fallback_model in enumerate(as_list(get_path(cfg, "agents.defaults.model.fallbacks", []))):
            default_models.append((fallback_model, f"agents.defaults.model.fallbacks[{idx}]"))
        for model, model_path in default_models:
            cls = classify_model(model)
            if cls:
                add("warn", "risky_default_model", field=model_path, model=model_to_str(model), risk_class=cls[0], reason=cls[1])

        agents = as_list(agents_root.get("list"))
        if agents_root.get("list") is not None and not isinstance(agents_root.get("list"), list):
            add("warn", "invalid_agents_list_schema", field="agents.list", expected="list")
        for idx, agent_raw in enumerate(agents):
            if not isinstance(agent_raw, dict):
                add("warn", "invalid_agent_schema", index=idx, expected="object", field=f"agents.list[{idx}]")
                continue
            aid = agent_raw.get("id", f"index:{idx}")
            agent_tools = as_dict(agent_raw.get("tools"))
            agent_elevated = as_dict(agent_tools.get("elevated"))
            if truthy(agent_elevated.get("enabled")) and not agent_elevated.get("allowFrom"):
                add("high", "agent_elevated_without_allowlist", agent=aid, field=f"agents.list[{idx}].tools.elevated.allowFrom")
            agent_model = agent_raw.get("model") or get_path(agent_raw, "model.default")
            cls = classify_model(agent_model)
            if cls and agent_tools:
                add("warn", "risky_agent_model_with_tools", agent=aid, field=f"agents.list[{idx}].model", model=model_to_str(agent_model), risk_class=cls[0])

        bindings = as_list(cfg.get("bindings"))
        if cfg.get("bindings") is not None and not isinstance(cfg.get("bindings"), list):
            add("warn", "invalid_bindings_schema", field="bindings", expected="list")
        shared_binding = False
        shared_binding_paths: list[str] = []
        for idx, b in enumerate(bindings):
            if not isinstance(b, dict):
                continue
            match = as_dict(b.get("match"))
            peer = as_dict(match.get("peer"))
            if match.get("channel") == "discord" and peer.get("kind") == "channel":
                shared_binding = True
                binding_paths = [f"bindings[{idx}].match.channel", f"bindings[{idx}].match.peer.kind"]
                shared_binding_paths.extend(binding_paths)
                add("info", "discord_channel_binding", agent=b.get("agentId"), evidence_paths=binding_paths)
        private_network_paths = ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"]
        if shared_binding and private_network:
            add("critical", "shared_channel_with_private_network_browser", evidence_paths=shared_binding_paths + private_network_paths)
        if shared_binding and exec_enabled:
            add("high", "shared_channel_with_exec_surface", evidence_paths=shared_binding_paths + exec_enabled_paths)
        if shared_binding and elevated_enabled:
            add("high", "shared_channel_with_elevated_surface", evidence_paths=shared_binding_paths + elevated_paths)

        persistence_paths = []
        for path in ("memory.enabled", "cron.enabled", "tools.memory.enabled", "tools.cron.enabled", "notes.enabled"):
            if truthy(get_path(cfg, path)):
                persistence_paths.append(path)
        if persistence_paths and (shared_binding or browser_enabled or discord_enabled):
            add("warn", "persistence_available_in_untrusted_content_context", fields=persistence_paths)

    findings = apply_policy_severity_overrides(findings, policy)
    policy_active_findings, policy_suppressed_findings = apply_policy_suppressions(findings, policy)
    active_findings, suppressed_findings = apply_baseline_suppressions(policy_active_findings, baseline_suppressions)
    severity_order = {"error": 5, "critical": 4, "high": 3, "warn": 2, "info": 1}
    summary = {
        "schema_version": SCHEMA_VERSION,
        "ok": not any(f["severity"] in {"error", "critical", "high"} for f in active_findings),
        "risk_count": len(active_findings),
        "counts": count_by_severity(active_findings),
        "findings": active_findings,
        "policy_suppressed_findings": policy_suppressed_findings,
        "policy_suppressed_summary": {
            "count": len(policy_suppressed_findings),
            "counts": count_by_severity(policy_suppressed_findings),
        },
        "suppressed_findings": suppressed_findings,
        "suppressed_summary": {
            "count": len(suppressed_findings),
            "counts": count_by_severity(suppressed_findings),
        },
    }
    if args.format == "markdown":
        print(render_markdown(summary))
    elif args.format == "sarif":
        print(json.dumps(render_sarif(summary), separators=(",", ":") if args.compact else None, indent=None if args.compact else 2, sort_keys=True))
    else:
        print(json.dumps(summary, separators=(",", ":") if args.compact else None, indent=None if args.compact else 2, sort_keys=True))

    fail_on = args.fail_on or ("high" if args.strict else None)
    if fail_on:
        threshold = severity_order[fail_on]
        if any(severity_order.get(f["severity"], 0) >= threshold for f in active_findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
