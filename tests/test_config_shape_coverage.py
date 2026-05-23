import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "examples" / "config-shapes"
CONFIG_SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"
SCORE_SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "score_prompt_injection_exposure.py"

EXPECTED_CONFIG_RISKS = {
    "personal-local.json": {"exec_or_commands_without_owner_allow_from", "risky_default_model"},
    "discord-shared.json": {"discord_group_chat_surface", "discord_channel_binding", "shared_channel_with_exec_surface"},
    "browser-agent.json": {"browser_private_network_allowed", "shared_channel_with_private_network_browser"},
    "cron-memory-agent.json": {"persistence_available_in_untrusted_content_context"},
    "ci-only-scanner.json": set(),
    "malformed-safe.json": {"invalid_agents_list_schema", "invalid_bindings_schema"},
}

EXPECTED_EXPOSURE_FACTORS = {
    "personal-local.json": {"exec_surface_present", "small_or_local_model_present"},
    "discord-shared.json": {"discord_enabled", "discord_group_chat_surface", "exec_surface_present", "shared_channel_with_high_impact_tools"},
    "browser-agent.json": {"browser_enabled", "browser_private_network_allowed", "shared_channel_with_high_impact_tools"},
    "cron-memory-agent.json": {"discord_enabled", "persistence_surface_present", "persistence_reachable_from_untrusted_content_context"},
    "ci-only-scanner.json": set(),
    "malformed-safe.json": set(),
}


def fixture_payload(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def run(script: Path, payload: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_every_config_shape_fixture_is_declared():
    actual = {path.name for path in FIXTURE_DIR.glob("*.json")}
    assert actual == set(EXPECTED_CONFIG_RISKS) == set(EXPECTED_EXPOSURE_FACTORS)


def test_config_risk_summary_handles_real_world_config_shapes():
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        data = run(CONFIG_SCRIPT, fixture_payload(path))
        risks = {finding["risk"] for finding in data["findings"]}
        assert EXPECTED_CONFIG_RISKS[path.name].issubset(risks), path.name
        if not EXPECTED_CONFIG_RISKS[path.name]:
            assert risks == set(), path.name
        assert all("traceback" not in json.dumps(finding).lower() for finding in data["findings"])


def test_prompt_injection_exposure_handles_real_world_config_shapes():
    for path in sorted(FIXTURE_DIR.glob("*.json")):
        data = run(SCORE_SCRIPT, fixture_payload(path))
        factors = {factor["factor"] for factor in data["factors"]}
        assert EXPECTED_EXPOSURE_FACTORS[path.name].issubset(factors), path.name
        if not EXPECTED_EXPOSURE_FACTORS[path.name]:
            assert factors == set(), path.name
        assert data["severity"] in {"low", "medium", "high", "critical", "error"}


def test_alias_normalization_merges_partial_canonical_discord_config():
    payload = json.dumps({
        "channels": {"discord": {"enabled": True}},
        "platforms": {"discord": {"group_policy": "all"}},
        "enabled_toolsets": ["terminal"],
        "bindings": [{"match": {"channel": "discord", "peer": {"kind": "channel"}}}],
    })
    summary = run(CONFIG_SCRIPT, payload)
    risks = {finding["risk"] for finding in summary["findings"]}
    assert "discord_group_chat_surface" in risks

    exposure = run(SCORE_SCRIPT, payload)
    factors = {factor["factor"] for factor in exposure["factors"]}
    assert "discord_group_chat_surface" in factors


def test_toolsets_alias_is_used_when_enabled_toolsets_is_empty():
    payload = json.dumps({"enabled_toolsets": [], "toolsets": ["terminal"]})
    summary = run(CONFIG_SCRIPT, payload)
    risks = {finding["risk"] for finding in summary["findings"]}
    assert "exec_or_commands_without_owner_allow_from" in risks

    exposure = run(SCORE_SCRIPT, payload)
    factors = {factor["factor"] for factor in exposure["factors"]}
    assert "exec_surface_present" in factors


def test_alias_source_locations_resolve_to_alias_lines():
    data = run(CONFIG_SCRIPT, fixture_payload(FIXTURE_DIR / "browser-agent.json"))
    finding = next(finding for finding in data["findings"] if finding["risk"] == "browser_private_network_allowed")
    assert finding["evidence_paths"] == ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork"]
    assert finding["source_locations"][0]["line"] > 1


def test_config_shape_docs_and_roadmap_are_in_sync():
    docs = (ROOT / "docs" / "config-shapes.md").read_text(encoding="utf-8")
    for fixture_name in EXPECTED_CONFIG_RISKS:
        assert fixture_name in docs
    assert "canonical fields" in docs.lower()
    assert "aliases" in docs.lower()
    assert "best-effort compatibility" in docs.lower()

    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    phase4 = roadmap.split("## Phase 4:", 1)[1].split("## Phase 5:", 1)[0]
    assert "**Status:** Shipped" in phase4
    assert "docs/config-shapes.md" in phase4
