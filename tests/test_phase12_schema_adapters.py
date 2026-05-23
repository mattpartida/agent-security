import json
import subprocess
import sys
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parents[1]
CONFIG_SCRIPT = ROOT / "skills" / "agent-security" / "scripts" / "config_risk_summary.py"
FIXTURE_DIR = ROOT / "examples" / "schema-adapters"
PHASE12_DOC = ROOT / "docs" / "schema-adapters.md"

EXPECTED = {
    "openai-tools-risky.json": ("openai_tools", {"exec_or_commands_without_owner_allow_from", "risky_default_model"}),
    "openai-tools-safe.json": ("openai_tools", set()),
    "claude-desktop-mcp-risky.json": ("claude_desktop_mcp", {"exec_or_commands_without_owner_allow_from", "filesystem_not_workspace_only"}),
    "claude-desktop-mcp-safe.json": ("claude_desktop_mcp", set()),
    "github-actions-risky.json": ("github_actions", {"exec_or_commands_without_owner_allow_from"}),
    "github-actions-safe.json": ("github_actions", set()),
}


def run_config(payload: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [sys.executable, str(CONFIG_SCRIPT), *args],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    if check:
        assert proc.returncode == 0, proc.stderr
    return proc


def load_json(path: Path, *args: str) -> dict:
    proc = run_config(path.read_text(encoding="utf-8"), *args)
    return json.loads(proc.stdout)


def test_phase12_schema_adapter_fixtures_report_adapter_and_findings():
    actual = {path.name for path in FIXTURE_DIR.glob("*.json")}
    assert actual == set(EXPECTED)

    for path in sorted(FIXTURE_DIR.glob("*.json")):
        expected_adapter, expected_risks = EXPECTED[path.name]
        data = load_json(path)
        assert data["schema"]["adapter"] == expected_adapter, path.name
        risks = {finding["risk"] for finding in data["findings"]}
        assert expected_risks.issubset(risks), path.name
        if not expected_risks:
            assert risks == set(), path.name
        assert all(finding.get("schema", {}).get("adapter") == expected_adapter for finding in data["findings"])


def test_phase12_adapter_is_reported_in_markdown_and_sarif_properties():
    payload = (FIXTURE_DIR / "openai-tools-risky.json").read_text(encoding="utf-8")

    markdown = run_config(payload, "--format", "markdown").stdout
    assert "**Schema adapter:** openai_tools" in markdown

    sarif = json.loads(run_config(payload, "--format", "sarif").stdout)
    run = sarif["runs"][0]
    assert run["properties"]["schema_adapter"] == "openai_tools"
    assert run["results"]
    assert {result["properties"]["schema_adapter"] for result in run["results"]} == {"openai_tools"}


def test_phase12_path_serialization_is_platform_stable():
    sys.path.insert(0, str(CONFIG_SCRIPT.parent))
    try:
        import config_risk_summary

        assert config_risk_summary.report_path_uri(PureWindowsPath("examples", "schema-adapters", "openai-tools-risky.json")) == "examples/schema-adapters/openai-tools-risky.json"
        assert config_risk_summary.report_path_uri(Path("examples/schema-adapters/openai-tools-risky.json")) == "examples/schema-adapters/openai-tools-risky.json"
    finally:
        sys.path.pop(0)


def test_phase12_docs_roadmap_and_changelog_are_in_sync():
    docs = PHASE12_DOC.read_text(encoding="utf-8")
    for fixture_name, (adapter, _) in EXPECTED.items():
        assert fixture_name in docs
        assert adapter in docs
    assert "Unsupported fields" in docs
    assert "Report stability" in docs
    assert "non-executable" in docs

    roadmap = (ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    phase12 = roadmap.split("## Phase 12:", 1)[1].split("## Implementation order", 1)[0]
    assert "**Status:** Shipped" in phase12
    assert "tests/test_phase12_schema_adapters.py" in phase12

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "Phase 12 schema adapter" in changelog
