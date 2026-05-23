import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SKILLS_README = ROOT / "skills" / "README.md"
BOUNDARY_DOC = ROOT / "docs" / "skill-boundary.md"
COMBINED_REPORT = ROOT / "examples" / "reports" / "combined-browser-private-network-boundary.md"
AGENT_SKILL = ROOT / "skills" / "agent-security" / "SKILL.md"
HEALTHCHECK_SKILL = ROOT / "skills" / "healthcheck" / "SKILL.md"
ROADMAP = ROOT / "docs" / "roadmap.md"


def _read(path: Path) -> str:
    assert path.exists(), f"missing Phase 8 artifact: {path.relative_to(ROOT)}"
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n"), f"{path.relative_to(ROOT)} should end with newline"
    return text


def _table_rows(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("| ")]


def test_skill_decision_tables_exist_in_root_and_skills_readmes() -> None:
    for path in (README, SKILLS_README):
        text = _read(path)
        assert "## Which skill should I use?" in text
        rows = _table_rows(text)
        joined = "\n".join(rows)
        assert "Agent runtime / tool permissions" in joined
        assert "Host OS / network exposure" in joined
        assert "Use both" in joined
        assert "browser private-network" in joined
        assert "SSRF" in joined
        assert "cron" in joined
        assert "rollback" in joined
        assert "docs/skill-boundary.md" in text or "../docs/skill-boundary.md" in text


def test_boundary_doc_assigns_shared_concept_ownership_without_conflicts() -> None:
    doc = _read(BOUNDARY_DOC)
    required_sections = [
        "## Ownership model",
        "## Shared-concept ownership",
        "## Cross-skill handoff rules",
        "## Combined-review example",
        "## Non-duplication rules",
    ]
    for section in required_sections:
        assert section in doc

    ownership_expectations = {
        "SSRF": "agent-security owns browser policy",
        "exposed services": "healthcheck owns listening services",
        "cron": "agent-security owns agent scheduled jobs",
        "rollback": "healthcheck owns host rollback",
    }
    for concept, phrase in ownership_expectations.items():
        assert concept in doc
        assert phrase in doc

    forbidden_conflicts = [
        "healthcheck owns ASG-",
        "healthcheck assigns ASG-",
        "agent-security owns firewall policy",
        "agent-security owns SSH hardening",
    ]
    lowered = doc.lower()
    for phrase in forbidden_conflicts:
        assert phrase.lower() not in lowered


def test_skill_cross_links_and_combined_report_are_present() -> None:
    agent_skill = _read(AGENT_SKILL)
    health_skill = _read(HEALTHCHECK_SKILL)
    report = _read(COMBINED_REPORT)

    assert "docs/skill-boundary.md" in agent_skill
    assert "ASG-002" in agent_skill and "ASG-006" in agent_skill
    assert "healthcheck" in agent_skill

    assert "docs/skill-boundary.md" in health_skill
    assert "agent-security" in health_skill
    assert "Do not duplicate `ASG-###`" in health_skill

    required_report_phrases = [
        "Combined browser private-network boundary review",
        "Agent-security findings",
        "Healthcheck findings",
        "ASG-002",
        "ASG-006",
        "Private-network browser access",
        "Host network exposure",
        "Ownership split",
    ]
    for phrase in required_report_phrases:
        assert phrase in report


def test_phase8_roadmap_is_marked_shipped_and_links_are_valid() -> None:
    roadmap = _read(ROADMAP)
    assert "## Phase 8: Healthcheck and agent-security boundary cleanup" in roadmap
    assert "**Status:** Shipped" in roadmap
    assert "docs/skill-boundary.md" in roadmap
    assert "combined-browser-private-network-boundary.md" in roadmap
    assert "tests/test_phase8_skill_boundary.py" in roadmap

    # Dependency-light markdown link check for touched docs.
    docs_to_check = [README, SKILLS_README, BOUNDARY_DOC, AGENT_SKILL, HEALTHCHECK_SKILL, ROADMAP]
    link_re = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in docs_to_check:
        for target in link_re.findall(path.read_text(encoding="utf-8")):
            if target.startswith(("http://", "https://", "#")):
                continue
            clean_target = target.split("#", 1)[0]
            if not clean_target:
                continue
            resolved = (path.parent / clean_target).resolve()
            assert resolved.exists(), f"broken link in {path.relative_to(ROOT)}: {target}"
