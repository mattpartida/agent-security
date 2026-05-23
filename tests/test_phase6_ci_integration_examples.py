from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / "examples" / "ci" / "github-actions"
STRICT_WORKFLOW = WORKFLOW_DIR / "agent-security-strict.yml"
SARIF_WORKFLOW = WORKFLOW_DIR / "agent-security-sarif.yml"
INTEGRATION_DOC = ROOT / "docs" / "ci-integration.md"
README = ROOT / "README.md"
ROADMAP = ROOT / "docs" / "roadmap.md"


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected Phase 6 artifact: {path.relative_to(ROOT)}"
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n"), f"{path.relative_to(ROOT)} should end with a newline"
    return text


def _assert_basic_yaml_shape(text: str) -> None:
    """Dependency-free guard for the workflow examples' YAML shape.

    The repo intentionally has no YAML dependency. This catches the common
    syntax mistakes that would make GitHub Actions examples unusable: tabs,
    odd indentation, missing mapping separators, and list entries without a
    nested mapping or scalar.
    """
    stack = [0]
    block_scalar_indent: int | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        assert "\t" not in line, f"line {lineno} uses a tab"
        indent = len(line) - len(line.lstrip(" "))
        assert indent % 2 == 0, f"line {lineno} indentation is not a multiple of two"
        if block_scalar_indent is not None:
            if indent >= block_scalar_indent:
                continue
            block_scalar_indent = None
        stripped = line.strip()
        assert stripped.startswith("-") or ":" in stripped, f"line {lineno} is not a YAML mapping/list item"
        while stack and indent < stack[-1]:
            stack.pop()
        assert stack, f"line {lineno} indentation underflow"
        if indent > stack[-1]:
            assert indent == stack[-1] + 2, f"line {lineno} jumps more than one level"
            stack.append(indent)
        if stripped.endswith(": |") or stripped.endswith(": >"):
            block_scalar_indent = indent + 2


def test_github_actions_examples_are_safe_and_parseable() -> None:
    strict = _read(STRICT_WORKFLOW)
    sarif = _read(SARIF_WORKFLOW)
    for text in (strict, sarif):
        _assert_basic_yaml_shape(text)
        assert "python3 skills/agent-security/scripts/config_risk_summary.py" in text
        assert "--strict" in text or "--fail-on high" in text
        assert "permissions:" in text
        assert "contents: read" in text
        assert "pull-requests: write" not in text
        assert "issues: write" not in text
        assert "actions: write" not in text
        assert "contents: write" not in text

    assert "security-events: write" not in strict
    assert "github/codeql-action/upload-sarif@v4" not in strict
    assert "security-events: write" in sarif
    assert "github/codeql-action/upload-sarif@v4" in sarif
    assert "agent-security.sarif" in sarif


def test_integration_docs_cover_ci_pr_comments_scheduled_audits_and_failure_modes() -> None:
    doc = _read(INTEGRATION_DOC)
    required_phrases = [
        "Strict config scanning",
        "Optional SARIF upload",
        "PR comment markdown",
        "Scheduled audits",
        "Local preflight checks",
        "Minimal permissions",
        "security-events: write",
        "High or critical findings should block merges",
    ]
    for phrase in required_phrases:
        assert phrase in doc
    assert "pull-requests: write" in doc
    assert "only when posting PR comments" in doc


def test_readme_and_roadmap_point_to_integration_examples() -> None:
    readme = _read(README)
    roadmap = _read(ROADMAP)
    assert "docs/ci-integration.md" in readme
    assert "examples/ci/github-actions" in readme
    assert "## Phase 6: CI and downstream integration examples" in roadmap
    assert "**Status:** Shipped" in roadmap
    assert "agent-security-strict.yml" in roadmap
    assert "agent-security-sarif.yml" in roadmap
