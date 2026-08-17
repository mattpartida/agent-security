from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
WORKFLOW_DIR = ROOT / "examples" / "ci" / "github-actions"
WORKFLOW_EXAMPLES = sorted(WORKFLOW_DIR.glob("*.yml"))
CHANGELOG = ROOT / "CHANGELOG.md"
CI_DOC = ROOT / "docs" / "ci-integration.md"

# First-party action major versions that run on the node24 runtime.
# actions/checkout v4 and actions/setup-python v5 run on node20, which
# GitHub Actions flags with node-deprecation annotations as node24
# becomes the required runtime. Keep the repo workflow and the copyable
# downstream examples on node24-compatible majors.
NODE24_ACTIONS = {
    "actions/checkout": "v7",
    "actions/setup-python": "v7",
}

# Third-party actions allowed in workflows; codeql-action's current major
# already targets modern node runtimes and is validated separately.
ALLOWED_ACTIONS = {
    "actions/checkout",
    "actions/setup-python",
    "github/codeql-action/upload-sarif",
}

# Stale node20-era majors that must not reappear in runnable workflows.
STALE_ACTION_REFS = [
    "actions/checkout@v1",
    "actions/checkout@v2",
    "actions/checkout@v3",
    "actions/checkout@v4",
    "actions/setup-python@v1",
    "actions/setup-python@v2",
    "actions/setup-python@v3",
    "actions/setup-python@v4",
    "actions/setup-python@v5",
]


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected CI artifact: {path.relative_to(ROOT)}"
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n"), f"{path.relative_to(ROOT)} should end with a newline"
    return text


def _action_refs(text: str) -> list:
    """Return every `uses:` reference in a workflow body."""
    refs = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- uses:") or stripped.startswith("uses:"):
            ref = stripped.split("uses:", 1)[1].strip().strip("'\"")
            refs.append(ref)
    return refs


def test_ci_workflow_and_examples_use_node24_first_party_actions() -> None:
    paths = [CI_WORKFLOW, *WORKFLOW_EXAMPLES]
    assert WORKFLOW_EXAMPLES, "expected workflow examples under examples/ci/github-actions"
    for path in paths:
        text = _read(path)
        refs = _action_refs(text)
        assert refs, f"{path.relative_to(ROOT)} uses no actions"
        for ref in refs:
            owner_repo, _, version = ref.partition("@")
            assert owner_repo in ALLOWED_ACTIONS, (
                f"{path.relative_to(ROOT)} references unexpected action {owner_repo}"
            )
            if owner_repo in NODE24_ACTIONS:
                assert version == NODE24_ACTIONS[owner_repo], (
                    f"{path.relative_to(ROOT)} should use {owner_repo}@{NODE24_ACTIONS[owner_repo]} "
                    f"(node24 runtime), found {ref}"
                )


def test_no_stale_node20_action_majors_in_runnable_workflows() -> None:
    """Guard against stale node20-era majors creeping back into runnable workflows."""
    scan_targets = [CI_WORKFLOW, *WORKFLOW_EXAMPLES]
    for path in scan_targets:
        text = _read(path)
        for stale in STALE_ACTION_REFS:
            assert stale not in text, f"{path.relative_to(ROOT)} still references {stale}"


def test_changelog_and_ci_docs_note_the_node24_actions_upgrade() -> None:
    changelog = _read(CHANGELOG)
    doc = _read(CI_DOC)
    assert "actions/checkout@v7" in changelog
    assert "actions/setup-python@v7" in changelog
    assert "node24" in doc
    assert "actions/checkout@v7" in doc
    assert "actions/setup-python@v7" in doc
