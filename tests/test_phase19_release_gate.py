import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "verify_release_gate.py"
PACKAGER = ROOT / "scripts" / "package_skills.py"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
RELEASE_DOC = ROOT / "docs" / "release-automation.md"
INSTALL_DOC = ROOT / "docs" / "installation-and-release.md"
ROADMAP = ROOT / "docs" / "roadmap.md"
CHANGELOG = ROOT / "CHANGELOG.md"

EXPECTED_ARTIFACTS = {"agent-security.skill", "healthcheck.skill", "MANIFEST.json"}


def load_gate():
    spec = importlib.util.spec_from_file_location("phase19_gate", GATE)
    assert spec is not None and spec.loader is not None
    gate = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = gate
    spec.loader.exec_module(gate)
    return gate


def run_packager(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PACKAGER), *args],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )


def init_release_repo(path: Path) -> str:
    """Create a tiny git repo with one commit and return its HEAD SHA."""
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=path, check=True, capture_output=True, text=True)

    path.mkdir(parents=True, exist_ok=True)
    git("init", "-q")
    git("config", "user.email", "release-gate@example.com")
    git("config", "user.name", "Release Gate Test")
    (path / "placeholder.txt").write_text("release gate test\n", encoding="utf-8")
    git("add", "placeholder.txt")
    git("commit", "-q", "-m", "test commit")
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, check=True, capture_output=True, text=True).stdout.strip()


def build_dist(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    run_packager("--output-dir", str(dist))
    return dist


# --- Tag shape ---------------------------------------------------------------


def test_tag_shape_accepts_stable_semver_and_rejects_other_tags():
    gate = load_gate()
    assert gate.verify_tag_shape("v0.1.0") is None
    assert gate.verify_tag_shape("v10.20.30") is None
    for bad in ("v0.1", "0.1.0", "v0.1.0-rc1", " v0.1.0", "v0.1.0 ", "release-1", "vX.Y.Z"):
        assert gate.verify_tag_shape(bad) is not None, bad


# --- Changelog section -------------------------------------------------------


def test_changelog_check_detects_version_section(tmp_path):
    gate = load_gate()
    original = gate.CHANGELOG
    try:
        changelog = tmp_path / "CHANGELOG.md"
        gate.CHANGELOG = changelog

        changelog.write_text("# Changelog\n\n## Unreleased\n\n- something\n", encoding="utf-8")
        assert gate.verify_changelog_section("v0.2.0") is not None

        changelog.write_text("# Changelog\n\n## Unreleased\n\n- something\n\n## 0.2.0\n\n- shipped\n", encoding="utf-8")
        assert gate.verify_changelog_section("v0.2.0") is None

        changelog.write_text("# Changelog\n\n## Unreleased\n\n- something\n", encoding="utf-8")
        assert gate.verify_changelog_section("v0.2.0") is not None

        changelog.write_text("# Changelog\n\n## 0.2.0\n\n- shipped\n", encoding="utf-8")
        assert gate.verify_changelog_section("v0.2.0") is None
    finally:
        gate.CHANGELOG = original


def test_changelog_check_requires_newest_version_section_topmost(tmp_path):
    gate = load_gate()
    original = gate.CHANGELOG
    try:
        changelog = tmp_path / "CHANGELOG.md"
        gate.CHANGELOG = changelog
        changelog.write_text(
            "# Changelog\n\n## Unreleased\n\n- something\n\n## 0.2.0\n\n- newer\n\n## 0.1.0\n\n- older\n",
            encoding="utf-8",
        )
        assert gate.verify_changelog_section("v0.2.0") is None
        assert gate.verify_changelog_section("v0.1.0") is not None
    finally:
        gate.CHANGELOG = original


# --- Dist inventory, manifest, digests ----------------------------------------


def test_inventory_reports_missing_and_extra_artifacts(tmp_path):
    gate = load_gate()
    assert gate.verify_dist_inventory(tmp_path / "does-not-exist")

    dist = tmp_path / "dist"
    dist.mkdir()
    problems = gate.verify_dist_inventory(dist)
    assert len(problems) == len(EXPECTED_ARTIFACTS)

    for name in sorted(EXPECTED_ARTIFACTS):
        (dist / name).write_bytes(b"placeholder")
    assert gate.verify_dist_inventory(dist) == []

    (dist / "extra.skill").write_bytes(b"placeholder")
    problems = gate.verify_dist_inventory(dist)
    assert len(problems) == 1
    assert "extra.skill" in problems[0]


def test_manifest_validation_rejects_malformed_manifests(tmp_path):
    gate = load_gate()
    dist = tmp_path / "dist"
    dist.mkdir()
    for name in EXPECTED_ARTIFACTS:
        (dist / name).write_bytes(b"placeholder")

    (dist / "MANIFEST.json").write_text("{not json", encoding="utf-8")
    _, error = gate.load_manifest(dist)
    assert error is not None and "JSON" in error

    (dist / "MANIFEST.json").write_text(json.dumps({"schema_version": "1.0", "archives": []}), encoding="utf-8")
    _, error = gate.load_manifest(dist)
    assert error is not None and "archives" in error

    (dist / "MANIFEST.json").write_text(
        json.dumps({"schema_version": "1.0", "archives": [{"name": "someone-else"}]}),
        encoding="utf-8",
    )
    _, error = gate.load_manifest(dist)
    assert error is not None and "someone-else" in error


def test_digest_verification_detects_tampered_archives(tmp_path):
    dist = build_dist(tmp_path)
    gate = load_gate()
    manifest, error = gate.load_manifest(dist)
    assert error is None and manifest is not None
    assert gate.verify_artifact_digests(dist, manifest) == []

    tampered = dist / "agent-security.skill"
    tampered.write_bytes(tampered.read_bytes() + b"tampered")
    problems = gate.verify_artifact_digests(dist, manifest)
    assert len(problems) == 1
    assert "agent-security.skill" in problems[0]


def test_secret_scan_flags_token_shaped_artifact_content(tmp_path):
    gate = load_gate()
    dist = tmp_path / "dist"
    dist.mkdir()
    for name in ("agent-security.skill", "healthcheck.skill", "MANIFEST.json"):
        (dist / name).write_bytes(b"clean")
    assert gate.scan_artifacts_for_secrets(dist) == []

    (dist / "agent-security.skill").write_text(
        "leaked token ghp_0123456789abcdefghijklmnopqrstuvwxyzAB\n", encoding="utf-8"
    )
    problems = gate.scan_artifacts_for_secrets(dist)
    assert len(problems) == 1
    assert "secret-shaped" in problems[0]
    # Match details are never echoed into gate output.
    assert "ghp_0123456789" not in problems[0]


# --- Tag/commit binding -------------------------------------------------------


def test_tag_commit_binding_peels_annotated_tags(tmp_path, monkeypatch):
    gate = load_gate()
    head = init_release_repo(tmp_path)

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=tmp_path, capture_output=True, text=True, check=True
        ).stdout.strip()

    monkeypatch.setattr(gate, "ROOT", tmp_path)

    # Lightweight tag at HEAD binds directly.
    git("tag", "v1.2.3")
    assert gate.verify_tag_points_at_commit("v1.2.3", head) is None

    # Annotated tag object SHA also binds after peeling.
    git("tag", "-a", "v1.2.4", "-m", "annotated")
    tag_object = git("rev-parse", "v1.2.4")
    assert tag_object != head, "expected the annotated tag object SHA to differ from the commit"
    assert gate.verify_tag_points_at_commit("v1.2.4", tag_object) is None
    assert gate.verify_tag_points_at_commit("v1.2.4", head) is None

    # A tag pointing elsewhere must fail closed.
    (tmp_path / "other.txt").write_text("second commit\n", encoding="utf-8")
    git("add", "other.txt")
    git("commit", "-q", "-m", "second")
    new_head = git("rev-parse", "HEAD")
    assert gate.verify_tag_points_at_commit("v1.2.3", new_head) is not None

    # Unknown tags and commits fail closed.
    assert gate.verify_tag_points_at_commit("v9.9.9", head) is not None
    assert gate.verify_tag_points_at_commit("v1.2.3", "not-a-commit") is not None


# --- End-to-end gate ----------------------------------------------------------


def test_gate_passes_for_clean_tagged_release(tmp_path, monkeypatch):
    gate = load_gate()
    repo = tmp_path / "repo"
    init_release_repo(repo)

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()

    git("tag", "-a", "v0.2.0", "-m", "release v0.2.0")
    dist = build_dist(tmp_path)

    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## 0.2.0\n\n- shipped\n", encoding="utf-8")

    monkeypatch.setattr(gate, "ROOT", repo)
    monkeypatch.setattr(gate, "CHANGELOG", changelog)
    rc = gate.main(["v0.2.0", "--dist-dir", str(dist), "--commit", git("rev-parse", "v0.2.0")])
    assert rc == 0


def test_gate_blocks_when_changelog_or_artifacts_are_wrong(tmp_path, monkeypatch, capsys):
    gate = load_gate()
    repo = tmp_path / "repo"
    init_release_repo(repo)

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()

    git("tag", "v0.2.0")
    dist = build_dist(tmp_path)
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## Unreleased\n\n- not released yet\n", encoding="utf-8")

    monkeypatch.setattr(gate, "ROOT", repo)
    monkeypatch.setattr(gate, "CHANGELOG", changelog)

    # Missing changelog section blocks the release.
    rc = gate.main(["v0.2.0", "--dist-dir", str(dist), "--skip-packager-check"])
    assert rc == 1
    assert "CHANGELOG.md has no '## 0.2.0' section" in capsys.readouterr().err

    # A tampered archive blocks the release via digest mismatch.
    changelog.write_text("# Changelog\n\n## 0.2.0\n\n- shipped\n", encoding="utf-8")
    tampered = dist / "healthcheck.skill"
    tampered.write_bytes(b"tampered")
    rc = gate.main(["v0.2.0", "--dist-dir", str(dist), "--skip-packager-check"])
    assert rc == 1
    assert "does not match manifest sha256" in capsys.readouterr().err

    # Invalid tag shape is a hard block regardless of other inputs.
    rc = gate.main(["0.2.0", "--dist-dir", str(dist), "--skip-packager-check"])
    assert rc == 1
    assert "not a stable semantic tag" in capsys.readouterr().err


def test_gate_runs_packager_check_by_default_and_detects_drift(tmp_path, monkeypatch, capsys):
    gate = load_gate()
    repo = tmp_path / "repo"
    init_release_repo(repo)

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=repo, capture_output=True, text=True, check=True
        ).stdout.strip()

    git("tag", "v0.2.0")
    dist = build_dist(tmp_path)
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## 0.2.0\n\n- shipped\n", encoding="utf-8")
    monkeypatch.setattr(gate, "ROOT", repo)
    monkeypatch.setattr(gate, "CHANGELOG", changelog)

    # An extra artifact is both an inventory problem and packager drift.
    (dist / "stale-extra.skill").write_bytes(b"stale")
    rc = gate.main(["v0.2.0", "--dist-dir", str(dist)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "stale-extra.skill" in err


# --- Workflow and documentation shape -----------------------------------------


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected Phase 19 artifact: {path.relative_to(ROOT)}"
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n"), f"{path.relative_to(ROOT)} should end with a newline"
    return text


def test_release_workflow_is_tag_gated_and_least_privilege():
    text = _read(RELEASE_WORKFLOW)
    assert "tags:" in text
    assert '"v*.*.*"' in text
    assert "on:" in text
    assert "pull_request" not in text
    assert "pull-requests:" not in text
    assert "issues:" not in text
    assert "permissions:" in text
    assert "contents: write" in text
    assert "attestations: write" in text
    assert "id-token: write" in text
    assert "persist-credentials: false" in text
    assert "actions/checkout@v7" in text
    assert "actions/setup-python@v7" in text
    assert "actions/attest-build-provenance@v4" in text
    assert "verify_release_gate.py" in text
    assert "GITHUB_REF_NAME" in text
    assert "--verify-tag" in text
    assert "dist/agent-security.skill" in text
    assert "dist/healthcheck.skill" in text
    assert "dist/MANIFEST.json" in text


def test_release_docs_and_roadmap_coverage():
    doc = _read(RELEASE_DOC)
    for phrase in (
        "verify_release_gate.py",
        "annotated tag",
        "gh release",
        "attest",
        "MANIFEST.json",
        "does not grant",
        "fail",
    ):
        assert phrase in doc, phrase

    install = _read(INSTALL_DOC)
    assert "release-automation.md" in install

    roadmap = _read(ROADMAP)
    assert "## Phase 19: Tagged release automation and attestations" in roadmap
    assert "**Status:** Shipped" in roadmap

    changelog = _read(CHANGELOG)
    assert "verify_release_gate.py" in changelog
    assert "release.yml" in changelog
