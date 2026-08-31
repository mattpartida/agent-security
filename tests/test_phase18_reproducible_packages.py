import hashlib
import importlib.util
import json
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGER = ROOT / "scripts" / "package_skills.py"
README = ROOT / "README.md"
ROADMAP = ROOT / "docs" / "roadmap.md"
CHANGELOG = ROOT / "CHANGELOG.md"

PUBLISHED_SKILLS = ("agent-security", "healthcheck")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def load_packager():
    spec = importlib.util.spec_from_file_location("phase18_packager", PACKAGER)
    assert spec is not None and spec.loader is not None
    packager = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = packager
    spec.loader.exec_module(packager)
    return packager


def source_digest(skill: str, members: list[tuple[str, bytes, int]]) -> str:
    digest = hashlib.sha256()
    for relative, data, mode in members:
        member = f"{skill}/{relative}".encode()
        digest.update(len(member).to_bytes(8, "big"))
        digest.update(member)
        digest.update(mode.to_bytes(4, "big"))
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def run_packager(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PACKAGER), *args],
        cwd=ROOT,
        check=check,
        text=True,
        capture_output=True,
    )


def test_repeated_builds_are_byte_for_byte_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"

    run_packager("--output-dir", str(first))
    run_packager("--output-dir", str(second))

    expected = {"MANIFEST.json", *(f"{name}.skill" for name in PUBLISHED_SKILLS)}
    assert {path.name for path in first.iterdir()} == expected
    assert {path.name for path in second.iterdir()} == expected
    for name in expected:
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_manifest_and_archives_match_authoritative_sources(tmp_path: Path) -> None:
    output = tmp_path / "dist"
    run_packager("--output-dir", str(output))
    manifest = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))

    assert manifest["schema_version"] == "1.0"
    assert manifest["generated_from"] == "skills/"
    entries = manifest["archives"]
    assert [entry["name"] for entry in entries] == sorted(PUBLISHED_SKILLS)

    for entry in entries:
        skill = entry["name"]
        archive = output / f"{skill}.skill"
        assert entry["source_path"] == f"skills/{skill}"
        assert entry["archive_path"] == f"dist/{skill}.skill"
        assert entry["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
        assert SHA256.fullmatch(entry["sha256"])
        assert SHA256.fullmatch(entry["source_sha256"])

        source_root = ROOT / "skills" / skill
        source_files = sorted(
            path
            for path in source_root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
            and path.name != ".DS_Store"
        )
        with zipfile.ZipFile(archive) as packaged:
            assert packaged.testzip() is None
            members = packaged.infolist()
            assert entry["file_count"] == len(source_files) == len(members)
            assert [member.filename for member in members] == sorted(member.filename for member in members)
            digest_members = []
            for member, source in zip(members, source_files, strict=True):
                path = PurePosixPath(member.filename)
                assert not path.is_absolute()
                assert ".." not in path.parts
                assert "__pycache__" not in path.parts
                assert path.suffix not in {".pyc", ".pyo"}
                assert member.date_time == (1980, 1, 1, 0, 0, 0)
                assert member.filename == f"{skill}/{source.relative_to(source_root).as_posix()}"
                assert packaged.read(member) == source.read_bytes()
                expected_mode = 0o755 if source.stat().st_mode & stat.S_IXUSR else 0o644
                assert (member.external_attr >> 16) == stat.S_IFREG | expected_mode
                digest_members.append(
                    (source.relative_to(source_root).as_posix(), source.read_bytes(), expected_mode)
                )
            assert entry["source_sha256"] == source_digest(skill, digest_members)


def test_check_mode_detects_archive_drift_without_rewriting(tmp_path: Path) -> None:
    output = tmp_path / "dist"
    run_packager("--output-dir", str(output))
    before = {path.name: path.read_bytes() for path in output.iterdir()}

    checked = run_packager("--output-dir", str(output), "--check")
    assert "release artifacts are current" in checked.stdout.lower()
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before

    archive = output / "agent-security.skill"
    archive.write_bytes(archive.read_bytes() + b"tampered")
    tampered = archive.read_bytes()
    failed = run_packager("--output-dir", str(output), "--check", check=False)
    assert failed.returncode == 1
    assert "agent-security.skill" in failed.stderr
    assert archive.read_bytes() == tampered

    run_packager("--output-dir", str(output))
    outside = tmp_path / "outside.skill"
    outside.write_bytes(b"outside")
    archive.unlink()
    archive.symlink_to(outside)
    failed_link = run_packager("--output-dir", str(output), "--check", check=False)
    assert failed_link.returncode == 1
    assert "agent-security.skill" in failed_link.stderr
    assert outside.read_bytes() == b"outside"
    assert archive.is_symlink()


def test_packager_rejects_symlinked_source_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    packager = load_packager()

    skills_root = tmp_path / "skills"
    source_root = skills_root / "agent-security"
    source_root.mkdir(parents=True)
    (source_root / "SKILL.md").write_text("---\nname: agent-security\n---\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("must not be packaged\n", encoding="utf-8")
    (source_root / "linked.txt").symlink_to(outside)
    monkeypatch.setattr(packager, "SKILLS_ROOT", skills_root)

    with pytest.raises(ValueError, match="symlinked source"):
        packager._source_files("agent-security")


def test_packager_rejects_symlinked_skill_root_and_skills_ancestry(tmp_path: Path) -> None:
    packager = load_packager()
    real_skills = tmp_path / "real-skills"
    real_source = real_skills / "agent-security"
    real_source.mkdir(parents=True)
    (real_source / "SKILL.md").write_text("source\n", encoding="utf-8")

    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_source, target_is_directory=True)
    packager.SKILLS_ROOT = tmp_path
    with pytest.raises(ValueError, match="symlinked source"):
        packager._snapshot_skill("linked-root")

    linked_skills = tmp_path / "linked-skills"
    linked_skills.symlink_to(real_skills, target_is_directory=True)
    packager.SKILLS_ROOT = linked_skills
    with pytest.raises(ValueError, match="symlinked source"):
        packager._snapshot_skill("agent-security")


@pytest.mark.parametrize(
    "name",
    [
        r"skill\\payload.py",
        "/skill/payload.py",
        r"C:\\skill\\payload.py",
        "C:payload.py",
        "skill/C:payload.py",
        "skill/./payload.py",
        "skill/../payload.py",
        "skill/\x00payload.py",
        "skill/\udcffpayload.py",
        "skill/CON",
        "skill/con.txt",
        "skill/AUX.json",
        "skill/NUL",
        "skill/COM1.md",
        "skill/LPT9",
        "skill/trailing.",
        "skill/trailing ",
        "skill/bad?.txt",
        "skill/bad*.txt",
        "skill/bad<name>.txt",
        "skill/bad|name.txt",
        "skill/bidi-\u202e.py",
        "skill/e\u0301.txt",
    ],
)
def test_archive_member_names_reject_cross_platform_ambiguity(name: str) -> None:
    packager = load_packager()
    with pytest.raises(ValueError, match="unsafe archive member"):
        packager._validate_member_name(name)


@pytest.mark.parametrize(
    "names",
    [
        ["skill/A.txt", "skill/a.txt"],
        ["skill/Straße.txt", "skill/STRASSE.txt"],
        ["skill/é.txt", "skill/e\u0301.txt"],
    ],
)
def test_archive_inventory_rejects_portable_name_collisions(names: list[str]) -> None:
    packager = load_packager()
    with pytest.raises(ValueError, match="archive member collision|unsafe archive member"):
        packager._validate_member_inventory(names)


def test_snapshot_is_used_for_both_archive_and_source_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packager = load_packager()
    skills_root = tmp_path / "skills"
    source_root = skills_root / "demo"
    source_root.mkdir(parents=True)
    source = source_root / "SKILL.md"
    source.write_bytes(b"before\n")
    source.chmod(0o644)
    packager.SKILLS_ROOT = skills_root
    packager.PUBLISHED_SKILLS = ("demo",)
    output = tmp_path / "dist"

    original_archive_bytes = packager._archive_bytes

    def mutate_after_snapshot(snapshot):
        source.write_bytes(b"after\n")
        source.chmod(0o755)
        return original_archive_bytes(snapshot)

    monkeypatch.setattr(packager, "_archive_bytes", mutate_after_snapshot)
    packager.build(output)

    manifest = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    with zipfile.ZipFile(output / "demo.skill") as archive:
        info = archive.getinfo("demo/SKILL.md")
        assert archive.read(info) == b"before\n"
        assert (info.external_attr >> 16) == stat.S_IFREG | 0o644
    assert manifest["archives"][0]["source_sha256"] == source_digest(
        "demo", [("SKILL.md", b"before\n", 0o644)]
    )


def test_snapshot_excludes_cache_files(tmp_path: Path) -> None:
    packager = load_packager()
    source_root = tmp_path / "skills" / "demo"
    (source_root / "__pycache__").mkdir(parents=True)
    (source_root / "SKILL.md").write_text("demo\n", encoding="utf-8")
    (source_root / "module.pyc").write_bytes(b"cache")
    (source_root / ".DS_Store").write_bytes(b"metadata")
    (source_root / "__pycache__" / "module.py").write_bytes(b"cache")
    packager.SKILLS_ROOT = tmp_path / "skills"

    snapshot = packager._snapshot_skill("demo")

    assert [member.relative_path for member in snapshot.members] == ["SKILL.md"]


def test_build_rejects_output_root_and_destination_symlinks(tmp_path: Path) -> None:
    output_target = tmp_path / "outside-dir"
    output_target.mkdir()
    output_link = tmp_path / "dist-link"
    output_link.symlink_to(output_target, target_is_directory=True)
    failed_root = run_packager("--output-dir", str(output_link), check=False)
    assert failed_root.returncode == 2
    assert not list(output_target.iterdir())

    output = tmp_path / "dist"
    output.mkdir()
    outside = tmp_path / "outside.skill"
    outside.write_bytes(b"outside")
    (output / "agent-security.skill").symlink_to(outside)
    failed_leaf = run_packager("--output-dir", str(output), check=False)
    assert failed_leaf.returncode == 2
    assert outside.read_bytes() == b"outside"
    assert (output / "agent-security.skill").is_symlink()

    non_directory_root = tmp_path / "dist-file"
    non_directory_root.write_bytes(b"not a directory")
    failed_non_directory = run_packager("--output-dir", str(non_directory_root), check=False)
    assert failed_non_directory.returncode == 2
    assert non_directory_root.read_bytes() == b"not a directory"

    destination_directory = tmp_path / "dist-directory-leaf"
    destination_directory.mkdir()
    (destination_directory / "agent-security.skill").mkdir()
    failed_destination_directory = run_packager(
        "--output-dir", str(destination_directory), check=False
    )
    assert failed_destination_directory.returncode == 2
    assert (destination_directory / "agent-security.skill").is_dir()


@pytest.mark.parametrize("extra_kind", ["zip", "skill", "directory", "symlink"])
def test_check_rejects_exact_inventory_extras_without_following(
    tmp_path: Path, extra_kind: str
) -> None:
    output = tmp_path / "dist"
    run_packager("--output-dir", str(output))
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    extra_names = {"zip": "stale.zip", "skill": "stale.skill"}
    extra = output / extra_names.get(extra_kind, "unexpected")
    if extra_kind in {"zip", "skill"}:
        extra.write_bytes(b"stale")
    elif extra_kind == "directory":
        extra.mkdir()
    else:
        extra.symlink_to(outside)

    failed = run_packager("--output-dir", str(output), "--check", check=False)

    assert failed.returncode == 1
    assert extra.name in failed.stderr
    assert outside.read_bytes() == b"outside"
    if extra_kind == "symlink":
        assert extra.is_symlink()


def test_publication_failure_restores_complete_previous_artifact_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packager = load_packager()
    source_root = tmp_path / "skills" / "demo"
    source_root.mkdir(parents=True)
    source = source_root / "SKILL.md"
    source.write_bytes(b"old\n")
    packager.SKILLS_ROOT = tmp_path / "skills"
    packager.PUBLISHED_SKILLS = ("demo",)
    output = tmp_path / "dist"
    packager.build(output)
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    source.write_bytes(b"new\n")

    real_replace = packager.os.replace
    publications = 0

    def fail_second_publication(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        nonlocal publications
        if dst in {"demo.skill", "MANIFEST.json"} and src_dir_fd != dst_dir_fd:
            publications += 1
            if publications == 2:
                raise OSError("injected publication failure")
        return real_replace(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(packager.os, "replace", fail_second_publication)
    with pytest.raises(OSError, match="injected publication failure"):
        packager.build(output)

    assert {path.name: path.read_bytes() for path in output.iterdir()} == before
    assert sorted(path.name for path in tmp_path.iterdir()) == ["dist", "skills"]


def test_phase18_release_integrity_is_documented() -> None:
    readme = README.read_text(encoding="utf-8")
    roadmap = ROADMAP.read_text(encoding="utf-8")
    changelog = CHANGELOG.read_text(encoding="utf-8")
    release_guide = (ROOT / "docs" / "installation-and-release.md").read_text(encoding="utf-8")

    assert "python3 scripts/package_skills.py --check" in readme
    assert "dist/MANIFEST.json" in readme
    assert "## Phase 18: Reproducible skill archives and release manifests" in roadmap
    phase = roadmap.split("## Phase 18:", 1)[1].split("## Phase 19:", 1)[0]
    assert "**Status:** Shipped" in phase
    assert "tests/test_phase18_reproducible_packages.py" in phase
    assert "reproducible" in changelog.lower()
    assert "manifest" in changelog.lower()
    assert "exact artifact inventory" in release_guide
    assert "rolls back the complete pre-build artifact set" in release_guide
    assert "process interruption or power loss" in release_guide
    assert "POSIX-only" in release_guide
    assert "fixed Python and zlib toolchain" in release_guide
