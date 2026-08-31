#!/usr/bin/env python3
"""Build reproducible, source-authoritative AgentSkills archives."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = ROOT / "skills"
DEFAULT_OUTPUT = ROOT / "dist"
PUBLISHED_SKILLS = ("agent-security", "healthcheck")
MANIFEST_NAME = "MANIFEST.json"
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
EXCLUDED_NAMES = {".DS_Store"}
WINDOWS_ILLEGAL_CHARACTERS = frozenset('<>:"\\|?*')
WINDOWS_RESERVED_BASENAMES = frozenset({"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"})
WINDOWS_RESERVED_PATTERN = re.compile(r"^(?:COM|LPT)[1-9]$")
_OPEN_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_OPEN_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True)
class SnapshotMember:
    relative_path: str
    data: bytes
    mode: int


@dataclass(frozen=True)
class SkillSnapshot:
    name: str
    members: tuple[SnapshotMember, ...]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unsafe_member(name: str) -> ValueError:
    return ValueError(f"unsafe archive member name: {name!r}")


def _validate_member_name(name: str) -> None:
    """Reject names that different ZIP consumers could interpret differently."""
    try:
        name.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise _unsafe_member(name) from exc
    if not name or name.startswith("/") or "\\" in name:
        raise _unsafe_member(name)
    if unicodedata.normalize("NFC", name) != name:
        raise _unsafe_member(name)
    parts = name.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise _unsafe_member(name)
    for part in parts:
        if part.endswith((" ", ".")):
            raise _unsafe_member(name)
        if any(character in WINDOWS_ILLEGAL_CHARACTERS for character in part):
            raise _unsafe_member(name)
        if any(unicodedata.category(character).startswith("C") for character in part):
            raise _unsafe_member(name)
        basename = part.split(".", 1)[0].upper()
        if basename in WINDOWS_RESERVED_BASENAMES or WINDOWS_RESERVED_PATTERN.fullmatch(basename):
            raise _unsafe_member(name)


def _validate_member_inventory(names: list[str]) -> None:
    seen: dict[str, str] = {}
    for name in names:
        _validate_member_name(name)
        portable_key = unicodedata.normalize("NFC", name).casefold()
        previous = seen.get(portable_key)
        if previous is not None:
            raise ValueError(f"archive member collision: {previous!r} and {name!r}")
        seen[portable_key] = name


def _reject_symlink_ancestry(path: Path, label: str) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            break
        if stat.S_ISLNK(mode):
            raise ValueError(f"refusing to use symlinked {label}: {current}")


def _read_snapshot_file(parent_fd: int, name: str, display: str) -> tuple[bytes, int]:
    descriptor = os.open(name, _OPEN_FILE_FLAGS, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"refusing to package non-regular source: skills/{display}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode")
        if any(getattr(before, field) != getattr(after, field) for field in identity):
            raise ValueError(f"source changed while snapshotting: skills/{display}")
        mode = 0o755 if before.st_mode & stat.S_IXUSR else 0o644
        return b"".join(chunks), mode
    finally:
        os.close(descriptor)


def _snapshot_skill(skill: str) -> SkillSnapshot:
    _validate_member_name(skill)
    source_root = SKILLS_ROOT / skill
    _reject_symlink_ancestry(SKILLS_ROOT, "source ancestry")
    _reject_symlink_ancestry(source_root, "source")
    try:
        root_fd = os.open(source_root, _OPEN_DIRECTORY_FLAGS)
    except OSError as exc:
        raise ValueError(f"published skill source is incomplete: skills/{skill}") from exc

    members: list[SnapshotMember] = []

    def walk(directory_fd: int, prefix: str = "") -> None:
        for name in sorted(os.listdir(directory_fd)):
            relative = f"{prefix}/{name}" if prefix else name
            member_name = f"{skill}/{relative}"
            _validate_member_name(member_name)
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"refusing to package symlinked source: skills/{skill}/{relative}")
            if stat.S_ISDIR(metadata.st_mode):
                if name == "__pycache__":
                    continue
                child_fd = os.open(name, _OPEN_DIRECTORY_FLAGS, dir_fd=directory_fd)
                try:
                    walk(child_fd, relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(metadata.st_mode):
                suffix = Path(name).suffix
                if suffix in EXCLUDED_SUFFIXES or name in EXCLUDED_NAMES:
                    continue
                data, mode = _read_snapshot_file(directory_fd, name, f"{skill}/{relative}")
                members.append(SnapshotMember(relative, data, mode))
            else:
                raise ValueError(f"refusing to package non-regular source: skills/{skill}/{relative}")

    try:
        walk(root_fd)
    finally:
        os.close(root_fd)

    members.sort(key=lambda member: member.relative_path)
    if not any(member.relative_path == "SKILL.md" for member in members):
        raise ValueError(f"published skill source is incomplete: skills/{skill}")
    _validate_member_inventory([f"{skill}/{member.relative_path}" for member in members])
    return SkillSnapshot(skill, tuple(members))


def _source_files(skill: str) -> list[Path]:
    """Compatibility helper retained for callers that validate source trees."""
    snapshot = _snapshot_skill(skill)
    return [SKILLS_ROOT / skill / member.relative_path for member in snapshot.members]


def _source_digest(snapshot: SkillSnapshot) -> str:
    digest = hashlib.sha256()
    for member in snapshot.members:
        member_path = f"{snapshot.name}/{member.relative_path}".encode()
        digest.update(len(member_path).to_bytes(8, "big"))
        digest.update(member_path)
        digest.update(member.mode.to_bytes(4, "big"))
        digest.update(len(member.data).to_bytes(8, "big"))
        digest.update(member.data)
    return digest.hexdigest()


def _archive_bytes(snapshot: SkillSnapshot) -> bytes:
    _validate_member_inventory([f"{snapshot.name}/{member.relative_path}" for member in snapshot.members])
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for member in snapshot.members:
            member_name = f"{snapshot.name}/{member.relative_path}"
            _validate_member_name(member_name)
            info = zipfile.ZipInfo(member_name, date_time=FIXED_TIMESTAMP)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | member.mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(
                info,
                member.data,
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
    return buffer.getvalue()


def _artifact_set() -> dict[str, bytes]:
    snapshots = [_snapshot_skill(skill) for skill in sorted(PUBLISHED_SKILLS)]
    artifacts: dict[str, bytes] = {}
    entries: list[dict[str, object]] = []
    for snapshot in snapshots:
        archive_name = f"{snapshot.name}.skill"
        archive_bytes = _archive_bytes(snapshot)
        artifacts[archive_name] = archive_bytes
        entries.append(
            {
                "name": snapshot.name,
                "source_path": f"skills/{snapshot.name}",
                "archive_path": f"dist/{archive_name}",
                "file_count": len(snapshot.members),
                "sha256": _sha256(archive_bytes),
                "source_sha256": _source_digest(snapshot),
            }
        )
    manifest = {
        "schema_version": "1.0",
        "generated_from": "skills/",
        "archives": entries,
    }
    artifacts[MANIFEST_NAME] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    return artifacts


def _prepare_output_root(output_dir: Path) -> tuple[int, bool]:
    output_dir = output_dir.absolute()
    skills = SKILLS_ROOT.absolute()
    if output_dir == skills or skills in output_dir.parents:
        raise ValueError("output directory must not be inside skills/")
    _reject_symlink_ancestry(output_dir.parent, "output ancestry")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_ancestry(output_dir.parent, "output ancestry")
    created = False
    try:
        metadata = output_dir.lstat()
    except FileNotFoundError:
        output_dir.mkdir(mode=0o755)
        created = True
        metadata = output_dir.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"output root must be a regular directory, not a symlink: {output_dir}")
    return os.open(output_dir, _OPEN_DIRECTORY_FLAGS), created


def _read_regular_at(directory_fd: int, name: str) -> bytes:
    descriptor = os.open(name, _OPEN_FILE_FLAGS, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"artifact is not a regular file: {name}")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _validate_inventory(directory_fd: int, expected: set[str], *, allow_missing: bool) -> set[str]:
    actual = set(os.listdir(directory_fd))
    extras = actual - expected
    missing = expected - actual
    if extras:
        raise ValueError(f"unexpected release artifacts: {', '.join(sorted(extras))}")
    if missing and not allow_missing:
        raise ValueError(f"missing release artifacts: {', '.join(sorted(missing))}")
    for name in sorted(actual):
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"artifact is not a regular file: {name}")
    return actual


def _write_staged_artifacts(directory_fd: int, artifacts: dict[str, bytes]) -> None:
    for name, data in sorted(artifacts.items()):
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    os.fsync(directory_fd)


def _publish(output_dir: Path, artifacts: dict[str, bytes]) -> None:
    output_fd, output_created = _prepare_output_root(output_dir)
    expected = set(artifacts)
    try:
        existing = _validate_inventory(output_fd, expected, allow_missing=True)
        with tempfile.TemporaryDirectory(
            prefix=f".{output_dir.name}.package-", dir=output_dir.absolute().parent
        ) as transaction:
            transaction_path = Path(transaction)
            transaction_path.chmod(0o700)
            new_path = transaction_path / "new"
            backup_path = transaction_path / "backup"
            new_path.mkdir(mode=0o700)
            backup_path.mkdir(mode=0o700)
            new_fd = os.open(new_path, _OPEN_DIRECTORY_FLAGS)
            backup_fd = os.open(backup_path, _OPEN_DIRECTORY_FLAGS)
            try:
                _write_staged_artifacts(new_fd, artifacts)
                _validate_inventory(new_fd, expected, allow_missing=False)
                for name, data in artifacts.items():
                    if _read_regular_at(new_fd, name) != data:
                        raise ValueError(f"staged artifact validation failed: {name}")

                moved_old: list[str] = []
                moved_new: list[str] = []
                try:
                    for name in sorted(existing):
                        os.replace(name, name, src_dir_fd=output_fd, dst_dir_fd=backup_fd)
                        moved_old.append(name)
                    for name in sorted(expected):
                        os.replace(name, name, src_dir_fd=new_fd, dst_dir_fd=output_fd)
                        moved_new.append(name)
                    _validate_inventory(output_fd, expected, allow_missing=False)
                    for name, data in artifacts.items():
                        if _read_regular_at(output_fd, name) != data:
                            raise ValueError(f"published artifact validation failed: {name}")
                    os.fsync(output_fd)
                except BaseException:
                    for name in reversed(moved_new):
                        os.replace(name, name, src_dir_fd=output_fd, dst_dir_fd=new_fd)
                    for name in reversed(moved_old):
                        os.replace(name, name, src_dir_fd=backup_fd, dst_dir_fd=output_fd)
                    os.fsync(output_fd)
                    raise
            finally:
                os.close(backup_fd)
                os.close(new_fd)
    except BaseException:
        os.close(output_fd)
        if output_created:
            try:
                output_dir.rmdir()
            except OSError:
                pass
        raise
    else:
        os.close(output_fd)


def build(output_dir: Path) -> list[Path]:
    artifacts = _artifact_set()
    _publish(output_dir, artifacts)
    return [output_dir / name for name in sorted(artifacts)]


def check(output_dir: Path) -> bool:
    artifacts = _artifact_set()
    try:
        _reject_symlink_ancestry(output_dir, "output")
        metadata = output_dir.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("artifact output root is not a regular directory")
        output_fd = os.open(output_dir, _OPEN_DIRECTORY_FLAGS)
    except (OSError, ValueError) as exc:
        print(f"release artifact drift detected: {exc}", file=sys.stderr)
        return False

    drifted: list[str] = []
    try:
        try:
            _validate_inventory(output_fd, set(artifacts), allow_missing=False)
        except (OSError, ValueError) as exc:
            print(f"release artifact drift detected: {exc}", file=sys.stderr)
            return False
        for name, expected in sorted(artifacts.items()):
            try:
                if _read_regular_at(output_fd, name) != expected:
                    drifted.append(name)
            except (OSError, ValueError):
                drifted.append(name)
    finally:
        os.close(output_fd)

    if drifted:
        print(f"release artifact drift detected: {', '.join(sorted(drifted))}", file=sys.stderr)
        return False
    print("Release artifacts are current and reproducible.")
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="artifact directory (default: dist)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare current artifacts with a clean deterministic rebuild without rewriting them",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.check:
            return 0 if check(args.output_dir) else 1
        written = build(args.output_dir)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"packaging failed: {exc}", file=sys.stderr)
        return 2

    print(f"Packaged {len(PUBLISHED_SKILLS)} skills into {args.output_dir}")
    for path in sorted(written):
        print(path.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
