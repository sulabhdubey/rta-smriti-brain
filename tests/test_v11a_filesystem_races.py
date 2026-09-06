from __future__ import annotations

import concurrent.futures
import os
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from rta_brain import benchmark, platform_paths, temporal_validators, workspaces
from rta_brain.runtime_control import prepare_control_dir


def _sqlite_file(path: Path, marker: str) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE marker(value TEXT NOT NULL)")
        connection.execute("INSERT INTO marker(value) VALUES (?)", (marker,))
        connection.commit()
    finally:
        connection.close()


def test_workspace_connection_rejects_member_path_swapped_before_sqlite_open(tmp_path):
    member = tmp_path / "member.sqlite"
    replacement = tmp_path / "replacement.sqlite"
    parked = tmp_path / "parked.sqlite"
    _sqlite_file(member, "approved")
    _sqlite_file(replacement, "substituted")
    real_connect = sqlite3.connect
    swapped = False

    def swapping_connect(database, *args, **kwargs):
        nonlocal swapped
        if not swapped and member.name in str(database):
            member.replace(parked)
            replacement.replace(member)
            swapped = True
        return real_connect(database, *args, **kwargs)

    with patch.object(workspaces.sqlite3, "connect", side_effect=swapping_connect):
        with pytest.raises(ValueError, match="changed while it was opened"):
            workspaces._connect_existing_brain(member, read_only=True)


@pytest.mark.parametrize("suffix", ["wal", "shm"])
def test_workspace_connection_rejects_sidecar_swapped_before_sqlite_open(
    tmp_path, suffix
):
    member = tmp_path / "member.sqlite"
    sidecar = Path(f"{member}-{suffix}")
    replacement = tmp_path / f"replacement-{suffix}"
    parked = tmp_path / f"parked-{suffix}"
    _sqlite_file(member, "approved")
    sidecar.write_bytes(b"approved sidecar")
    replacement.write_bytes(b"substituted sidecar")
    real_connect = sqlite3.connect
    swapped = False

    def swapping_connect(_database, *args, **kwargs):
        nonlocal swapped
        sidecar.replace(parked)
        replacement.replace(sidecar)
        swapped = True
        return real_connect(":memory:")

    with patch.object(
        workspaces.sqlite3, "connect", side_effect=swapping_connect
    ), pytest.raises(ValueError, match="changed while it was opened"):
        workspaces._connect_existing_brain(member, read_only=True)

    assert swapped is (os.name != "nt")


def test_workspace_connection_allows_bound_active_wal_sidecars(tmp_path):
    member = tmp_path / "member.sqlite"
    writer = sqlite3.connect(member)
    reader = None
    try:
        assert writer.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
        writer.execute("CREATE TABLE marker(value TEXT NOT NULL)")
        writer.execute("INSERT INTO marker(value) VALUES ('approved')")
        writer.commit()
        assert Path(f"{member}-wal").is_file()
        assert Path(f"{member}-shm").is_file()

        reader, resolved = workspaces._connect_existing_brain(
            member, read_only=True
        )

        assert resolved == member.resolve()
        assert reader.execute("SELECT value FROM marker").fetchone()[0] == "approved"
    finally:
        if reader is not None:
            reader.close()
        writer.close()

@pytest.mark.parametrize("reader", ["sha256", "bytes"])
def test_temporal_file_read_rejects_path_swap_before_descriptor_open(tmp_path, reader):
    target = tmp_path / "evidence.txt"
    replacement = tmp_path / "replacement.txt"
    parked = tmp_path / "parked.txt"
    target.write_text("approved evidence", encoding="utf-8")
    replacement.write_text("substituted data", encoding="utf-8")
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if not swapped and Path(path) == target:
            target.replace(parked)
            replacement.replace(target)
            swapped = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    with patch.object(temporal_validators.os, "open", side_effect=swapping_open):
        with pytest.raises(RuntimeError, match="path changed while it was read"):
            if reader == "sha256":
                temporal_validators.stable_file_sha256(target)
            else:
                temporal_validators.stable_file_bytes(target, maximum_bytes=1024)

    assert swapped is True


def test_temporal_sqlite_validator_rejects_path_swapped_before_connection(tmp_path):
    target = tmp_path / "evidence.sqlite"
    replacement = tmp_path / "replacement.sqlite"
    parked = tmp_path / "parked.sqlite"
    _sqlite_file(target, "approved")
    _sqlite_file(replacement, "substituted")
    real_connect = sqlite3.connect
    swapped = False

    def swapping_connect(database, *args, **kwargs):
        nonlocal swapped
        if not swapped and target.name in str(database):
            target.replace(parked)
            replacement.replace(target)
            swapped = True
        return real_connect(database, *args, **kwargs)

    with patch.object(
        temporal_validators.sqlite3, "connect", side_effect=swapping_connect
    ):
        status, details = temporal_validators.evaluate_validator(
            "sqlite_integrity",
            {"path": target.name},
            active_root=tmp_path,
            allow_command=False,
            trusted_executables=(),
        )

    assert status == "fail"
    assert details["reason"] == "path_changed"


def test_temporal_file_exists_rejects_path_swapped_before_descriptor_open(tmp_path):
    target = tmp_path / "evidence.txt"
    replacement = tmp_path / "replacement.txt"
    parked = tmp_path / "parked.txt"
    target.write_text("approved evidence", encoding="utf-8")
    replacement.write_text("substituted data", encoding="utf-8")
    real_open = os.open

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        if Path(path) == target and target.exists():
            target.replace(parked)
            replacement.replace(target)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    with patch.object(temporal_validators.os, "open", side_effect=swapping_open):
        status, details = temporal_validators.evaluate_validator(
            "file_exists",
            {"path": target.name},
            active_root=tmp_path,
            allow_command=False,
            trusted_executables=(),
        )

    assert status == "fail"
    assert details == {"path": target.name, "exists": False, "reason": "path_changed"}


def test_benchmark_append_does_not_write_swapped_hard_link(tmp_path):
    history = tmp_path / "history.jsonl"
    victim = tmp_path / "victim.jsonl"
    parked = tmp_path / "parked.jsonl"
    result = {"dataset": "fixture", "modes": {}, "quality_gates": {}}
    benchmark.append_benchmark_history(result, history, label="first")
    victim.write_text("private sentinel\n", encoding="utf-8")
    expected = victim.read_bytes()
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        candidate = Path(path)
        if not swapped and candidate == history:
            history.replace(parked)
            os.link(victim, history)
            swapped = True
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    with patch.object(benchmark.os, "open", side_effect=swapping_open):
        with pytest.raises(ValueError):
            benchmark.append_benchmark_history(result, history, label="second")

    assert swapped is True
    assert victim.read_bytes() == expected


def test_prepare_control_dir_rejects_reparse_ancestor_before_creating_leaf(tmp_path):
    ancestor = tmp_path / "linked-ancestor"
    ancestor.mkdir()
    target = ancestor / "service" / "control"

    with patch(
        "rta_brain.runtime_control._is_reparse_point",
        side_effect=lambda path: Path(path) == ancestor,
    ):
        with pytest.raises(ValueError, match="ancestor"):
            prepare_control_dir(target, label="capture")

    assert not (ancestor / "service").exists()


def test_control_directory_allows_safe_concurrent_creation(tmp_path):
    target = tmp_path / "runtime" / "shared"

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(lambda _index: prepare_control_dir(target), range(12)))

    assert outcomes == [None] * 12
    assert target.is_dir()


def test_macos_system_root_alias_is_canonicalized_without_allowing_other_links(tmp_path):
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(canonical, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")

    with (
        patch.object(platform_paths.sys, "platform", "darwin"),
        patch.object(platform_paths, "_DARWIN_ROOT_ALIASES", ((alias, canonical),)),
    ):
        assert (
            platform_paths.canonicalize_system_root_alias(alias / "nested")
            == canonical / "nested"
        )
        assert (
            platform_paths.canonicalize_system_root_alias(tmp_path / "other-link")
            == tmp_path / "other-link"
        )


def test_macos_system_root_alias_rejects_an_unexpected_target(tmp_path):
    expected = tmp_path / "expected"
    unexpected = tmp_path / "unexpected"
    expected.mkdir()
    unexpected.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(unexpected, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")

    with (
        patch.object(platform_paths.sys, "platform", "darwin"),
        patch.object(platform_paths, "_DARWIN_ROOT_ALIASES", ((alias, expected),)),
        pytest.raises(ValueError, match="not trusted"),
    ):
        platform_paths.canonicalize_system_root_alias(alias / "nested")
