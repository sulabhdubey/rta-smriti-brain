"""Bounded, non-shell validator adapters for temporal truth claims."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .platform_paths import canonicalize_system_root_alias
from .repository import canonical_root, repository_state, run_git_inspection


def _file_identity(details: os.stat_result) -> tuple[int, int]:
    return int(details.st_dev), int(details.st_ino)


def _is_link_or_reparse(details: os.stat_result) -> bool:
    attributes = int(getattr(details, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(details.st_mode) or bool(attributes & reparse_flag)


def _ancestor_snapshot(path: Path) -> tuple[tuple[Path, tuple[int, int]], ...]:
    snapshot: list[tuple[Path, tuple[int, int]]] = []
    selected = canonicalize_system_root_alias(path)
    for ancestor in reversed(selected.parents):
        details = os.stat(ancestor, follow_symlinks=False)
        if not stat.S_ISDIR(details.st_mode) or _is_link_or_reparse(details):
            raise RuntimeError("validator path has an unsafe ancestor")
        snapshot.append((ancestor, _file_identity(details)))
    return tuple(snapshot)


def _assert_stable_ancestors(
    expected: tuple[tuple[Path, tuple[int, int]], ...],
) -> None:
    try:
        current = []
        for ancestor, _identity in expected:
            details = os.stat(ancestor, follow_symlinks=False)
            if not stat.S_ISDIR(details.st_mode) or _is_link_or_reparse(details):
                raise RuntimeError("validator path has an unsafe ancestor")
            current.append((ancestor, _file_identity(details)))
    except OSError as exc:
        raise RuntimeError("validator path ancestor changed while it was read") from exc
    if tuple(current) != expected:
        raise RuntimeError("validator path ancestor changed while it was read")


def _open_stable_regular(
    path: Path,
) -> tuple[int, os.stat_result, tuple[tuple[Path, tuple[int, int]], ...]]:
    ancestors = _ancestor_snapshot(path)
    try:
        expected = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        raise
    if not stat.S_ISREG(expected.st_mode):
        raise FileNotFoundError(str(path))
    if expected.st_nlink != 1:
        raise ValueError("validator files must not be hard linked")
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW"):
        flags |= int(getattr(os, name, 0))
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise RuntimeError("validator path changed while it was read") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _file_identity(opened) != _file_identity(expected)
        ):
            raise RuntimeError("validator path changed while it was read")
        _assert_stable_ancestors(ancestors)
        return descriptor, opened, ancestors
    except BaseException:
        os.close(descriptor)
        raise


def _assert_stable_path(path: Path, opened: os.stat_result) -> os.stat_result:
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError("validator path changed while it was read") from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or _file_identity(current) != _file_identity(opened)
    ):
        raise RuntimeError("validator path changed while it was read")
    return current


def safe_project_file(root: str | Path, relative_path: str) -> Path:
    canonical = Path(canonical_root(root))
    candidate = canonical.joinpath(*Path(relative_path).parts)
    current = canonical
    for part in Path(relative_path).parts:
        if part in {"", ".", ".."}:
            raise ValueError("validator path contains an unsafe segment")
        current = current / part
        if current.exists() and current.is_symlink():
            raise ValueError("validator path must not traverse a symbolic link")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(canonical)
    except ValueError as exc:
        raise ValueError("validator path escapes the canonical root") from exc
    return resolved


def stable_file_sha256(path: Path, *, maximum_bytes: int = 64 * 1024 * 1024) -> str:
    descriptor, before, ancestors = _open_stable_regular(path)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as stream:
        if before.st_size > maximum_bytes:
            raise ValueError("validator file exceeds the 64 MiB bound")
        total = 0
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum_bytes:
                raise ValueError("validator file exceeds the 64 MiB bound")
            digest.update(block)
        after = os.fstat(stream.fileno())
        if after.st_nlink != 1:
            raise ValueError("validator files must not be hard linked")
        _assert_stable_path(path, opened=before)
        _assert_stable_ancestors(ancestors)
    if (
        _file_identity(before) != _file_identity(after)
        or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
    ):
        raise RuntimeError("validator file changed while it was read")
    return digest.hexdigest()


def stable_file_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    descriptor, before, ancestors = _open_stable_regular(path)
    with os.fdopen(descriptor, "rb") as stream:
        if before.st_size > maximum_bytes:
            raise ValueError("validator file exceeds its byte bound")
        data = stream.read(maximum_bytes + 1)
        after = os.fstat(stream.fileno())
        if after.st_nlink != 1:
            raise ValueError("validator files must not be hard linked")
        _assert_stable_path(path, opened=before)
        _assert_stable_ancestors(ancestors)
    if len(data) > maximum_bytes:
        raise ValueError("validator file exceeds its byte bound")
    if (
        _file_identity(before) != _file_identity(after)
        or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
    ):
        raise RuntimeError("validator file changed while it was read")
    return data


def json_pointer(document: Any, pointer: str) -> Any:
    current = document
    if pointer == "":
        return current
    for encoded in pointer.split("/")[1:]:
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            raise KeyError(pointer)
    return current


def git_anchor_state(active_root: str | Path) -> dict[str, Any]:
    root = canonical_root(active_root)
    head_result = run_git_inspection(Path(root), "rev-parse", "--verify", "HEAD")
    status_result = run_git_inspection(
        Path(root), "status", "--porcelain=v1", "-z", "--untracked-files=normal"
    )
    if (
        head_result is None or status_result is None
        or head_result.returncode != 0 or status_result.returncode != 0
    ):
        raise ValueError(
            "repository anchor requires an available verified Git checkout"
        )
    head_stdout = head_result.stdout.encode("utf-8", errors="strict")
    status_stdout = status_result.stdout.encode("utf-8", errors="surrogatepass")
    if len(head_stdout) > 128 or len(status_stdout) > 1024 * 1024:
        raise ValueError("repository anchor Git output exceeded its bound")
    commit = head_result.stdout.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ValueError("repository anchor could not resolve a full Git commit")
    state = repository_state(root)
    return {
        "branch": state.get("branch"),
        "commit": commit,
        "dirty_digest": hashlib.sha256(status_stdout).hexdigest(),
        "dirty_files": state.get("dirty_files"),
    }


def evaluate_validator(
    validator_type: str,
    config: dict[str, Any],
    *,
    active_root: str | Path,
    allow_command: bool,
    trusted_executables: list[str] | tuple[str, ...],
) -> tuple[str, dict[str, Any]]:
    if validator_type == "file_sha256":
        path = safe_project_file(active_root, config["path"])
        try:
            actual = stable_file_sha256(path)
        except FileNotFoundError:
            return "fail", {"path": config["path"], "reason": "missing"}
        expected = config["sha256"]
        return (
            "pass" if actual == expected else "fail",
            {"path": config["path"], "expected_sha256": expected, "actual_sha256": actual},
        )
    if validator_type == "file_exists":
        path = safe_project_file(active_root, config["path"])
        try:
            descriptor, opened, ancestors = _open_stable_regular(path)
            try:
                _assert_stable_path(path, opened)
                _assert_stable_ancestors(ancestors)
            finally:
                os.close(descriptor)
        except FileNotFoundError:
            return "fail", {"path": config["path"], "exists": False}
        except (OSError, RuntimeError, ValueError):
            return "fail", {
                "path": config["path"], "exists": False, "reason": "path_changed",
            }
        return "pass", {"path": config["path"], "exists": True}
    if validator_type == "json_pointer_equals":
        path = safe_project_file(active_root, config["path"])
        try:
            document = json.loads(stable_file_bytes(path, maximum_bytes=4 * 1024 * 1024))
            actual = json_pointer(document, config["pointer"])
        except FileNotFoundError:
            return "fail", {"path": config["path"], "reason": "missing"}
        except (UnicodeDecodeError, json.JSONDecodeError):
            return "fail", {"path": config["path"], "reason": "invalid_json"}
        except KeyError:
            return "fail", {"path": config["path"], "reason": "pointer_missing"}
        passed = actual == config["equals"]
        return "pass" if passed else "fail", {
            "path": config["path"], "pointer": config["pointer"], "matched": passed,
        }
    if validator_type == "sqlite_integrity":
        path = safe_project_file(active_root, config["path"])
        try:
            database_bytes = stable_file_bytes(path, maximum_bytes=64 * 1024 * 1024)
        except FileNotFoundError:
            return "fail", {"path": config["path"], "reason": "missing"}
        except (OSError, RuntimeError, ValueError):
            return "fail", {"path": config["path"], "reason": "path_changed"}
        with tempfile.TemporaryDirectory(prefix="rta-validator-") as directory:
            snapshot = Path(directory) / "evidence.sqlite"
            try:
                with snapshot.open("xb") as stream:
                    stream.write(database_bytes)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                os.chmod(snapshot, stat.S_IRUSR | stat.S_IWUSR)
                check = sqlite3.connect(
                    f"{snapshot.as_uri()}?mode=ro&immutable=1",
                    uri=True,
                    timeout=2.0,
                )
                try:
                    result = str(check.execute("PRAGMA quick_check").fetchone()[0])
                finally:
                    check.close()
            except (OSError, sqlite3.Error) as exc:
                return "fail", {
                    "path": config["path"], "reason": "sqlite_error",
                    "error_type": type(exc).__name__,
                }
        try:
            if stable_file_sha256(path) != hashlib.sha256(database_bytes).hexdigest():
                return "fail", {"path": config["path"], "reason": "path_changed"}
        except (FileNotFoundError, OSError, RuntimeError, ValueError):
            return "fail", {"path": config["path"], "reason": "path_changed"}
        return "pass" if result == "ok" else "fail", {
            "path": config["path"], "quick_check": result,
        }
    if validator_type == "git_head_equals":
        state = git_anchor_state(active_root)
        passed = state["commit"] == config["commit"]
        return "pass" if passed else "fail", {
            "expected_commit": config["commit"], "actual_commit": state["commit"],
        }
    if validator_type == "git_clean_state":
        state = git_anchor_state(active_root)
        if state["dirty_files"] is None:
            return "unavailable", {"reason": "git_status_unknown"}
        actual_clean = int(state["dirty_files"]) == 0
        passed = actual_clean is bool(config["clean"])
        return "pass" if passed else "fail", {
            "expected_clean": bool(config["clean"]), "actual_clean": actual_clean,
        }
    if validator_type == "command_exit" and not allow_command:
        return "unavailable", {"reason": "command validator capability is disabled"}
    if validator_type == "command_exit":
        executable = Path(config["argv"][0]).expanduser().resolve()
        trusted = {
            os.path.normcase(str(Path(value).expanduser().resolve()))
            for value in trusted_executables
        }
        if os.path.normcase(str(executable)) not in trusted:
            return "unavailable", {"reason": "executable is not operator-trusted"}
        if not executable.is_file() or executable.is_symlink():
            return "unavailable", {"reason": "trusted executable is not a safe regular file"}
        environment = {
            key: value for key, value in os.environ.items()
            if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME"}
        }
        environment["PYTHONIOENCODING"] = "utf-8"
        kwargs: dict[str, Any] = {
            "cwd": canonical_root(active_root), "env": environment,
            "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL, "timeout": float(config["timeout_seconds"]),
            "check": False, "shell": False,
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = subprocess.run([str(executable), *config["argv"][1:]], **kwargs)
        except subprocess.TimeoutExpired:
            return "error", {"reason": "command timed out"}
        except OSError as exc:
            return "error", {"reason": f"command could not start: {type(exc).__name__}"}
        exit_code = int(completed.returncode)
        return "pass" if exit_code == 0 else "fail", {
            "exit_code": exit_code, "output_captured": False,
        }
    return "unavailable", {"reason": f"validator adapter unavailable: {validator_type}"}
