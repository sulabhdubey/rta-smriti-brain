"""Cross-platform background repository watcher with a polling fallback."""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from .db import connect, ingest_repo
from .runtime_control import (
    clear_control_files,
    detach_current_worker_session,
    detached_worker_bootstrap,
    is_safe_regular_file,
    now_iso,
    open_log,
    prepare_control_dir,
    process_alive,
    read_json,
    spawn_detached_worker,
    stop_requested,
    write_json,
    write_stop_request,
)


_SPAWNED_PROCESSES: dict[str, subprocess.Popen] = {}
_CONTENT_EVENT_TYPES = frozenset({"created", "modified", "deleted", "moved"})
MAX_PENDING_CHANGED_PATHS = 50_000
MIN_POLLING_DEEP_VERIFY_SECONDS = 300.0
LARGE_REPOSITORY_FILE_COUNT = 10_000
VERY_LARGE_REPOSITORY_FILE_COUNT = 50_000


def _polling_wait_seconds(requested_seconds: float, indexed_files: int) -> float:
    requested = float(requested_seconds)
    count = max(0, int(indexed_files))
    if count >= VERY_LARGE_REPOSITORY_FILE_COUNT:
        return max(requested, 60.0)
    if count >= LARGE_REPOSITORY_FILE_COUNT:
        return max(requested, 30.0)
    return requested


def _now_iso() -> str:
    return now_iso()


def _slug(value: str) -> str:
    return "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-") or "default"


def watcher_paths(db_path: Path, project: str) -> dict[str, Path]:
    database = db_path.expanduser().resolve()
    key = hashlib.sha256(f"{database}\0{project}".encode("utf-8")).hexdigest()[:12]
    control_dir = database.parent / ".rta-smriti-daemons"
    stem = f"{database.stem}-{_slug(project)}-{key}"
    return {
        "directory": control_dir,
        "state": control_dir / f"{stem}.json",
        "stop": control_dir / f"{stem}.stop",
        "lock": control_dir / f"{stem}.lock",
        "log": control_dir / f"{stem}.log",
    }


def _prepare_control_dir(path: Path) -> None:
    prepare_control_dir(path, label="watcher")


def _write_json(path: Path, payload: dict) -> None:
    write_json(path, payload, label="watcher state")


def _read_json(path: Path) -> dict | None:
    return read_json(path)


def _is_safe_regular_file(path: Path) -> bool:
    return is_safe_regular_file(path)


def _watchdog_event_requires_refresh(event, is_internal_event) -> bool:
    """Ignore access/open/close noise and react only to repository content changes."""
    if getattr(event, "is_directory", False):
        return False
    if getattr(event, "event_type", None) not in _CONTENT_EVENT_TYPES:
        return False
    paths = [getattr(event, "src_path", None), getattr(event, "dest_path", None)]
    return any(path and not is_internal_event(path) for path in paths)


def _normalized_event_path(path: str | Path) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(os.fspath(path))))


def _internal_event_filter(db_path: Path, control_path: Path):
    database = _normalized_event_path(db_path)
    control = _normalized_event_path(control_path)
    sqlite_artifacts = {
        database,
        database + "-journal",
        database + "-shm",
        database + "-wal",
    }

    def is_internal(raw_path: str | None) -> bool:
        if not raw_path:
            return False
        candidate = _normalized_event_path(raw_path)
        if candidate in sqlite_artifacts:
            return True
        try:
            return os.path.commonpath((candidate, control)) == control
        except ValueError:
            return False

    return is_internal


def _write_stop_request(path: Path) -> None:
    write_stop_request(path, label="watcher")


def _stop_requested(path: Path) -> bool:
    return stop_requested(path, label="watcher")


def _open_log(path: Path):
    return open_log(path, label="watcher")


def _process_alive(pid: int | None) -> bool:
    return process_alive(pid)


def watcher_status(db_path: Path, project: str) -> dict:
    paths = watcher_paths(db_path, project)
    payload = _read_json(paths["state"])
    counters = {
        "cycles": 0,
        "updated_files": 0,
        "removed_files": 0,
        "errors": 0,
    }
    if not payload:
        return {
            "status": "ok",
            "state": "stopped",
            "project": project,
            "db_path": str(db_path.expanduser().resolve()),
            "backend": None,
            **counters,
        }
    state = str(payload.get("state") or "unknown")
    if state in {"starting", "running", "stopping"} and not _process_alive(payload.get("pid")):
        state = "stale"
    return {"status": "ok", **counters, **payload, "state": state}


def _clear_stale_control(paths: dict[str, Path]) -> None:
    clear_control_files(paths, ("state", "stop", "lock"))


def _worker_command(db_path: Path, root: Path, project: str, paths: dict[str, Path], interval: float) -> list[str]:
    suffix = [
        "_watch-worker",
        "--root", str(root),
        "--project", project,
        "--state-file", str(paths["state"]),
        "--stop-file", str(paths["stop"]),
        "--lock-file", str(paths["lock"]),
        "--interval", str(interval),
    ]
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve()), "--db", str(db_path), *suffix]
    return [
        str(Path(sys.executable).resolve()),
        "-I",
        "-c",
        detached_worker_bootstrap(
            "rta_brain.watch_worker", Path(__file__).resolve().parents[1]
        ),
        "--db",
        str(db_path),
        *suffix[1:],
    ]


def start_watcher(
    db_path: Path,
    root: Path,
    project: str,
    interval_seconds: float = 2.0,
    startup_timeout: float = 10.0,
) -> dict:
    database = db_path.expanduser().resolve()
    repository = root.expanduser().resolve()
    interval = float(interval_seconds)
    if not database.is_file() or database.is_symlink() or database.stat().st_nlink > 1:
        raise ValueError(f"brain database must be an existing unlinked file: {database}")
    if not repository.is_dir():
        raise ValueError(f"watch root does not exist or is not a directory: {repository}")
    if not 0.1 <= interval <= 3600:
        raise ValueError("watch interval must be between 0.1 and 3,600 seconds")
    paths = watcher_paths(database, project)
    _prepare_control_dir(paths["directory"])
    current = watcher_status(database, project)
    if current["state"] in {"starting", "running", "stopping"}:
        return current
    _clear_stale_control(paths)
    token = secrets_token = uuid.uuid4().hex
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    try:
        descriptor = os.open(paths["lock"], os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise RuntimeError("watcher start is already in progress") from exc
    with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
        stream.write(token_hash + "\n")
    env = {**os.environ, "RTA_SMIRTI_WATCH_TOKEN": secrets_token}
    try:
        log_stream = _open_log(paths["log"])
    except Exception:
        paths["lock"].unlink(missing_ok=True)
        raise
    try:
        process = spawn_detached_worker(
            _worker_command(database, repository, project, paths, interval),
            log_stream,
            env,
            Path(__file__).resolve().parents[1],
        )
    except Exception:
        paths["lock"].unlink(missing_ok=True)
        raise
    finally:
        log_stream.close()
    deadline = time.monotonic() + max(1.0, float(startup_timeout))
    while time.monotonic() < deadline:
        state = watcher_status(database, project)
        if state.get("token_hash") == token_hash and state["state"] == "running":
            _SPAWNED_PROCESSES[str(paths["state"])] = process
            return state
        if process.poll() is not None:
            break
        time.sleep(0.05)
    _write_stop_request(paths["stop"])
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    tail = ""
    try:
        tail = paths["log"].read_text(encoding="utf-8", errors="ignore")[-2_000:]
    except OSError:
        pass
    raise RuntimeError(f"watcher did not become ready within {startup_timeout:g} seconds{': ' + tail if tail else ''}")


def stop_watcher(db_path: Path, project: str, timeout: float = 10.0) -> dict:
    paths = watcher_paths(db_path, project)
    state = watcher_status(db_path, project)
    if state["state"] in {"stopped", "stale", "error"}:
        _clear_stale_control(paths)
        return {**state, "state": "stopped"}
    _prepare_control_dir(paths["directory"])
    _write_stop_request(paths["stop"])
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        state = watcher_status(db_path, project)
        if state["state"] in {"stopped", "stale", "error"}:
            process = _SPAWNED_PROCESSES.pop(str(paths["state"]), None)
            if process is not None:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            return {**state, "state": "stopped" if state["state"] == "stale" else state["state"]}
        time.sleep(0.05)
    raise TimeoutError(f"watcher did not stop within {timeout:g} seconds")


def run_watcher_worker(
    db_path: Path,
    root: Path,
    project: str,
    state_file: Path,
    stop_file: Path,
    lock_file: Path,
    interval_seconds: float,
) -> int:
    detach_current_worker_session()
    token = os.environ.get("RTA_SMIRTI_WATCH_TOKEN", "")
    if not token:
        raise RuntimeError("watcher launch token is missing")
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    if not lock_file.is_file() or lock_file.read_text(encoding="ascii", errors="ignore").strip() != token_hash:
        raise RuntimeError("watcher launch lock does not match")
    stop_event = threading.Event()
    change_event = threading.Event()
    pending_lock = threading.Lock()
    pending_changes = {"paths": set(), "force_full": False}
    observer = None
    backend = "polling"
    counters = {"cycles": 0, "updated_files": 0, "removed_files": 0, "errors": 0}
    deep_verify_interval = max(MIN_POLLING_DEEP_VERIFY_SECONDS, float(interval_seconds) * 30.0)
    last_deep_verify = time.monotonic()
    effective_poll_interval = float(interval_seconds)
    state = {
        "project": project,
        "db_path": str(db_path.expanduser().resolve()),
        "root": str(root.expanduser().resolve()),
        "pid": os.getpid(),
        "token_hash": token_hash,
        "state": "starting",
        "backend": backend,
        "interval_seconds": float(interval_seconds),
        "effective_poll_interval_seconds": effective_poll_interval,
        "deep_verify_interval_seconds": deep_verify_interval,
        "started_at": _now_iso(),
        "heartbeat_at": _now_iso(),
        "last_cycle_at": None,
        "last_error": None,
        **counters,
    }

    def request_stop(_signum=None, _frame=None) -> None:
        stop_event.set()
        change_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer

            is_internal_event = _internal_event_filter(
                db_path.expanduser().resolve(),
                state_file.expanduser().resolve().parent,
            )

            class Handler(FileSystemEventHandler):
                def on_any_event(self, event) -> None:
                    if _watchdog_event_requires_refresh(event, is_internal_event):
                        candidates = (
                            getattr(event, "src_path", None),
                            getattr(event, "dest_path", None),
                        )
                        with pending_lock:
                            for candidate in candidates:
                                if not candidate or is_internal_event(candidate):
                                    continue
                                if len(pending_changes["paths"]) >= MAX_PENDING_CHANGED_PATHS:
                                    pending_changes["paths"].clear()
                                    pending_changes["force_full"] = True
                                    break
                                pending_changes["paths"].add(_normalized_event_path(candidate))
                        change_event.set()

            observer = Observer()
            observer.schedule(Handler(), str(root.expanduser().resolve()), recursive=True)
            observer.start()
            backend = "watchdog"
            state["backend"] = backend
        except (ImportError, OSError, RuntimeError):
            observer = None
        state["state"] = "running"
        _write_json(state_file, state)
        should_index = True
        while not stop_event.is_set() and not _stop_requested(stop_file):
            if should_index:
                with pending_lock:
                    cycle_paths = tuple(pending_changes["paths"])
                    force_cycle = bool(pending_changes["force_full"])
                    pending_changes["paths"].clear()
                    pending_changes["force_full"] = False
                if backend == "polling" and time.monotonic() - last_deep_verify >= deep_verify_interval:
                    force_cycle = True
                try:
                    conn = connect(db_path)
                    try:
                        result = ingest_repo(
                            conn, root, project=project, force=force_cycle,
                            changed_paths=cycle_paths,
                        )
                    finally:
                        conn.close()
                    if force_cycle:
                        last_deep_verify = time.monotonic()
                    counters["cycles"] += 1
                    counters["updated_files"] += int(result.get("updated_files", 0))
                    counters["removed_files"] += int(result.get("removed_files", 0))
                    if backend == "polling":
                        effective_poll_interval = _polling_wait_seconds(
                            interval_seconds, int(result.get("indexed_files", 0))
                        )
                        state["effective_poll_interval_seconds"] = effective_poll_interval
                    state["last_cycle_at"] = _now_iso()
                    state["last_error"] = None
                except Exception as exc:
                    with pending_lock:
                        if not pending_changes["force_full"]:
                            pending_changes["paths"].update(cycle_paths)
                            if len(pending_changes["paths"]) > MAX_PENDING_CHANGED_PATHS:
                                pending_changes["paths"].clear()
                                pending_changes["force_full"] = True
                        pending_changes["force_full"] = pending_changes["force_full"] or force_cycle
                    counters["errors"] += 1
                    state["last_error"] = f"{exc.__class__.__name__}: {exc}"
                state.update(counters)
            state["heartbeat_at"] = _now_iso()
            _write_json(state_file, state)
            if backend == "watchdog":
                changed = change_event.wait(timeout=max(0.1, min(float(interval_seconds), 5.0)))
                if changed:
                    time.sleep(min(0.25, float(interval_seconds)))
                    change_event.clear()
                should_index = changed
            else:
                stop_event.wait(timeout=effective_poll_interval)
                should_index = True
        state["state"] = "stopping"
        state["heartbeat_at"] = _now_iso()
        _write_json(state_file, state)
        return 0
    except Exception as exc:
        state["state"] = "error"
        state["last_error"] = f"{exc.__class__.__name__}: {exc}"
        state["heartbeat_at"] = _now_iso()
        _write_json(state_file, state)
        return 1
    finally:
        if observer is not None:
            observer.stop()
            observer.join(timeout=5)
        if state.get("state") != "error":
            state["state"] = "stopped"
            state["stopped_at"] = _now_iso()
            state["heartbeat_at"] = _now_iso()
            _write_json(state_file, state)
        if _is_safe_regular_file(stop_file):
            stop_file.unlink(missing_ok=True)
        try:
            if lock_file.read_text(encoding="ascii", errors="ignore").strip() == token_hash:
                lock_file.unlink(missing_ok=True)
        except OSError:
            pass
