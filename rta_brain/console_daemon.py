"""Managed, terminal-independent lifecycle for the local operator console."""

from __future__ import annotations

import hashlib
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
import json
from pathlib import Path

from .runtime_control import (
    clear_control_files,
    detach_current_worker_session,
    detached_worker_bootstrap,
    is_safe_regular_file,
    now_iso,
    open_log,
    prepare_control_dir,
    process_alive,
    process_identity,
    read_json,
    read_secret,
    spawn_detached_worker,
    stop_requested,
    terminate_worker,
    write_json,
    write_secret,
    write_stop_request,
)


_SPAWNED_PROCESSES: dict[str, subprocess.Popen] = {}
_ACTIVE_STATES = frozenset({"starting", "running", "stopping"})


def console_paths(brain_dir: Path) -> dict[str, Path]:
    directory = brain_dir.expanduser().resolve() / ".rta-smriti-console"
    return {
        "directory": directory,
        "state": directory / "state.json",
        "stop": directory / "stop.request",
        "lock": directory / "launch.lock",
        "token": directory / "capability.secret",
        "log": directory / "console.log",
    }


def _public_state(payload: dict) -> dict:
    private_names = {"token", "capability", "capability_token", "url", "authorized_url"}
    return {key: value for key, value in payload.items() if key not in private_names}


def console_status(brain_dir: Path) -> dict:
    paths = console_paths(brain_dir)
    payload = read_json(paths["state"])
    if not payload:
        return {
            "status": "ok",
            "state": "stopped",
            "brain_dir": str(brain_dir.expanduser().resolve()),
            "host": None,
            "port": None,
        }
    state = str(payload.get("state") or "unknown")
    if state in _ACTIVE_STATES and not process_alive(payload.get("pid")):
        state = "stale"
    elif state == "running" and not _runtime_identity_matches(paths, payload):
        state = "unresponsive"
    return {"status": "ok", **_public_state(payload), "state": state}


def _runtime_identity_matches(paths: dict[str, Path], state: dict) -> bool:
    instance_id = str(state.get("instance_id") or "")
    host = str(state.get("host") or "")
    port = state.get("port")
    if not instance_id or host not in {"127.0.0.1", "localhost"} or not port:
        return False
    try:
        capability = read_secret(paths["token"], label="console capability")
        request = urllib.request.Request(
            f"http://{host}:{int(port)}/api/runtime-health",
            headers={"X-Rta-Smriti-Token": capability},
        )
        with urllib.request.urlopen(request, timeout=0.5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return response.status == 200 and payload.get("instance_id") == instance_id
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return False


def _worker_process_matches(state: dict) -> bool:
    return _recorded_process_matches(state, "pid", "process_identity")


def _launcher_process_matches(state: dict) -> bool:
    return _recorded_process_matches(
        state, "launcher_pid", "launcher_process_identity",
    )


def _recorded_process_matches(state: dict, pid_key: str, identity_key: str) -> bool:
    pid = state.get(pid_key)
    expected = str(state.get(identity_key) or "")
    if not pid or not expected or not process_alive(pid):
        return False
    actual = process_identity(pid)
    return bool(actual and secrets.compare_digest(str(actual), expected))


def _worker_command(
    tool_root: Path,
    brain_dir: Path,
    default_db: Path | None,
    default_project: str | None,
    host: str,
    port: int,
    paths: dict[str, Path],
) -> list[str]:
    suffix = [
        "_console-worker",
        "--tool-root", str(tool_root),
        "--brain-dir", str(brain_dir),
        "--host", host,
        "--port", str(port),
        "--state-file", str(paths["state"]),
        "--stop-file", str(paths["stop"]),
        "--lock-file", str(paths["lock"]),
        "--token-file", str(paths["token"]),
    ]
    if default_db:
        suffix.extend(("--default-db", str(default_db)))
    if default_project:
        suffix.extend(("--default-project", default_project))
    if getattr(sys, "frozen", False):
        return [str(Path(sys.executable).resolve()), *suffix]
    return [
        str(Path(sys.executable).resolve()),
        "-I",
        "-c",
        detached_worker_bootstrap("rta_brain.console_worker", tool_root),
        *suffix[1:],
    ]


def _authorized_result(state: dict, paths: dict[str, Path]) -> dict:
    token = read_secret(paths["token"], label="console capability")
    url = f"http://{state['host']}:{int(state['port'])}/#token={token}"
    return {**_public_state(state), "url": url}


def _wait_for_peer_start(
    brain_dir: Path,
    paths: dict[str, Path],
    *,
    timeout: float,
    open_browser: bool,
) -> dict:
    deadline = time.monotonic() + max(1.0, float(timeout))
    while time.monotonic() < deadline:
        state = console_status(brain_dir)
        if state["state"] == "running":
            result = _authorized_result(state, paths)
            if open_browser:
                webbrowser.open(result["url"])
            return result
        if state["state"] in {"error", "stale", "unresponsive"}:
            break
        if not paths["lock"].exists() and state["state"] == "stopped":
            break
        time.sleep(0.05)
    raise RuntimeError("concurrent console start did not produce a verified running instance")


def start_console(
    tool_root: Path,
    brain_dir: Path,
    default_db: Path | None = None,
    default_project: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
    startup_timeout: float = 10.0,
) -> dict:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("console host must be loopback-only")
    if not 0 <= int(port) <= 65_535:
        raise ValueError("console port must be between 0 and 65,535")
    root = brain_dir.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    paths = console_paths(root)
    prepare_control_dir(paths["directory"], label="console")
    current = console_status(root)
    if current["state"] in _ACTIVE_STATES:
        result = _authorized_result(current, paths)
        if open_browser:
            webbrowser.open(result["url"])
        return result
    if current["state"] == "unresponsive":
        raise RuntimeError("console process is alive but failed identity verification; stop it before restarting")
    clear_control_files(paths, ("state", "stop", "token"))
    if paths["lock"].exists():
        if not is_safe_regular_file(paths["lock"]):
            raise ValueError(f"refusing linked console launch lock: {paths['lock']}")
        stale_lock = current["state"] == "stale" or time.time() - paths["lock"].stat().st_mtime > 30.0
        if not stale_lock:
            return _wait_for_peer_start(
                root, paths, timeout=startup_timeout, open_browser=open_browser,
            )
        paths["lock"].unlink()

    launch_secret = secrets.token_urlsafe(32)
    capability = secrets.token_urlsafe(32)
    instance_id = secrets.token_hex(16)
    launch_fingerprint = hashlib.sha256(launch_secret.encode("ascii")).hexdigest()
    try:
        descriptor = os.open(paths["lock"], os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        if not is_safe_regular_file(paths["lock"]):
            raise ValueError(f"refusing linked console launch lock: {paths['lock']}") from exc
        return _wait_for_peer_start(
            root, paths, timeout=startup_timeout, open_browser=open_browser,
        )
    with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
        stream.write(launch_fingerprint + "\n")

    env = {
        **os.environ,
        "RTA_SMIRTI_CONSOLE_LAUNCH_SECRET": launch_secret,
        "RTA_SMIRTI_CONSOLE_CAPABILITY": capability,
        "RTA_SMIRTI_CONSOLE_INSTANCE_ID": instance_id,
    }
    try:
        log_stream = open_log(paths["log"], label="console")
    except Exception:
        paths["lock"].unlink(missing_ok=True)
        raise
    try:
        process = spawn_detached_worker(
            _worker_command(tool_root.resolve(), root, default_db, default_project, host, int(port), paths),
            log_stream,
            env,
            tool_root.resolve(),
        )
    except Exception:
        paths["lock"].unlink(missing_ok=True)
        raise
    finally:
        log_stream.close()

    deadline = time.monotonic() + max(1.0, float(startup_timeout))
    while time.monotonic() < deadline:
        state = console_status(root)
        if state.get("launch_fingerprint") == launch_fingerprint and state["state"] == "running":
            _SPAWNED_PROCESSES[str(paths["state"])] = process
            result = _authorized_result(state, paths)
            if open_browser:
                webbrowser.open(result["url"])
            return result
        if process.poll() is not None:
            break
        time.sleep(0.05)

    write_stop_request(paths["stop"], label="console")
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
    observed = read_json(paths["state"])
    stage = ""
    if observed and observed.get("launch_fingerprint") == launch_fingerprint:
        stage = str(observed.get("startup_stage") or observed.get("state") or "")
    detail = tail or (f"startup stage: {stage}" if stage else "")
    raise RuntimeError(
        f"console did not become ready within {startup_timeout:g} seconds"
        f"{': ' + detail if detail else ''}"
    )


def open_console(brain_dir: Path, *, launch_browser: bool = True) -> dict:
    paths = console_paths(brain_dir)
    state = console_status(brain_dir)
    if state["state"] != "running":
        raise RuntimeError("console is not running; run `rta-brain console start` first")
    result = _authorized_result(state, paths)
    if launch_browser:
        webbrowser.open(result["url"])
    return result


def stop_console(brain_dir: Path, timeout: float = 10.0) -> dict:
    paths = console_paths(brain_dir)
    state = console_status(brain_dir)
    deadline = time.monotonic() + max(0.1, float(timeout))
    if state["state"] in {"stopped", "stale", "error"}:
        while _worker_process_matches(state) or _launcher_process_matches(state):
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"console process did not exit within {timeout:g} seconds"
                )
            time.sleep(0.05)
        clear_control_files(paths, ("state", "stop", "lock", "token"))
        return {**state, "state": "stopped"}
    prepare_control_dir(paths["directory"], label="console")
    write_stop_request(paths["stop"], label="console")
    while time.monotonic() < deadline:
        state = console_status(brain_dir)
        if state["state"] in {"stopped", "stale", "error"}:
            if _worker_process_matches(state) or _launcher_process_matches(state):
                time.sleep(0.05)
                continue
            process = _SPAWNED_PROCESSES.pop(str(paths["state"]), None)
            if process is not None:
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            clear_control_files(paths, ("stop", "lock", "token"))
            return {**state, "state": "stopped" if state["state"] == "stale" else state["state"]}
        time.sleep(0.05)
    process = _SPAWNED_PROCESSES.get(str(paths["state"]))
    latest = console_status(brain_dir)
    if (
        process is not None
        and int(process.pid) == int(latest.get("pid") or 0)
        and _worker_process_matches(latest)
    ):
        terminate_worker(process, timeout=1.0)
        _SPAWNED_PROCESSES.pop(str(paths["state"]), None)
        clear_control_files(paths, ("stop", "lock", "token"))
        return {**latest, "state": "stopped"}
    raise TimeoutError(f"console did not stop within {timeout:g} seconds")


def restart_console(tool_root: Path, brain_dir: Path, **options) -> dict:
    stop_console(brain_dir, timeout=float(options.pop("stop_timeout", 10.0)))
    return start_console(tool_root, brain_dir, **options)


def run_console_worker(
    tool_root: Path,
    brain_dir: Path,
    default_db: Path | None,
    default_project: str | None,
    host: str,
    port: int,
    state_file: Path,
    stop_file: Path,
    lock_file: Path,
    token_file: Path,
) -> int:
    launch_secret = os.environ.pop("RTA_SMIRTI_CONSOLE_LAUNCH_SECRET", "")
    capability = os.environ.pop("RTA_SMIRTI_CONSOLE_CAPABILITY", "")
    instance_id = os.environ.pop("RTA_SMIRTI_CONSOLE_INSTANCE_ID", "")
    detach_current_worker_session()
    if not launch_secret or not capability or not instance_id:
        raise RuntimeError("console launch credentials are missing")
    worker_identity = process_identity(os.getpid())
    if not worker_identity:
        raise RuntimeError("console worker process identity is unavailable")
    fingerprint = hashlib.sha256(launch_secret.encode("ascii")).hexdigest()
    if not is_safe_regular_file(lock_file):
        raise RuntimeError("console launch lock is missing or linked")
    if lock_file.read_text(encoding="ascii", errors="ignore").strip() != fingerprint:
        raise RuntimeError("console launch lock does not match")

    state = {
        "brain_dir": str(brain_dir.expanduser().resolve()),
        "pid": os.getpid(),
        "process_identity": worker_identity,
        "instance_id": instance_id,
        "launch_fingerprint": fingerprint,
        "state": "starting",
        "host": host,
        "port": None,
        "started_at": now_iso(),
        "heartbeat_at": now_iso(),
        "last_error": None,
        "startup_stage": "loading_console",
    }
    if bool(getattr(sys, "frozen", False)):
        launcher_pid = os.getppid()
        launcher_identity = process_identity(launcher_pid)
        if launcher_identity:
            state["launcher_pid"] = launcher_pid
            state["launcher_process_identity"] = launcher_identity
    server = None
    should_stop = False

    def request_stop(_signum=None, _frame=None) -> None:
        nonlocal should_stop
        should_stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        write_json(state_file, state, label="console state")
        print("rta-smriti console stage=loading_console", file=sys.stderr, flush=True)
        from .console import create_dashboard_server

        state["startup_stage"] = "binding_loopback"
        write_json(state_file, state, label="console state")
        print("rta-smriti console stage=binding_loopback", file=sys.stderr, flush=True)
        server, _config, _url = create_dashboard_server(
            tool_root,
            brain_dir,
            default_db=default_db,
            default_project=default_project,
            host=host,
            port=port,
            capability_token=capability,
            instance_id=instance_id,
        )
        server.timeout = 0.25
        state["port"] = int(server.server_address[1])
        write_secret(token_file, capability, label="console capability")
        state["state"] = "running"
        state["startup_stage"] = "running"
        write_json(state_file, state, label="console state")
        last_heartbeat = time.monotonic()
        while not should_stop and not stop_requested(stop_file, label="console"):
            server.handle_request()
            if time.monotonic() - last_heartbeat >= 2.0:
                state["heartbeat_at"] = now_iso()
                write_json(state_file, state, label="console state")
                last_heartbeat = time.monotonic()
        state["state"] = "stopping"
        state["heartbeat_at"] = now_iso()
        write_json(state_file, state, label="console state")
        return 0
    except Exception as exc:
        state["state"] = "error"
        state["last_error"] = f"{exc.__class__.__name__}: {exc}"
        state["heartbeat_at"] = now_iso()
        write_json(state_file, state, label="console state")
        return 1
    finally:
        if server is not None:
            server.wait_for_idle(timeout=5.0)
            server.server_close()
        if state.get("state") != "error":
            state["state"] = "stopped"
            state["stopped_at"] = now_iso()
            state["heartbeat_at"] = now_iso()
            write_json(state_file, state, label="console state")
        for path in (stop_file, token_file):
            if is_safe_regular_file(path):
                path.unlink(missing_ok=True)
        try:
            if is_safe_regular_file(lock_file) and lock_file.read_text(encoding="ascii", errors="ignore").strip() == fingerprint:
                lock_file.unlink(missing_ok=True)
        except OSError:
            pass
