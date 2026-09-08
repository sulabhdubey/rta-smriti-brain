"""Quiet, singular, explicitly enrolled background federation synchronization."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import signal
import sys
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import db
from .federation_crypto import load_identity
from .federation_http_relay import FederationHttpRelay
from .federation_transport import (
    MAX_RELAY_OBJECTS,
    FederationTransportError,
    FilesystemFederationRelay,
    apply_sync_operation,
    preview_sync_operation,
)
from .runtime_control import (
    clear_control_files,
    create_secret,
    detached_worker_bootstrap,
    is_safe_regular_file,
    now_iso,
    open_log,
    prepare_control_dir,
    process_alive,
    process_identity,
    read_json,
    read_secret,
    runtime_executable,
    settle_worker,
    spawn_detached_worker,
    stop_requested,
    terminate_worker,
    write_json,
    write_stop_request,
)

CONFIG_SCHEMA = "rta-smriti.federation-sync-config/v1"
STATE_SCHEMA = "rta-smriti.federation-sync-state/v1"
_ACTIVE_STATES = frozenset({"starting", "running", "stopping"})
_SPAWNED_PROCESSES: dict[str, Any] = {}


def _fingerprint(value: object) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identifier(name: str, value: object) -> str:
    selected = str(value or "")
    if (
        len(selected) != 64
        or any(char not in "0123456789abcdef" for char in selected)
        or set(selected) == {"0"}
    ):
        raise ValueError(f"{name} must be a non-zero lower-case SHA-256 identifier")
    return selected


def _bounded_text(name: str, value: object, *, maximum: int = 256) -> str:
    selected = str(value or "").strip()
    if not selected or len(selected) > maximum or "\0" in selected:
        raise ValueError(f"{name} must be a bounded non-empty string")
    return selected


def federation_sync_paths(db_path: Path, project: str) -> dict[str, Path]:
    database = Path(db_path).expanduser().resolve()
    key = hashlib.sha256(
        f"federation-sync\0{database}\0{project}".encode()
    ).hexdigest()[:12]
    directory = database.parent / ".rta-smriti-daemons"
    stem = f"{database.stem}-federation-{key}"
    return {
        "directory": directory,
        "config": directory / f"{stem}.config.json",
        "state": directory / f"{stem}.json",
        "stop": directory / f"{stem}.stop",
        "lock": directory / f"{stem}.lock",
        "log": directory / f"{stem}.log",
    }


def _safe_directory(path: Path, *, label: str) -> Path:
    selected = path.expanduser().resolve()
    if not selected.is_dir() or selected.is_symlink():
        raise ValueError(f"{label} must be an existing unlinked directory")
    return selected


def _validated_config(config: Mapping[str, Any]) -> dict[str, Any]:
    database = Path(config.get("db_path", "")).expanduser().resolve()
    if not is_safe_regular_file(database):
        raise ValueError("federation sync database must be an existing unlinked file")
    project = _bounded_text("project", config.get("project"))
    identity_dir = _safe_directory(
        Path(config.get("identity_dir", "")), label="federation identity"
    )
    passphrase_file = Path(config.get("passphrase_file", "")).expanduser().resolve()
    read_secret(passphrase_file, label="federation identity passphrase")
    selected: dict[str, Any] = {
        "schema": CONFIG_SCHEMA,
        "db_path": str(database),
        "project": project,
        "space_id": _identifier("space_id", config.get("space_id")),
        "scope_id": _identifier("scope_id", config.get("scope_id")),
        "identity_dir": str(identity_dir),
        "passphrase_file": str(passphrase_file),
        "transport_id": _bounded_text("transport_id", config.get("transport_id")),
        "limit": int(config.get("limit", MAX_RELAY_OBJECTS)),
        "interval_seconds": float(config.get("interval_seconds", 30.0)),
    }
    if not 1 <= selected["limit"] <= MAX_RELAY_OBJECTS:
        raise ValueError("federation sync limit is outside the supported range")
    if not 2.0 <= selected["interval_seconds"] <= 3_600.0:
        raise ValueError("federation sync interval must be between 2 and 3,600 seconds")
    relay_kind = str(config.get("relay_kind") or "").strip().casefold()
    selected["relay_kind"] = relay_kind
    if relay_kind == "filesystem":
        selected["relay_root"] = str(
            _safe_directory(
                Path(config.get("relay_root", "")), label="federation relay"
            )
        )
    elif relay_kind == "http":
        relay_url = _bounded_text("relay_url", config.get("relay_url"), maximum=2048).rstrip("/")
        parsed = urlsplit(relay_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("federation relay URL must use HTTP or HTTPS")
        if parsed.username or parsed.password or parsed.fragment or parsed.query:
            raise ValueError("federation relay URL must not contain credentials, query, or fragment")
        if parsed.scheme == "http" and parsed.hostname not in {
            "127.0.0.1", "::1", "localhost"
        }:
            raise ValueError("remote federation relay URLs require HTTPS")
        capability_file = Path(
            config.get("relay_capability_file", "")
        ).expanduser().resolve()
        read_secret(capability_file, label="federation relay capability")
        selected["relay_url"] = relay_url
        selected["relay_capability_file"] = str(capability_file)
    else:
        raise ValueError("federation relay kind must be filesystem or http")
    return selected


def _public_configuration(config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "configuration_digest": _digest(config),
        "project_fingerprint": _fingerprint(config["project"]),
        "database_fingerprint": _fingerprint(config["db_path"]),
        "identity_fingerprint": _fingerprint(config["identity_dir"]),
        "relay_fingerprint": _fingerprint(
            config.get("relay_root") or config.get("relay_url")
        ),
        "relay_kind": config["relay_kind"],
        "space_id": config["space_id"],
        "scope_id": config["scope_id"],
        "transport_id": config["transport_id"],
        "interval_seconds": config["interval_seconds"],
        "limit": config["limit"],
    }


def preview_federation_sync_configuration(
    config: Mapping[str, Any],
) -> dict[str, Any]:
    selected = _validated_config(config)
    public = _public_configuration(selected)
    confirmation = hashlib.sha256(
        b"rta-smriti-federation-sync-config-v1\0"
        + str(public["configuration_digest"]).encode("ascii")
    ).hexdigest()
    return {
        "status": "ok",
        "state": "preview",
        **public,
        "confirmation_digest": confirmation,
        "writes_performed": False,
    }


def configure_federation_sync(
    config: Mapping[str, Any], *, confirmation_digest: str
) -> dict[str, Any]:
    """Persist one exact private sync enrollment after a matching preview."""

    preview = preview_federation_sync_configuration(config)
    if not hmac.compare_digest(
        str(confirmation_digest), str(preview["confirmation_digest"])
    ):
        raise PermissionError("federation sync configuration changed after preview")
    selected = _validated_config(config)
    paths = federation_sync_paths(Path(selected["db_path"]), selected["project"])
    prepare_control_dir(paths["directory"], label="federation sync")
    current = federation_sync_status(Path(selected["db_path"]), selected["project"])
    if current["state"] in _ACTIVE_STATES:
        raise RuntimeError("stop federation sync before changing its configuration")
    if paths["config"].exists():
        existing = read_json(paths["config"])
        if existing is None:
            raise ValueError("federation sync configuration is malformed")
        if hmac.compare_digest(_digest(existing), _digest(selected)):
            return {
                "status": "ok",
                "state": "configured",
                **_public_configuration(selected),
                "idempotent_replay": True,
            }
    write_json(paths["config"], selected, label="federation sync configuration")
    clear_control_files(paths, ("state", "stop", "lock"))
    return {
        "status": "ok",
        "state": "configured",
        **_public_configuration(selected),
        "idempotent_replay": False,
    }


def _load_config(db_path: Path, project: str) -> tuple[dict[str, Any], dict[str, Path]]:
    paths = federation_sync_paths(db_path, project)
    payload = read_json(paths["config"])
    if payload is None:
        raise ValueError("federation sync is not configured")
    selected = _validated_config(payload)
    if Path(selected["db_path"]) != Path(db_path).expanduser().resolve() or selected["project"] != project:
        raise ValueError("federation sync configuration binding does not match")
    return selected, paths


def _heartbeat_fresh(payload: Mapping[str, Any]) -> bool:
    try:
        heartbeat = datetime.fromisoformat(str(payload["heartbeat_at"]))
        if heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=UTC)
        age = (datetime.now(UTC) - heartbeat.astimezone(UTC)).total_seconds()
        interval = float(payload.get("interval_seconds", 30.0))
        return -5.0 <= age <= max(20.0, min(interval, 30.0) * 4)
    except (KeyError, TypeError, ValueError):
        return False


def federation_sync_status(db_path: Path, project: str) -> dict[str, Any]:
    paths = federation_sync_paths(db_path, project)
    config = read_json(paths["config"])
    if config is None:
        return {"status": "ok", "state": "not_configured"}
    try:
        selected = _validated_config(config)
    except (OSError, TypeError, ValueError):
        return {"status": "attention_required", "state": "invalid_configuration"}
    public_config = _public_configuration(selected)
    state = read_json(paths["state"])
    if state is None:
        return {"status": "ok", "state": "configured", **public_config}
    public = {
        key: state.get(key)
        for key in (
            "schema", "state", "pid", "process_identity", "started_at",
            "heartbeat_at", "last_cycle_at", "last_success_at", "sync_state",
            "cycles", "successful_cycles", "consecutive_failures", "error_class",
            "local_event_count", "relay_event_count", "local_only_count",
            "relay_only_count", "comparison_digest", "configuration_digest",
        )
        if key in state
    }
    observed_state = str(public.get("state") or "unknown")
    if observed_state in _ACTIVE_STATES:
        alive = process_alive(public.get("pid"))
        actual = process_identity(public.get("pid")) if alive else None
        expected = str(public.get("process_identity") or "")
        matches = bool(actual and expected and hmac.compare_digest(str(actual), expected))
        public["process_alive"] = alive
        public["process_identity_matches"] = matches
        if not alive or not matches or not _heartbeat_fresh(public):
            observed_state = "stale"
    return {
        "status": "ok" if observed_state in {"configured", "running", "stopped"} else "attention_required",
        **public_config,
        **public,
        "state": observed_state,
    }


def _relay(config: Mapping[str, Any]):
    if config["relay_kind"] == "filesystem":
        return FilesystemFederationRelay(Path(config["relay_root"]))
    capability = read_secret(
        Path(config["relay_capability_file"]), label="federation relay capability"
    )
    return FederationHttpRelay(str(config["relay_url"]), capability=capability)


def perform_federation_sync_cycle(db_path: Path, project: str) -> dict[str, Any]:
    """Run one bounded repair cycle and return content-free operational evidence."""

    try:
        config, _paths = _load_config(db_path, project)
        passphrase = read_secret(
            Path(config["passphrase_file"]), label="federation identity passphrase"
        ).encode("utf-8")
        identity = load_identity(Path(config["identity_dir"]), passphrase=passphrase)
        relay = _relay(config)
        connection = db.connect(Path(config["db_path"]))
        try:
            db.init_schema(connection)
            project_row = connection.execute(
                "SELECT id FROM projects WHERE name = ?", (config["project"],)
            ).fetchone()
            if project_row is None:
                raise ValueError("configured federation project does not exist")
            common = {
                "project_id": int(project_row["id"]),
                "space_id": config["space_id"],
                "scope_id": config["scope_id"],
                "actor": identity,
                "relay": relay,
                "action": "repair",
                "transport_id": config["transport_id"],
                "limit": int(config["limit"]),
            }
            preview = preview_sync_operation(connection, **common)
            result = apply_sync_operation(
                connection,
                **common,
                confirmation_digest=str(preview["confirmation_digest"]),
            )
        finally:
            connection.close()
        return {
            "state": str(result["state"]),
            "pushed": int(result["pushed"]),
            "pulled": int(result["pulled"]),
            "accepted": int(result["accepted"]),
            "already_present": int(result["already_present"]),
            "local_event_count": int(result["local_event_count"]),
            "relay_event_count": int(result["relay_event_count"]),
            "local_only_count": int(result["local_only_count"]),
            "relay_only_count": int(result["relay_only_count"]),
            "comparison_digest": str(result["comparison_digest"]),
            "error_class": None,
        }
    except FederationTransportError as exc:
        return {"state": "offline", "error_class": exc.__class__.__name__}
    except Exception as exc:  # noqa: BLE001 - isolate a failed cycle from the service
        return {"state": "degraded", "error_class": exc.__class__.__name__}


def _worker_command(paths: Mapping[str, Path]) -> list[str]:
    suffix = [
        "--config-file", str(paths["config"]),
        "--state-file", str(paths["state"]),
        "--stop-file", str(paths["stop"]),
        "--lock-file", str(paths["lock"]),
    ]
    if getattr(sys, "frozen", False):
        return [str(runtime_executable()), "_federation-sync-worker", *suffix]
    return [
        str(runtime_executable()),
        "-I",
        "-c",
        detached_worker_bootstrap(
            "rta_brain.federation_worker", Path(__file__).resolve().parents[1]
        ),
        *suffix,
    ]


def start_federation_sync(
    db_path: Path, project: str, *, startup_timeout: float = 10.0
) -> dict[str, Any]:
    config, paths = _load_config(db_path, project)
    current = federation_sync_status(db_path, project)
    if current["state"] in _ACTIVE_STATES:
        return current
    if current["state"] == "stale" and current.get("process_alive"):
        raise RuntimeError(
            "existing federation sync process is alive but unresponsive; stop it first"
        )
    prepare_control_dir(paths["directory"], label="federation sync")
    if paths["lock"].exists():
        raise RuntimeError("federation sync launch is already in progress")
    clear_control_files(paths, ("state", "stop"))
    token = os.urandom(32).hex()
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    try:
        create_secret(paths["lock"], token_hash, label="federation sync launch lock")
    except FileExistsError as exc:
        raise RuntimeError("federation sync launch is already in progress") from exc
    log_stream = open_log(paths["log"], label="federation sync")
    try:
        process = spawn_detached_worker(
            _worker_command(paths),
            log_stream,
            {**os.environ, "RTA_SMIRTI_FEDERATION_SYNC_TOKEN": token},
            Path(__file__).resolve().parents[1],
        )
    except Exception:
        paths["lock"].unlink(missing_ok=True)
        raise
    finally:
        log_stream.close()
    deadline = time.monotonic() + max(0.1, float(startup_timeout))
    while time.monotonic() < deadline:
        state = federation_sync_status(db_path, project)
        if state.get("configuration_digest") == _digest(config) and state["state"] == "running":
            _SPAWNED_PROCESSES[str(paths["state"])] = process
            return state
        if process.poll() is not None:
            break
        time.sleep(0.05)
    write_stop_request(paths["stop"], label="federation sync")
    terminate_worker(process, timeout=5)
    paths["lock"].unlink(missing_ok=True)
    raise RuntimeError("federation sync service did not become ready")


def stop_federation_sync(
    db_path: Path, project: str, *, timeout: float = 10.0
) -> dict[str, Any]:
    paths = federation_sync_paths(db_path, project)
    state = federation_sync_status(db_path, project)
    if state["state"] in {"not_configured", "configured", "stopped", "invalid_configuration"} or (
        state["state"] == "stale" and not state.get("process_alive")
    ):
        clear_control_files(paths, ("state", "stop", "lock"))
        return {**state, "state": "configured" if paths["config"].exists() else "not_configured"}
    write_stop_request(paths["stop"], label="federation sync")
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        state = federation_sync_status(db_path, project)
        if state["state"] == "stopped" or (
            state["state"] == "stale" and not state.get("process_alive")
        ):
            process = _SPAWNED_PROCESSES.pop(str(paths["state"]), None)
            if process is not None:
                settle_worker(process, timeout=1)
            clear_control_files(paths, ("state", "stop", "lock"))
            return {**state, "state": "configured"}
        time.sleep(0.05)
    raise TimeoutError(f"federation sync service did not stop within {timeout:g} seconds")


def remove_federation_sync(db_path: Path, project: str) -> dict[str, Any]:
    paths = federation_sync_paths(db_path, project)
    state = federation_sync_status(db_path, project)
    if state["state"] in _ACTIVE_STATES:
        raise RuntimeError("stop federation sync before removing its configuration")
    clear_control_files(paths, ("config", "state", "stop", "lock", "log"))
    return {"status": "ok", "state": "not_configured"}


def preview_federation_sync_daemon_operation(
    db_path: Path, project: str, *, action: str
) -> dict[str, Any]:
    """Preview one exact managed-sync control operation without writing."""

    selected_action = str(action).strip().casefold()
    if selected_action not in {"start", "stop", "cycle", "remove"}:
        raise ValueError("federation sync daemon action is unsupported")
    status = federation_sync_status(db_path, project)
    state = str(status["state"])
    if selected_action in {"start", "cycle", "remove"} and state in _ACTIVE_STATES:
        raise RuntimeError(
            f"federation sync must be stopped before {selected_action}"
        )
    if selected_action == "start" and state not in {"configured", "stopped", "stale"}:
        raise RuntimeError("federation sync must be configured before start")
    if selected_action == "cycle" and state not in {"configured", "stopped"}:
        raise RuntimeError("federation sync must be configured and stopped before a cycle")
    if selected_action == "remove" and state == "not_configured":
        raise RuntimeError("federation sync is not configured")
    if selected_action == "stop" and state not in _ACTIVE_STATES:
        raise RuntimeError("federation sync is not running")
    observed = {
        key: status.get(key)
        for key in (
            "state", "pid", "process_identity", "process_identity_matches",
            "configuration_digest", "sync_state", "comparison_digest",
        )
        if key in status
    }
    intent = {
        "action": selected_action,
        "project_fingerprint": _fingerprint(project),
        "database_fingerprint": _fingerprint(Path(db_path).expanduser().resolve()),
        "observed": observed,
    }
    return {
        "status": "ok",
        "state": "preview",
        "action": selected_action,
        "observed": observed,
        "confirmation_digest": hashlib.sha256(
            b"rta-smriti-federation-sync-daemon-v1\0"
            + json.dumps(
                intent, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        ).hexdigest(),
        "writes_performed": False,
    }


def apply_federation_sync_daemon_operation(
    db_path: Path,
    project: str,
    *,
    action: str,
    confirmation_digest: str,
) -> dict[str, Any]:
    """Apply a daemon operation only while its stable public state is unchanged."""

    preview = preview_federation_sync_daemon_operation(
        db_path, project, action=action
    )
    if not hmac.compare_digest(
        str(confirmation_digest), str(preview["confirmation_digest"])
    ):
        raise PermissionError("federation sync daemon state changed after preview")
    selected_action = str(preview["action"])
    if selected_action == "start":
        return start_federation_sync(db_path, project)
    if selected_action == "stop":
        return stop_federation_sync(db_path, project)
    if selected_action == "cycle":
        return {"status": "ok", **perform_federation_sync_cycle(db_path, project)}
    return remove_federation_sync(db_path, project)


def run_federation_sync_worker(
    config_file: Path, state_file: Path, stop_file: Path, lock_file: Path
) -> int:
    token = os.environ.get("RTA_SMIRTI_FEDERATION_SYNC_TOKEN", "")
    if not token:
        raise RuntimeError("federation sync launch token is missing")
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    if not hmac.compare_digest(
        read_secret(lock_file, label="federation sync launch lock"), token_hash
    ):
        raise RuntimeError("federation sync launch lock does not match")
    raw = read_json(config_file)
    if raw is None:
        raise ValueError("federation sync configuration is malformed")
    config = _validated_config(raw)
    expected_paths = federation_sync_paths(Path(config["db_path"]), config["project"])
    if any(
        Path(observed).resolve() != expected_paths[name].resolve()
        for name, observed in {
            "config": config_file,
            "state": state_file,
            "stop": stop_file,
            "lock": lock_file,
        }.items()
    ):
        raise ValueError("federation sync worker control binding does not match")
    identity = process_identity(os.getpid())
    if identity is None:
        raise RuntimeError("federation sync worker could not establish process identity")
    stop_event = threading.Event()
    state: dict[str, Any] = {
        "schema": STATE_SCHEMA,
        "state": "starting",
        "pid": os.getpid(),
        "process_identity": identity,
        "configuration_digest": _digest(config),
        "interval_seconds": config["interval_seconds"],
        "started_at": now_iso(),
        "heartbeat_at": now_iso(),
        "last_cycle_at": None,
        "last_success_at": None,
        "sync_state": "pending",
        "cycles": 0,
        "successful_cycles": 0,
        "consecutive_failures": 0,
        "error_class": None,
    }
    state_lock = threading.Lock()
    heartbeat_stop = threading.Event()

    def request_stop(_signum=None, _frame=None):
        stop_event.set()

    def persist():
        with state_lock:
            state["heartbeat_at"] = now_iso()
            write_json(state_file, dict(state), label="federation sync state")

    def heartbeat():
        while not heartbeat_stop.wait(5.0):
            persist()

    def wait_until_cycle_or_stop(delay: float) -> None:
        deadline = time.monotonic() + max(0.0, float(delay))
        while not stop_event.is_set() and time.monotonic() < deadline:
            if stop_requested(stop_file, label="federation sync"):
                stop_event.set()
                return
            stop_event.wait(min(0.25, max(0.0, deadline - time.monotonic())))

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        state["state"] = "running"
        persist()
        thread = threading.Thread(
            target=heartbeat, name="rta-federation-sync-heartbeat", daemon=True
        )
        thread.start()
        while not stop_event.is_set() and not stop_requested(
            stop_file, label="federation sync"
        ):
            result = perform_federation_sync_cycle(
                Path(config["db_path"]), config["project"]
            )
            state["cycles"] += 1
            state["sync_state"] = result["state"]
            state["error_class"] = result.get("error_class")
            for key in (
                "local_event_count", "relay_event_count", "local_only_count",
                "relay_only_count", "comparison_digest",
            ):
                if key in result:
                    state[key] = result[key]
            if result["state"] == "healthy":
                state["successful_cycles"] += 1
                state["consecutive_failures"] = 0
                state["last_success_at"] = now_iso()
            else:
                state["consecutive_failures"] += 1
            state["last_cycle_at"] = now_iso()
            persist()
            delay = min(
                300.0,
                float(config["interval_seconds"])
                * (2 ** min(int(state["consecutive_failures"]), 4)),
            )
            wait_until_cycle_or_stop(delay)
        state["state"] = "stopping"
        persist()
        state["state"] = "stopped"
        state["stopped_at"] = now_iso()
        persist()
        return 0
    except Exception as exc:  # noqa: BLE001 - persist only a safe class name
        state["state"] = "error"
        state["error_class"] = exc.__class__.__name__
        persist()
        return 1
    finally:
        heartbeat_stop.set()
        lock_file.unlink(missing_ok=True)
        stop_file.unlink(missing_ok=True)
