"""One-per-brain supervisor that drains private capture spools into the journal."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import signal
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import db
from .capture import append_event, validate_capture_identifiers
from .capture_adapters import normalize_capture_event
from .capture_spool import CaptureSpool, SpoolError, source_token
from .capture_types import CapturePolicy, NormalizedEvent
from .repository import same_root
from .runtime_control import (
    clear_control_files,
    create_secret,
    detached_worker_bootstrap,
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

_SPAWNED_PROCESSES: dict[str, Any] = {}
CAPTURE_INGRESS_FIELDS = frozenset(
    {
        "normalized_event",
        "cursor_kind",
        "original_bytes",
        "source_binding",
    }
)


def _normalized_event_document(event: NormalizedEvent) -> dict[str, Any]:
    return {
        "event_name": event.event_name,
        "session_id": event.session_id,
        "source_cursor": event.source_cursor,
        "observed_at": event.observed_at,
        "attributes": dict(event.attributes),
        "external_event_id": event.external_event_id,
        "occurred_at": event.occurred_at,
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "parent_span_id": event.parent_span_id,
        "causation_event_id": event.causation_event_id,
        "correlation_id": event.correlation_id,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
    }


def _normalized_event_from_document(value: Any) -> NormalizedEvent:
    if not isinstance(value, dict):
        raise TypeError("capture spool record requires a normalized event object")
    expected = {
        "event_name",
        "session_id",
        "source_cursor",
        "observed_at",
        "attributes",
        "external_event_id",
        "occurred_at",
        "trace_id",
        "span_id",
        "parent_span_id",
        "causation_event_id",
        "correlation_id",
        "actor_type",
        "actor_id",
    }
    if set(value) != expected:
        raise ValueError("capture normalized event fields are invalid")
    return NormalizedEvent(**value)


def prepare_capture_spool_record(
    conn,
    *,
    project: str,
    active_root: Path,
    source_id: str,
    record: dict[str, Any],
    original_bytes: int,
) -> dict[str, Any]:
    """Normalize and policy-filter one vendor record before durable spooling."""

    source = next(
        (
            candidate
            for candidate in _active_sources(conn)
            if candidate["project"] == project and candidate["source_id"] == source_id
        ),
        None,
    )
    if source is None:
        raise ValueError("capture emit requires an active registered source")
    if not same_root(str(source["root_path"]), active_root):
        raise ValueError("capture emit requires the exact canonical project root")
    unknown_fields = set(record).difference(
        {
            "source_cursor",
            "cursor_kind",
            "session_id",
            "observed_at",
            "occurred_at",
            "vendor_event",
            "payload",
        }
    )
    if unknown_fields:
        raise ValueError("capture emit contains unsupported envelope fields")
    payload = record.get("payload")
    if not isinstance(payload, dict):
        raise TypeError("capture emit requires an object payload")
    if record.get("occurred_at") is not None and "timestamp" not in payload:
        payload = {**payload, "timestamp": record["occurred_at"]}
    normalized = normalize_capture_event(
        str(source["adapter"]),
        payload,
        vendor_event=record.get("vendor_event"),
        trusted_workspace_roots=(str(source["root_path"]),),
        adapter_version=str(source["adapter_version"]),
        source_cursor=_record_value(record, "source_cursor"),
        observed_at=_record_value(record, "observed_at"),
        session_id=_record_value(record, "session_id"),
        policy=_bound_policy(source),
    )
    if normalized is None:
        raise ValueError("capture event is disabled by the bound policy")
    validate_capture_identifiers(normalized)
    return {
        "normalized_event": _normalized_event_document(normalized),
        "cursor_kind": str(record.get("cursor_kind") or "opaque"),
        "original_bytes": original_bytes,
        "source_binding": source_token(source_id, project=project),
    }


def capture_paths(db_path: Path) -> dict[str, Path]:
    database = db_path.expanduser().resolve()
    key = hashlib.sha256(f"capture\0{database}".encode()).hexdigest()[:12]
    directory = database.parent / ".rta-smriti-daemons"
    stem = f"{database.stem}-capture-{key}"
    return {
        "directory": directory,
        "state": directory / f"{stem}.json",
        "stop": directory / f"{stem}.stop",
        "lock": directory / f"{stem}.lock",
        "log": directory / f"{stem}.log",
    }


def _heartbeat_fresh(payload: dict[str, Any]) -> bool:
    try:
        heartbeat = datetime.fromisoformat(str(payload["heartbeat_at"]))
        if heartbeat.tzinfo is None:
            heartbeat = heartbeat.replace(tzinfo=UTC)
        age = (datetime.now(UTC) - heartbeat.astimezone(UTC)).total_seconds()
        return -5.0 <= age <= max(15.0, float(payload.get("interval_seconds", 1.0)) * 4)
    except (KeyError, TypeError, ValueError):
        return False


def capture_status(db_path: Path) -> dict[str, Any]:
    database = db_path.expanduser().resolve()
    paths = capture_paths(database)
    if not paths["state"].exists():
        return {"status": "ok", "state": "stopped", "db_path": str(database)}
    payload = read_json(paths["state"])
    if payload is None:
        return {
            "status": "error",
            "state": "error",
            "db_path": str(database),
            "reason": "invalid_state",
        }
    state = str(payload.get("state") or "unknown")
    if state in {"starting", "running", "stopping", "draining"}:
        alive = process_alive(payload.get("pid"))
        actual_identity = process_identity(payload.get("pid")) if alive else None
        expected_identity = payload.get("process_identity")
        identity_matches = bool(
            actual_identity
            and expected_identity
            and hmac.compare_digest(str(actual_identity), str(expected_identity))
        )
        payload["process_alive"] = alive
        payload["process_identity_matches"] = identity_matches
        if not alive or not identity_matches or not _heartbeat_fresh(payload):
            state = "stale"
    return {"status": "ok", **payload, "state": state}


def _worker_command(
    db_path: Path,
    paths: dict[str, Path],
    interval_seconds: float,
    batch_size: int,
) -> list[str]:
    suffix = [
        "--db",
        str(db_path),
        "--state-file",
        str(paths["state"]),
        "--stop-file",
        str(paths["stop"]),
        "--lock-file",
        str(paths["lock"]),
        "--interval",
        str(interval_seconds),
        "--batch-size",
        str(batch_size),
    ]
    if getattr(sys, "frozen", False):
        return [str(runtime_executable()), "_capture-worker", *suffix]
    return [
        str(runtime_executable()),
        "-I",
        "-c",
        detached_worker_bootstrap(
            "rta_brain.capture_daemon", Path(__file__).resolve().parents[1]
        ),
        *suffix,
    ]


def _prepare_launch_claim(
    paths: dict[str, Path], *, stale_after_seconds: float = 30.0
) -> None:
    clear_control_files(paths, ("state", "stop"))
    lock = paths["lock"]
    if not lock.exists():
        return
    try:
        age = time.time() - lock.stat().st_mtime
    except OSError as exc:
        raise RuntimeError("capture launch claim cannot be inspected") from exc
    if age < stale_after_seconds:
        raise RuntimeError("another capture start already owns this brain")
    if not lock.is_file() or lock.is_symlink() or lock.stat().st_nlink > 1:
        raise RuntimeError("stale capture launch claim is unsafe")
    lock.unlink()


def _release_launch_claim(paths: dict[str, Path], token_hash: str) -> None:
    try:
        stored = read_secret(paths["lock"], label="capture launch lock")
    except (OSError, ValueError):
        return
    if hmac.compare_digest(stored, token_hash):
        paths["lock"].unlink(missing_ok=True)
        paths["stop"].unlink(missing_ok=True)


def start_capture(
    db_path: Path,
    *,
    interval_seconds: float = 1.0,
    batch_size: int = 100,
    startup_timeout: float = 10.0,
) -> dict[str, Any]:
    database = db_path.expanduser().resolve()
    interval = float(interval_seconds)
    batch = int(batch_size)
    if not database.is_file() or database.is_symlink() or database.stat().st_nlink > 1:
        raise ValueError(
            f"brain database must be an existing unlinked file: {database}"
        )
    if not 0.1 <= interval <= 3_600:
        raise ValueError("capture interval must be between 0.1 and 3,600 seconds")
    if not 1 <= batch <= 1_000:
        raise ValueError("capture batch size must be between 1 and 1,000")
    paths = capture_paths(database)
    prepare_control_dir(paths["directory"], label="capture")
    current = capture_status(database)
    if current["state"] in {"starting", "running", "stopping", "draining"}:
        return current
    if current["state"] == "stale" and current.get("process_alive"):
        raise RuntimeError(
            "existing capture process is alive but unresponsive; stop it before restarting"
        )
    _prepare_launch_claim(paths)
    token = uuid.uuid4().hex
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    try:
        create_secret(paths["lock"], token_hash, label="capture launch lock")
    except FileExistsError as exc:
        raise RuntimeError("another capture start already owns this brain") from exc
    env = {**os.environ, "RTA_SMIRTI_CAPTURE_TOKEN": token}
    log_stream = open_log(paths["log"], label="capture")
    try:
        process = spawn_detached_worker(
            _worker_command(database, paths, interval, batch),
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
        state = capture_status(database)
        if state.get("token_hash") == token_hash and state["state"] == "running":
            _SPAWNED_PROCESSES[str(paths["state"])] = process
            return state
        if process.poll() is not None:
            break
        time.sleep(0.05)
    write_stop_request(paths["stop"], label="capture")
    terminate_worker(process, timeout=5)
    _release_launch_claim(paths, token_hash)
    raise RuntimeError(
        f"capture service did not become ready within {startup_timeout:g} seconds"
    )


def stop_capture(db_path: Path, timeout: float = 10.0) -> dict[str, Any]:
    paths = capture_paths(db_path)
    state = capture_status(db_path)
    if state["state"] in {"stopped", "error"} or (
        state["state"] == "stale" and not state.get("process_alive")
    ):
        clear_control_files(paths, ("state", "stop", "lock"))
        return {**state, "state": "stopped"}
    write_stop_request(paths["stop"], label="capture")
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        state = capture_status(db_path)
        if state["state"] == "stopped" or (
            state["state"] in {"stale", "error"} and not state.get("process_alive")
        ):
            process = _SPAWNED_PROCESSES.pop(str(paths["state"]), None)
            if process is not None:
                settle_worker(process, timeout=1)
            return {**state, "state": "stopped"}
        time.sleep(0.05)
    raise TimeoutError(f"capture service did not stop within {timeout:g} seconds")


def _active_sources(conn) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            """
        SELECT cs.source_id, cs.adapter, cs.adapter_version, p.name AS project,
               p.root_path, cp.profile, cp.enabled_event_names_json,
               cp.field_allowlist_json, cp.privacy_ceiling, cp.retain_payloads,
               cp.retention_seconds, cp.max_event_bytes, cp.max_field_chars,
               cp.max_collection_items
        FROM capture_sources cs
        JOIN projects p ON p.id = cs.project_id
        JOIN capture_policies cp ON cp.id = cs.policy_row_id
        WHERE cs.state = 'active' AND p.root_path IS NOT NULL
        ORDER BY p.name, cs.source_id
        """
        )
    ]


def _queue_metrics(
    spool: CaptureSpool, sources: list[dict[str, Any]]
) -> tuple[int, float | None, bool]:
    usage = spool.usage_summary()
    depth = int(usage["total_records"])
    oldest_mtime: float | None = None
    inspected = 0
    sample_limit = min(depth, 256)
    for source in sources:
        paths = spool.ensure_source(
            str(source["source_id"]), project=str(source["project"])
        )
        for name in ("inbox", "processing"):
            with os.scandir(paths[name]) as entries:
                for entry in entries:
                    if inspected >= sample_limit:
                        break
                    if not entry.name.endswith(".json"):
                        continue
                    inspected += 1
                    try:
                        modified = entry.stat(follow_symlinks=False).st_mtime
                    except OSError:
                        continue
                    oldest_mtime = (
                        modified
                        if oldest_mtime is None
                        else min(oldest_mtime, modified)
                    )
            if inspected >= sample_limit:
                break
        if inspected >= sample_limit:
            break
    oldest_age = None if oldest_mtime is None else max(0.0, time.time() - oldest_mtime)
    return depth, oldest_age, inspected < depth


def _quarantine_count(spool: CaptureSpool, source_id: str, project: str) -> int:
    return sum(
        1
        for _ in spool.ensure_source(source_id, project=project)["quarantine"].glob(
            "*.json"
        )
    )


def _crash_point(_point: str) -> None:
    """Test seam for deterministic crash-recovery qualification."""


def _bound_policy(source: dict[str, Any]) -> CapturePolicy:
    event_names = json.loads(str(source["enabled_event_names_json"]))
    field_allowlist = json.loads(str(source["field_allowlist_json"]))
    if not isinstance(event_names, list) or not isinstance(field_allowlist, dict):
        raise TypeError("capture policy document has an invalid shape")
    return CapturePolicy(
        profile=str(source["profile"]),
        enabled_event_names=tuple(event_names),
        field_allowlist={key: tuple(value) for key, value in field_allowlist.items()},
        privacy_ceiling=str(source["privacy_ceiling"]),
        retain_payloads=bool(source["retain_payloads"]),
        retention_seconds=int(source["retention_seconds"]),
        max_event_bytes=int(source["max_event_bytes"]),
        max_field_chars=int(source["max_field_chars"]),
        max_collection_items=int(source["max_collection_items"]),
    )


def _update_source_health(
    conn,
    source_id: str,
    project: str,
    *,
    captured: bool,
    error_class: str | None,
) -> None:
    timestamp = now_iso()
    conn.execute(
        """
        UPDATE capture_sources
        SET last_heartbeat_at = ?, last_event_at = CASE WHEN ? THEN ? ELSE last_event_at END,
            last_error_class = ?,
            consecutive_errors = CASE WHEN ? IS NULL THEN 0 ELSE consecutive_errors + 1 END,
            updated_at = ?
        WHERE source_id = ? AND project_id = (SELECT id FROM projects WHERE name = ?)
        """,
        (
            timestamp,
            int(captured),
            timestamp,
            error_class,
            error_class,
            timestamp,
            source_id,
            project,
        ),
    )
    conn.commit()


def _record_value(record: dict[str, Any], key: str, *, required: bool = True) -> Any:
    value = record.get(key)
    if required and (not isinstance(value, str) or not value.strip()):
        raise ValueError(f"capture spool record requires {key}")
    return value


def capture_cycle(
    conn,
    db_path: Path,
    *,
    max_events: int = 100,
    max_seconds: float = 0.25,
    abandoned_after_seconds: float = 60.0,
    start_offset: int = 0,
    propagate_crash: bool = False,
) -> dict[str, Any]:
    if not 1 <= int(max_events) <= 1_000:
        raise ValueError("max_events must be between 1 and 1,000")
    if float(max_seconds) <= 0:
        raise ValueError("max_seconds must be positive")
    db.init_schema(conn)
    sources = _active_sources(conn)
    if sources:
        offset = int(start_offset) % len(sources)
        sources = sources[offset:] + sources[:offset]
    spool = CaptureSpool(Path(db_path).expanduser().resolve())
    counters = {
        "sources_visited": 0,
        "events_inserted": 0,
        "duplicates": 0,
        "gaps": 0,
        "quarantined": 0,
        "failures": 0,
    }
    started = time.monotonic()
    exhausted: set[str] = set()
    for source in sources:
        project = str(source["project"])
        recovery = spool.recover_abandoned(
            str(source["source_id"]),
            project=project,
            older_than_seconds=abandoned_after_seconds,
            max_records=max_events,
            max_seconds=min(max_seconds, 0.25),
        )
        counters["quarantined"] += recovery.quarantined
    while sources and counters["events_inserted"] + counters["duplicates"] < max_events:
        progressed = False
        for source in sources:
            if time.monotonic() - started >= max_seconds:
                break
            source_id = str(source["source_id"])
            project = str(source["project"])
            source_namespace = source_token(source_id, project=project)
            if source_namespace in exhausted:
                continue
            counters["sources_visited"] += 1
            _crash_point("before_claim")
            try:
                quarantined_before = _quarantine_count(spool, source_id, project)
                claim = spool.claim_next(source_id, project=project)
                newly_quarantined = max(
                    0,
                    _quarantine_count(spool, source_id, project) - quarantined_before,
                )
                counters["quarantined"] += newly_quarantined
                counters["failures"] += newly_quarantined
            except SpoolError:
                counters["failures"] += 1
                exhausted.add(source_namespace)
                continue
            if claim is None:
                exhausted.add(source_namespace)
                continue
            progressed = True
            _crash_point("after_claim")
            record = claim.payload
            try:
                unknown_fields = set(record).difference(CAPTURE_INGRESS_FIELDS)
                if unknown_fields:
                    raise ValueError(
                        "capture spool record contains unsupported envelope fields"
                    )
                if record.get("source_binding") != source_namespace:
                    raise ValueError("capture spool record source binding is invalid")
                cursor_kind = str(record.get("cursor_kind") or "opaque")
                normalized = _normalized_event_from_document(
                    record.get("normalized_event")
                )
                validate_capture_identifiers(normalized)
                original_bytes = record.get("original_bytes")
                if (
                    type(original_bytes) is not int
                    or not 0 <= original_bytes <= 1_048_576
                ):
                    raise ValueError("capture spool original byte count is invalid")
                _crash_point("before_commit")
                result = append_event(
                    conn,
                    project=str(source["project"]),
                    active_root=str(source["root_path"]),
                    source_id=source_id,
                    event=normalized,
                    idempotency_key=f"spool:{source_id}:{claim.record_id}",
                    cursor_kind=cursor_kind,
                    original_bytes=original_bytes,
                    privacy_class="internal",
                    verification_status="unverified",
                    source_sha256=claim.content_sha256,
                    gap_state="detected"
                    if normalized.event_name == "capture.gap.v1"
                    else "none",
                )
                if result["idempotent_replay"]:
                    counters["duplicates"] += 1
                else:
                    counters["events_inserted"] += 1
                    if normalized.event_name == "capture.gap.v1":
                        counters["gaps"] += 1
                _crash_point("after_commit")
                _crash_point("before_receipt")
                spool.complete(claim)
                _update_source_health(
                    conn,
                    source_id,
                    str(source["project"]),
                    captured=True,
                    error_class=None,
                )
            except (TypeError, ValueError) as exc:
                try:
                    spool.quarantine(
                        claim, f"invalid_{exc.__class__.__name__.lower()}"
                    )
                except SpoolError as quarantine_error:
                    counters["failures"] += 1
                    exhausted.add(source_namespace)
                    _update_source_health(
                        conn,
                        source_id,
                        project,
                        captured=False,
                        error_class=quarantine_error.__class__.__name__,
                    )
                    continue
                counters["quarantined"] += 1
                counters["failures"] += 1
                _update_source_health(
                    conn,
                    source_id,
                    str(source["project"]),
                    captured=False,
                    error_class=exc.__class__.__name__,
                )
            except BaseException:
                counters["failures"] += 1
                if propagate_crash:
                    raise
                exhausted.add(source_namespace)
            if counters["events_inserted"] + counters["duplicates"] >= max_events:
                break
        if (
            not progressed
            or len(exhausted) == len(sources)
            or time.monotonic() - started >= max_seconds
        ):
            break
    depth, oldest_age, age_is_estimate = _queue_metrics(spool, sources)
    usage = spool.usage_summary()
    record_pressure = usage["total_records"] >= max(
        1,
        int(spool.limits.max_total_records * 0.8),
    )
    byte_pressure = usage["total_bytes"] >= max(
        1,
        int(spool.limits.max_total_bytes * 0.8),
    )
    return {
        **counters,
        "queue_depth": depth,
        "queue_bytes": usage["total_bytes"],
        "oldest_event_age_seconds": oldest_age,
        "oldest_event_age_is_estimate": age_is_estimate,
        "backpressure": record_pressure or byte_pressure,
        "next_offset": (int(start_offset) + 1) % max(1, len(sources)),
    }


def run_capture_worker(
    db_path: Path,
    state_file: Path,
    stop_file: Path,
    lock_file: Path,
    *,
    interval_seconds: float,
    batch_size: int,
) -> int:
    token = os.environ.get("RTA_SMIRTI_CAPTURE_TOKEN", "")
    if not token:
        raise RuntimeError("capture launch token is missing")
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    stored_hash = read_secret(lock_file, label="capture launch lock")
    if not hmac.compare_digest(stored_hash, token_hash):
        raise RuntimeError("capture launch lock does not match")
    stop_event = threading.Event()
    identity = process_identity(os.getpid())
    if identity is None:
        raise RuntimeError("capture worker could not establish its process identity")
    counters = {
        "cycles": 0,
        "events_inserted": 0,
        "duplicates": 0,
        "gaps": 0,
        "quarantined": 0,
        "failures": 0,
        "consecutive_failures": 0,
        "queue_depth": 0,
        "queue_bytes": 0,
        "oldest_event_age_seconds": None,
    }
    state: dict[str, Any] = {
        "db_path": str(db_path.expanduser().resolve()),
        "pid": os.getpid(),
        "process_identity": identity,
        "token_hash": token_hash,
        "state": "starting",
        "interval_seconds": float(interval_seconds),
        "batch_size": int(batch_size),
        "started_at": now_iso(),
        "heartbeat_at": now_iso(),
        "last_cycle_at": None,
        "last_error_class": None,
        "backpressure": False,
        **counters,
    }
    state_lock = threading.Lock()
    heartbeat_stop = threading.Event()

    def request_stop(_signum=None, _frame=None):
        stop_event.set()

    def persist():
        with state_lock:
            state["heartbeat_at"] = now_iso()
            write_json(state_file, dict(state), label="capture state")

    def heartbeat():
        cadence = 5.0
        while not heartbeat_stop.wait(cadence):
            persist()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    offset = 0
    try:
        state["state"] = "running"
        persist()
        heartbeat_thread = threading.Thread(
            target=heartbeat, name="rta-capture-heartbeat", daemon=True
        )
        heartbeat_thread.start()
        while not stop_event.is_set() and not stop_requested(
            stop_file, label="capture"
        ):
            try:
                conn = db.connect(db_path)
                try:
                    result = capture_cycle(
                        conn,
                        db_path,
                        max_events=batch_size,
                        max_seconds=0.25,
                        start_offset=offset,
                    )
                finally:
                    conn.close()
                offset = int(result["next_offset"])
                counters["cycles"] += 1
                for key in (
                    "events_inserted",
                    "duplicates",
                    "gaps",
                    "quarantined",
                    "failures",
                ):
                    counters[key] += int(result[key])
                counters["consecutive_failures"] = (
                    counters["consecutive_failures"] + 1 if result["failures"] else 0
                )
                counters["queue_depth"] = int(result["queue_depth"])
                counters["queue_bytes"] = int(result["queue_bytes"])
                counters["oldest_event_age_seconds"] = result[
                    "oldest_event_age_seconds"
                ]
                state["backpressure"] = bool(result["backpressure"])
                state["last_error_class"] = (
                    None if not result["failures"] else "CaptureSourceError"
                )
            except Exception as exc:  # noqa: BLE001 - isolate one source cycle from the daemon
                counters["cycles"] += 1
                counters["failures"] += 1
                counters["consecutive_failures"] += 1
                state["last_error_class"] = exc.__class__.__name__
            state.update(counters)
            state["last_cycle_at"] = now_iso()
            persist()
            sleep_for = (
                float(interval_seconds)
                if counters["queue_depth"] or state["backpressure"]
                else max(2.0, float(interval_seconds))
            )
            stop_event.wait(sleep_for)
        state["state"] = "draining"
        persist()
        for _ in range(1_000):
            conn = db.connect(db_path)
            try:
                result = capture_cycle(
                    conn,
                    db_path,
                    max_events=batch_size,
                    max_seconds=0.25,
                    start_offset=offset,
                )
            finally:
                conn.close()
            offset = int(result["next_offset"])
            for key in (
                "events_inserted",
                "duplicates",
                "gaps",
                "quarantined",
                "failures",
            ):
                counters[key] += int(result[key])
            counters["queue_depth"] = int(result["queue_depth"])
            counters["queue_bytes"] = int(result["queue_bytes"])
            counters["oldest_event_age_seconds"] = result["oldest_event_age_seconds"]
            if not result["queue_depth"] or not (
                result["events_inserted"] or result["duplicates"]
            ):
                break
        state.update(counters)
        state["final_drain_complete"] = counters["queue_depth"] == 0
        state["state"] = "stopped"
        return 0
    except BaseException as exc:  # noqa: BLE001 - persist terminal worker state before cleanup
        state["state"] = "error"
        state["last_error_class"] = exc.__class__.__name__
        return 1
    finally:
        heartbeat_stop.set()
        thread = locals().get("heartbeat_thread")
        if thread is not None:
            thread.join(timeout=10)
        persist()
        lock_file.unlink(missing_ok=True)
        stop_file.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m rta_brain.capture_daemon")
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--state-file", required=True, type=Path)
    parser.add_argument("--stop-file", required=True, type=Path)
    parser.add_argument("--lock-file", required=True, type=Path)
    parser.add_argument("--interval", required=True, type=float)
    parser.add_argument("--batch-size", required=True, type=int)
    args = parser.parse_args(argv)
    return run_capture_worker(
        args.db,
        args.state_file,
        args.stop_file,
        args.lock_file,
        interval_seconds=args.interval,
        batch_size=args.batch_size,
    )


if __name__ == "__main__":
    raise SystemExit(main())
