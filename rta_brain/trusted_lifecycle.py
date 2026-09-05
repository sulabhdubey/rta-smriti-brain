"""Authoritative lifecycle health and planning primitives."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .autostart import autostart_status, disable_autostart, enable_autostart
from .capture_daemon import capture_status, start_capture, stop_capture
from .console_daemon import console_status, start_console, stop_console
from .continuity_daemon import (
    continuity_status,
    public_continuity_status,
    start_continuity,
    stop_continuity,
)
from .db import SCHEMA_VERSION, connect, init_schema
from .mcp_host_lifecycle import (
    host_profile,
    record_fresh_session_proof,
    validate_installed_configuration,
)
from .repository import same_root
from .review_bundle import (
    normalize_audience,
    normalize_evidence_references,
    normalize_privacy_ceiling,
    normalize_redaction_manifest,
)
from .runtime_control import (
    is_safe_regular_file,
    prepare_control_dir,
    process_alive,
    process_identity,
    read_json,
    write_json,
)
from .watch_daemon import start_watcher, stop_watcher, watcher_status

LIFECYCLE_SCHEMA = "rta-smriti.trusted-lifecycle/v1"
SCHEMA_POLICIES = frozenset({"current-only", "migrate-with-backup", "inspect-only"})


class StaleLifecyclePlanError(RuntimeError):
    """The observed state no longer matches the approved lifecycle plan."""


class LifecycleOperationInProgressError(RuntimeError):
    """Another lifecycle mutation currently owns the project operation claim."""


class LifecyclePlan(dict[str, Any]):
    """Public plan payload with path-bound execution context kept out of serialization."""

    def __init__(self, payload: Mapping[str, Any], request: Mapping[str, Any]) -> None:
        super().__init__(payload)
        self._request = dict(request)
        self._execution_kind = "apply"
        self._attempt = 0


def _digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _fingerprint(value: object) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _control_root(request: Mapping[str, Any]) -> Path:
    database = Path(request["db_path"]).expanduser().resolve()
    project_key = _fingerprint(request["project"])
    return database.parent / ".rta-smriti-lifecycle" / f"{database.stem}-{project_key}"


def _write_once_json(path: Path, payload: Mapping[str, Any]) -> None:
    prepare_control_dir(path.parent, label="lifecycle receipt")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _write_operation_claim(path: Path, payload: Mapping[str, Any]) -> None:
    prepare_control_dir(path.parent, label="lifecycle operation")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(dict(payload), stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


@contextmanager
def _operation_claim_guard(path: Path):
    """Serialize claim replacement and release with an OS-released file lock."""

    guard = path.with_name(f"{path.name}.guard")
    prepare_control_dir(guard.parent, label="lifecycle operation")
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(guard, flags, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _acquire_operation_claim(path: Path, payload: Mapping[str, Any]) -> None:
    with _operation_claim_guard(path):
        try:
            _write_operation_claim(path, payload)
            return
        except FileExistsError:
            existing = read_json(path)
            if existing is None:
                raise PermissionError("lifecycle operation claim is unsafe") from None
            existing_pid = int(existing.get("pid") or 0)
            if process_alive(existing_pid):
                stored_identity = str(existing.get("process_identity") or "")
                observed_identity = process_identity(existing_pid)
                if not stored_identity or not observed_identity or stored_identity == observed_identity:
                    raise LifecycleOperationInProgressError(
                        "another lifecycle operation is already in progress"
                    ) from None
            path.unlink()
            _write_operation_claim(path, payload)


def _release_operation_claim(path: Path, operation_id: str) -> None:
    with _operation_claim_guard(path):
        existing = read_json(path)
        if existing and existing.get("operation_id") == operation_id:
            path.unlink(missing_ok=True)


def _recoverable_journal(control_root: Path) -> tuple[Path, dict[str, Any]] | None:
    directory = control_root / "inflight"
    if not directory.is_dir() or directory.is_symlink():
        return None
    candidates = []
    for index, path in enumerate(directory.glob("*.json")):
        if index >= 1_000:
            break
        payload = read_json(path)
        if (
            payload
            and payload.get("schema") == LIFECYCLE_SCHEMA
            and payload.get("state") in {"in_progress", "interrupted"}
            and isinstance(payload.get("desired_state"), dict)
        ):
            candidates.append((path, payload))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0].stat().st_mtime_ns, reverse=True)
    return candidates[0]


def _mcp_proof_status(
    control_root: Path,
    desired: Mapping[str, Any] | None,
) -> dict[str, Any]:
    hosts = list(desired.get("mcp_hosts", [])) if desired else []
    if not hosts:
        return {
            "state": "not_configured",
            "fresh_session_proof": "not_requested",
            "configured_host_count": 0,
            "verified_host_count": 0,
            "protocol_verified_host_count": 0,
            "pending_hosts": [],
        }
    desired_digest = _digest(desired)
    host_verified: set[str] = set()
    protocol_verified: set[str] = set()
    invalid_configuration: set[str] = set()
    directory = control_root / "mcp-proofs"
    if directory.is_dir() and not directory.is_symlink():
        for index, path in enumerate(directory.glob("*.json")):
            if index >= 1_000:
                break
            proof = read_json(path)
            if (
                proof
                and proof.get("schema") == LIFECYCLE_SCHEMA
                and proof.get("kind") == "mcp-protocol-session-proof"
                and proof.get("state") == "protocol_verified"
                and proof.get("host_verified") is False
                and proof.get("desired_state_digest") == desired_digest
                and proof.get("profile_id") in hosts
            ):
                profile_id = str(proof["profile_id"])
                receipt_path = proof.get("configuration_receipt_path")
                receipt_digest = proof.get("configuration_receipt_digest")
                if not isinstance(receipt_path, str) or not isinstance(
                    receipt_digest, str
                ):
                    invalid_configuration.add(profile_id)
                    continue
                try:
                    validation = validate_installed_configuration(
                        Path(receipt_path),
                        expected_plan_digest=str(
                            proof.get("configuration_plan_digest") or ""
                        ),
                    )
                except (OSError, PermissionError, TypeError, ValueError):
                    invalid_configuration.add(profile_id)
                    continue
                if validation["receipt_digest"] != receipt_digest:
                    invalid_configuration.add(profile_id)
                    continue
                protocol_verified.add(profile_id)
    valid = host_verified | protocol_verified
    drifted = sorted(invalid_configuration - valid)
    pending = sorted(set(hosts) - host_verified)
    if drifted:
        state = "configuration_drifted"
        fresh_session_proof = "invalidated"
    elif set(hosts) <= host_verified:
        state = "healthy"
        fresh_session_proof = "host_verified"
    elif set(hosts) <= valid:
        state = "protocol_verified"
        fresh_session_proof = "protocol_verified"
    else:
        state = "configuration_pending"
        fresh_session_proof = "pending"
    return {
        "state": state,
        "fresh_session_proof": fresh_session_proof,
        "configured_host_count": len(hosts),
        "verified_host_count": len(host_verified),
        "protocol_verified_host_count": len(protocol_verified),
        "pending_hosts": pending,
        "drifted_hosts": drifted,
    }


def _request_paths(request: Mapping[str, Any]) -> dict[str, Any]:
    project = str(request.get("project") or "").strip()
    if not project:
        raise ValueError("lifecycle request requires a project")
    required_paths = ("tool_root", "brain_dir", "db_path", "root")
    missing = [name for name in required_paths if not request.get(name)]
    if missing:
        raise ValueError(f"lifecycle request is missing: {', '.join(missing)}")
    environment = request.get("environment")
    if environment is not None and not isinstance(environment, Mapping):
        raise ValueError("lifecycle environment must be a mapping")
    return {
        "tool_root": Path(request["tool_root"]).expanduser().resolve(),
        "brain_dir": Path(request["brain_dir"]).expanduser().resolve(),
        "db_path": Path(request["db_path"]).expanduser().resolve(),
        "root": Path(request["root"]).expanduser().resolve(),
        "sessions_root": (
            Path(request["sessions_root"]).expanduser().resolve()
            if request.get("sessions_root")
            else None
        ),
        "project": project,
        "platform_name": str(request.get("platform_name") or sys.platform),
        "home": Path(request.get("home") or Path.home()).expanduser().resolve(),
        "environment": {
            str(key): str(value)
            for key, value in dict(
                os.environ if environment is None else environment
            ).items()
        },
    }


def _execution_context_digest(selected: Mapping[str, Any]) -> str:
    """Bind authority-bearing inputs without serializing their raw values."""

    body = {
        "tool_root": str(Path(selected["tool_root"]).resolve()),
        "brain_dir": str(Path(selected["brain_dir"]).resolve()),
        "db_path": str(Path(selected["db_path"]).resolve()),
        "root": str(Path(selected["root"]).resolve()),
        "sessions_root": (
            str(Path(selected["sessions_root"]).resolve())
            if selected.get("sessions_root") is not None
            else None
        ),
        "home": str(Path(selected["home"]).resolve()),
        "platform_name": str(selected["platform_name"]),
        "environment": dict(sorted(dict(selected["environment"]).items())),
        "project": str(selected["project"]),
    }
    return _digest(body)


def _read_only_database_state(database: Path, project: str, root: Path) -> dict[str, Any]:
    if not database.exists():
        return {
            "state": "missing",
            "healthy": False,
            "schema_state": "unavailable",
            "schema_version": None,
            "quick_check": None,
            "project_state": "unknown_project",
            "project_ready": False,
        }
    if not is_safe_regular_file(database):
        return {
            "state": "unsafe",
            "healthy": False,
            "schema_state": "unavailable",
            "schema_version": None,
            "quick_check": None,
            "project_state": "unknown_project",
            "project_ready": False,
        }
    wal_path = database.with_name(f"{database.name}-wal")
    sidecars = (
        wal_path,
        database.with_name(f"{database.name}-shm"),
        database.with_name(f"{database.name}-journal"),
    )
    if any(path.exists() and not is_safe_regular_file(path) for path in sidecars):
        return {
            "state": "unsafe",
            "healthy": False,
            "schema_state": "unavailable",
            "schema_version": None,
            "quick_check": None,
            "project_state": "unknown_project",
            "project_ready": False,
        }
    read_mode = "mode=ro" if wal_path.exists() else "mode=ro&immutable=1"
    connection = None
    try:
        connection = sqlite3.connect(f"{database.as_uri()}?{read_mode}", uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        if schema_version > SCHEMA_VERSION:
            schema_state = "newer_unsupported"
        elif schema_version == SCHEMA_VERSION:
            from .capture_schema import capture_schema_v10_patch_required

            schema_state = (
                "patch_required"
                if capture_schema_v10_patch_required(connection)
                else "current"
            )
        elif schema_version > 0:
            schema_state = "older_supported"
        else:
            schema_state = "invalid"
        try:
            row = connection.execute(
                "SELECT root_path FROM projects WHERE name = ?",
                (project,),
            ).fetchone()
        except sqlite3.DatabaseError:
            row = None
        try:
            checkpoint_row = connection.execute(
                """
                SELECT 1
                FROM checkpoints c
                JOIN projects p ON p.id = c.project_id
                WHERE p.name = ?
                LIMIT 1
                """,
                (project,),
            ).fetchone()
        except sqlite3.DatabaseError:
            checkpoint_row = None
        if row is None:
            project_state = "unknown_project"
            project_ready = False
        else:
            stored_root = row["root_path"]
            project_ready = bool(
                stored_root
                and root.is_dir()
                and Path(str(stored_root)).is_dir()
                and same_root(str(stored_root), root)
            )
            project_state = "exact" if project_ready else "binding_mismatch"
        healthy = quick_check == "ok" and schema_state == "current"
        return {
            "state": "healthy" if healthy else "attention_required",
            "healthy": healthy,
            "schema_state": schema_state,
            "schema_version": schema_version,
            "quick_check": quick_check,
            "project_state": project_state,
            "project_ready": project_ready,
            "manual_checkpoint_available": checkpoint_row is not None,
        }
    except sqlite3.Error as exc:
        sqlite_code = getattr(exc, "sqlite_errorcode", None)
        locked_codes = {
            getattr(sqlite3, "SQLITE_BUSY", 5),
            getattr(sqlite3, "SQLITE_LOCKED", 6),
        }
        state = (
            "locked"
            if sqlite_code in locked_codes or "locked" in str(exc).casefold()
            else "invalid"
        )
        return {
            "state": state,
            "healthy": False,
            "schema_state": "unavailable" if state == "locked" else "invalid",
            "schema_version": None,
            "quick_check": None,
            "project_state": "unknown_project",
            "project_ready": False,
            "error_class": exc.__class__.__name__,
        }
    finally:
        if connection is not None:
            connection.close()


def _read_only_operational_readiness(
    database: Path,
    project: str,
    root: Path,
    lifecycle: Mapping[str, Any],
) -> dict[str, Any]:
    """Run the canonical readiness evaluator against an isolated DB snapshot."""

    wal_path = database.with_name(f"{database.name}-wal")
    read_mode = "mode=ro" if wal_path.exists() else "mode=ro&immutable=1"
    source = sqlite3.connect(f"{database.as_uri()}?{read_mode}", uri=True)
    snapshot = sqlite3.connect(":memory:")
    snapshot.row_factory = sqlite3.Row
    try:
        source.backup(snapshot)
        from .continuity import operational_readiness

        return operational_readiness(
            snapshot,
            project,
            lifecycle=dict(lifecycle),
            include_event_count=False,
            active_root=root,
        )
    finally:
        snapshot.close()
        source.close()


def _external_work_active(value: object) -> bool:
    if isinstance(value, Mapping):
        state = str(value.get("state") or "").strip().casefold()
        count = max(0, int(value.get("count") or 0))
        return count > 0 or state in {"active", "running", "pending", "in_progress"}
    return bool(value)


def inspect_lifecycle(request: Mapping[str, Any]) -> dict[str, Any]:
    """Inspect one project lifecycle without migration or filesystem mutation."""

    selected = _request_paths(request)
    database_state = _read_only_database_state(
        selected["db_path"], selected["project"], selected["root"]
    )
    watcher = watcher_status(selected["db_path"], selected["project"])
    capture = capture_status(selected["db_path"])
    continuity = public_continuity_status(
        continuity_status(selected["db_path"], selected["project"])
    )
    console = console_status(selected["brain_dir"])
    login_restoration = autostart_status(
        selected["brain_dir"],
        platform_name=selected["platform_name"],
        home=selected["home"],
        environment=selected["environment"],
    )
    readiness: dict[str, Any] | None = None
    if database_state.get("healthy") and database_state.get("project_ready"):
        try:
            readiness = _read_only_operational_readiness(
                selected["db_path"],
                selected["project"],
                selected["root"],
                continuity,
            )
        except (OSError, sqlite3.Error, ValueError):
            readiness = None
    if readiness is None:
        continuation = derive_continuation_health(
            continuity,
            manual_checkpoint_available=False,
        )
        readiness_reasons = ["operational_readiness_unavailable"]
        manual_continuation_ready = False
        continuation_ready = False
    else:
        continuation = dict(readiness["continuation_health"])
        readiness_reasons = list(readiness["reasons"])
        manual_continuation_ready = bool(
            readiness["manual_continuation_ready"]
        )
        continuation_ready = bool(readiness["continuation_ready"])
    if _external_work_active(request.get("active_external_work")):
        if "active_external_work" not in readiness_reasons:
            readiness_reasons.append("active_external_work")
        manual_continuation_ready = False
        continuation_ready = False
    continuation.update(
        {
            "manual_continuation_ready": manual_continuation_ready,
            "continuation_ready": continuation_ready,
            "readiness_reason_codes": readiness_reasons,
        }
    )
    desired_payload = read_json(_control_root(selected) / "desired-state.json")
    enrollment_state = "not_configured"
    desired: dict[str, Any] | None = None
    if desired_payload is not None:
        try:
            _desired_path, desired = _load_desired_state(selected)
            enrollment_state = "configured"
        except (PermissionError, ValueError):
            enrollment_state = "invalid"
    recovery = _recoverable_journal(_control_root(selected))
    if recovery is not None:
        try:
            if desired is None:
                desired = _normalize_desired_state(recovery[1]["desired_state"])
            enrollment_state = "recovery_required"
        except ValueError:
            enrollment_state = "invalid"
    mcp_health = _mcp_proof_status(_control_root(selected), desired)
    axes = {
        "database_health": {
            "state": database_state["state"],
            "schema_state": database_state["schema_state"],
            "schema_version": database_state["schema_version"],
            "quick_check": database_state["quick_check"],
        },
        "project_integrity": {
            "state": (
                "healthy"
                if database_state["project_ready"]
                and readiness is not None
                and readiness["integrity"]["operationally_ready"]
                else "attention_required"
            ),
            "binding_state": database_state["project_state"],
            "watcher_state": watcher.get("state", "unknown"),
        },
        "capture_health": {
            "state": capture.get("state", "unknown"),
        },
        "continuation_health": continuation,
        "mcp_health": mcp_health,
        "federation_health": {"state": "not_configured"},
    }
    reason_codes: list[str] = []
    if not database_state["healthy"]:
        reason_codes.append("database_not_healthy")
    if not database_state["project_ready"]:
        reason_codes.append("project_integrity_not_healthy")
    if enrollment_state == "invalid":
        reason_codes.append("desired_state_invalid")
    if enrollment_state == "recovery_required":
        reason_codes.append("interrupted_operation_pending")
    services = {
        "watcher": watcher.get("state", "unknown"),
        "capture": capture.get("state", "unknown"),
        "continuity": continuity.get("state", "unknown"),
        "console": console.get("state", "unknown"),
        "login_restoration": (
            "enabled" if login_restoration.get("enabled") else "disabled"
        ),
    }
    if desired is not None:
        for service in ("watcher", "capture", "continuity", "console"):
            running = services[service] in {"running", "current"}
            if running != desired[service]:
                reason_codes.append(f"{service}_state_mismatch")
        login_enabled = services["login_restoration"] == "enabled"
        if login_enabled != desired["login_restoration"]:
            reason_codes.append("login_restoration_state_mismatch")
        if desired["continuity"] and not continuation["automatic_capture_ready"]:
            reason_codes.append("continuity_data_flow_unproven")
        if desired["mcp_hosts"] and mcp_health["state"] != "healthy":
            if mcp_health["state"] == "configuration_drifted":
                reason_codes.append("mcp_configuration_drifted")
            elif mcp_health["state"] == "protocol_verified":
                reason_codes.append("mcp_host_verification_unproven")
            else:
                reason_codes.append("mcp_configuration_pending")
    stable = {
        "status": "ok" if not reason_codes else "attention_required",
        "schema": LIFECYCLE_SCHEMA,
        "enrollment_state": enrollment_state,
        "reason_codes": reason_codes,
        "project_fingerprint": _fingerprint(selected["project"]),
        "database_fingerprint": _fingerprint(selected["db_path"]),
        "root_fingerprint": _fingerprint(selected["root"]),
        "services": services,
        "health_axes": axes,
        "continuation_ready": continuation_ready,
        "manual_continuation_ready": manual_continuation_ready,
        "operational_readiness_state": (
            "ready" if continuation_ready else "operationally_not_ready"
        ),
        "desired_state": desired,
        "desired_state_digest": _digest(desired) if desired is not None else None,
    }
    return {**stable, "observed_state_digest": _digest(stable)}


def _normalize_desired_state(desired_state: Mapping[str, Any]) -> dict[str, Any]:
    schema_policy = str(desired_state.get("schema_policy") or "current-only")
    if schema_policy not in SCHEMA_POLICIES:
        raise ValueError(f"unsupported schema policy: {schema_policy}")
    hosts = desired_state.get("mcp_hosts", [])
    if not isinstance(hosts, list) or any(not isinstance(host, str) or not host.strip() for host in hosts):
        raise ValueError("mcp_hosts must be a list of non-empty profile names")
    normalized_hosts = sorted({host.strip().casefold() for host in hosts})
    for host in normalized_hosts:
        host_profile(host)
    return {
        "watcher": bool(desired_state.get("watcher", False)),
        "capture": bool(desired_state.get("capture", False)),
        "continuity": bool(desired_state.get("continuity", False)),
        "console": bool(desired_state.get("console", False)),
        "login_restoration": bool(desired_state.get("login_restoration", False)),
        "mcp_hosts": normalized_hosts,
        "schema_policy": schema_policy,
    }


def _plan_lifecycle(
    request: Mapping[str, Any],
    desired_state: Mapping[str, Any],
    *,
    execution_kind: str,
    source_desired_state_digest: str | None = None,
) -> dict[str, Any]:
    """Return a deterministic, read-only lifecycle plan for one exact context."""

    if execution_kind not in {"apply", "stop", "remove", "repair"}:
        raise ValueError(f"unsupported lifecycle execution kind: {execution_kind}")
    selected = _request_paths(request)
    snapshot = inspect_lifecycle(selected)
    desired = _normalize_desired_state(desired_state)
    observed = snapshot["services"]
    steps: list[dict[str, Any]] = []
    blockers: list[str] = []
    schema_state = snapshot["health_axes"]["database_health"]["schema_state"]
    if schema_state == "newer_unsupported":
        blockers.append("schema_newer_unsupported")
    elif schema_state in {"invalid", "unavailable"}:
        blockers.append("schema_invalid_or_unavailable")
    elif schema_state in {"older_supported", "patch_required"} and desired["schema_policy"] != "migrate-with-backup":
        blockers.append("schema_migration_not_authorized")
    if schema_state in {"older_supported", "patch_required"} and desired["schema_policy"] == "migrate-with-backup":
        steps.extend([
            {"operation": "backup_database", "reversible": False},
            {"operation": "migrate_database", "reversible": True},
            {"operation": "validate_database", "reversible": False},
        ])
    for service in ("watcher", "capture", "continuity", "console"):
        service_state = str(observed[service])
        running = service_state in {"running", "current"}
        if service_state == "live-unverifiable":
            blockers.append(f"{service}_authority_uncertain")
            continue
        if desired[service] and not running:
            steps.append({"operation": f"start_{service}", "reversible": True})
        elif not desired[service] and service_state in {
            "running",
            "current",
            "starting",
            "stopping",
            "stale",
            "error",
            "unresponsive",
        }:
            steps.append({"operation": f"stop_{service}", "reversible": True})
    login_enabled = observed["login_restoration"] == "enabled"
    if desired["login_restoration"] and not login_enabled:
        steps.append({"operation": "enable_login_restoration", "reversible": True})
    elif not desired["login_restoration"] and login_enabled:
        steps.append({"operation": "disable_login_restoration", "reversible": True})
    plan_body = {
        "schema": LIFECYCLE_SCHEMA,
        "execution_kind": execution_kind,
        "execution_context_digest": _execution_context_digest(selected),
        "project_fingerprint": snapshot["project_fingerprint"],
        "observed_state_digest": snapshot["observed_state_digest"],
        "source_desired_state_digest": source_desired_state_digest,
        "desired_state": desired,
        "steps": steps,
        "blocked": bool(blockers),
        "blockers": blockers,
    }
    return LifecyclePlan({
        **plan_body,
        "status": "blocked" if blockers else "ok",
        "read_only": True,
        "plan_digest": _digest(plan_body),
    }, selected)


def plan_lifecycle(
    request: Mapping[str, Any],
    desired_state: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a deterministic, read-only lifecycle apply plan."""

    return _plan_lifecycle(request, desired_state, execution_kind="apply")


def _stopped_desired_state(desired: Mapping[str, Any]) -> dict[str, Any]:
    return {
        **desired,
        "watcher": False,
        "capture": False,
        "continuity": False,
        "console": False,
        "login_restoration": False,
        "mcp_hosts": [],
    }


def plan_stop_lifecycle(request: Mapping[str, Any]) -> LifecyclePlan:
    """Preview an exact stop operation without mutating managed state."""

    _path, desired = _load_desired_state(request)
    return _plan_lifecycle(
        request,
        _stopped_desired_state(desired),
        execution_kind="stop",
        source_desired_state_digest=_digest(desired),
    )


def plan_remove_lifecycle(request: Mapping[str, Any]) -> LifecyclePlan:
    """Preview stopping services and removing enrollment as one operation."""

    _path, desired = _load_desired_state(request)
    return _plan_lifecycle(
        request,
        _stopped_desired_state(desired),
        execution_kind="remove",
        source_desired_state_digest=_digest(desired),
    )


def plan_repair_lifecycle(request: Mapping[str, Any]) -> LifecyclePlan:
    """Preview an exact recovery or desired-state repair without mutation."""

    recovery = _recoverable_journal(_control_root(request))
    try:
        _desired_path, desired = _load_desired_state(request)
    except ValueError:
        if recovery is None:
            raise
        desired = _normalize_desired_state(recovery[1]["desired_state"])
    if recovery is not None and recovery[1].get("execution_kind") == "remove":
        return _plan_lifecycle(
            request,
            _stopped_desired_state(desired),
            execution_kind="remove",
            source_desired_state_digest=_digest(desired),
        )
    if recovery is not None and recovery[1].get("execution_kind") == "stop":
        return _plan_lifecycle(
            request,
            _stopped_desired_state(desired),
            execution_kind="stop",
            source_desired_state_digest=_digest(desired),
        )
    return _plan_lifecycle(request, desired, execution_kind="repair")


def _run_service_operation(operation: str, selected: Mapping[str, Any]) -> dict[str, Any]:
    if operation == "backup_database":
        backup_path = Path(selected["backup_path"])
        if backup_path.exists():
            raise FileExistsError("lifecycle migration backup already exists")
        prepare_control_dir(backup_path.parent, label="lifecycle backup")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{backup_path.name}.partial-",
            dir=backup_path.parent,
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        try:
            source = sqlite3.connect(str(selected["db_path"]))
            destination = None
            try:
                destination = sqlite3.connect(str(temporary_path))
                source.backup(destination)
                destination.commit()
                if destination.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RuntimeError(
                        "lifecycle migration backup failed integrity validation"
                    )
            finally:
                if destination is not None:
                    destination.close()
                source.close()
            backup_digest = _file_sha256(temporary_path)
            backup_size = temporary_path.stat().st_size
            os.link(temporary_path, backup_path)
            temporary_path.unlink()
            if (
                not is_safe_regular_file(backup_path)
                or _file_sha256(backup_path) != backup_digest
                or backup_path.stat().st_size != backup_size
            ):
                backup_path.unlink(missing_ok=True)
                raise RuntimeError(
                    "lifecycle migration backup failed exact digest validation"
                )
        finally:
            temporary_path.unlink(missing_ok=True)
        return {
            "state": "complete",
            "backup_digest": backup_digest,
            "backup_size": backup_size,
        }
    if operation == "migrate_database":
        connection = connect(selected["db_path"])
        try:
            init_schema(connection, allow_migration=True)
        finally:
            connection.close()
        return {"state": "complete"}
    if operation == "validate_database":
        state = _read_only_database_state(
            selected["db_path"], selected["project"], selected["root"]
        )
        if not state["healthy"] or not state["project_ready"]:
            raise RuntimeError("migrated database failed lifecycle validation")
        return {"state": "verified"}
    if operation == "restore_database_backup":
        backup_path = Path(selected["backup_path"])
        if not is_safe_regular_file(backup_path):
            raise RuntimeError("lifecycle migration backup is missing or unsafe")
        expected_digest = str(selected.get("backup_digest") or "")
        if len(expected_digest) != 64 or _file_sha256(backup_path) != expected_digest:
            raise RuntimeError("lifecycle migration backup digest does not match")
        source = sqlite3.connect(str(backup_path))
        destination = sqlite3.connect(str(selected["db_path"]))
        try:
            if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RuntimeError("lifecycle migration backup failed integrity validation")
            source.backup(destination)
            destination.commit()
            if destination.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise RuntimeError("restored database failed integrity validation")
        finally:
            destination.close()
            source.close()
        return {"state": "restored"}
    if operation == "enable_login_restoration":
        result = enable_autostart(
            selected["tool_root"],
            selected["brain_dir"],
            platform_name=selected["platform_name"],
            home=selected["home"],
            environment=selected["environment"],
        )
        return {**result, "state": "enabled" if result.get("enabled") else "error"}
    if operation == "disable_login_restoration":
        result = disable_autostart(
            selected["brain_dir"],
            platform_name=selected["platform_name"],
            home=selected["home"],
            environment=selected["environment"],
        )
        return {**result, "state": "disabled" if not result.get("enabled") else "error"}
    if operation == "start_watcher":
        return start_watcher(
            selected["db_path"], selected["root"], selected["project"]
        )
    if operation == "stop_watcher":
        return stop_watcher(selected["db_path"], selected["project"])
    if operation == "start_capture":
        return start_capture(selected["db_path"])
    if operation == "stop_capture":
        return stop_capture(selected["db_path"])
    if operation == "start_continuity":
        if selected["sessions_root"] is None:
            raise ValueError("continuity start requires a sessions root")
        return start_continuity(
            selected["db_path"],
            selected["root"],
            selected["project"],
            selected["sessions_root"],
        )
    if operation == "stop_continuity":
        return stop_continuity(selected["db_path"], selected["project"])
    if operation == "start_console":
        return start_console(
            selected["tool_root"],
            selected["brain_dir"],
            default_db=selected["db_path"],
            default_project=selected["project"],
            open_browser=False,
        )
    if operation == "stop_console":
        return stop_console(selected["brain_dir"])
    raise ValueError(f"unsupported lifecycle operation: {operation}")


def _compensation_for(
    operation: str, *, migration_committed: bool = False
) -> str | None:
    if operation == "migrate_database":
        # A post-backup writer may have advanced the live database. Preserve the
        # verified backup for operator recovery, but never overwrite newer state.
        return None
    if operation == "enable_login_restoration":
        return "disable_login_restoration"
    if operation == "disable_login_restoration":
        return "enable_login_restoration"
    action, separator, service = operation.partition("_")
    if not separator or action not in {"start", "stop"}:
        return None
    return f"{'stop' if action == 'start' else 'start'}_{service}"


def apply_lifecycle(
    plan: Mapping[str, Any],
    confirmation: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply a confirmed plan only while its inspected state is unchanged."""

    if not confirmation.get("approved"):
        raise PermissionError("lifecycle plan requires explicit approval")
    plan_body = {
        key: plan[key]
        for key in (
            "schema",
            "execution_kind",
            "execution_context_digest",
            "project_fingerprint",
            "observed_state_digest",
            "source_desired_state_digest",
            "desired_state",
            "steps",
            "blocked",
            "blockers",
        )
    }
    expected_plan_digest = _digest(plan_body)
    if (
        plan.get("plan_digest") != expected_plan_digest
        or confirmation.get("plan_digest") != expected_plan_digest
    ):
        raise PermissionError("lifecycle confirmation does not match the plan digest")
    if confirmation.get("observed_state_digest") != plan.get("observed_state_digest"):
        raise PermissionError("lifecycle confirmation does not match observed state")
    if plan.get("blocked"):
        raise PermissionError("blocked lifecycle plan cannot be applied")
    request = getattr(plan, "_request", None)
    if request is None:
        raise ValueError("lifecycle plan execution context is unavailable")
    selected = _request_paths(request)
    if _execution_context_digest(selected) != plan.get("execution_context_digest"):
        raise PermissionError("lifecycle execution context does not match the plan")
    confirmation_digest = _digest({
        "approved": True,
        "plan_digest": confirmation["plan_digest"],
        "observed_state_digest": confirmation["observed_state_digest"],
    })
    execution_kind = str(plan.get("execution_kind") or "")
    if execution_kind not in {"apply", "stop", "remove", "repair"}:
        raise PermissionError("lifecycle execution kind is invalid")
    attempt = int(getattr(plan, "_attempt", 0))
    operation_id = _digest({
        "plan_digest": expected_plan_digest,
        "confirmation_digest": confirmation_digest,
        "execution_kind": execution_kind,
        "attempt": attempt,
    })[:32]
    control_root = _control_root(selected)
    receipt_path = control_root / "receipts" / f"{operation_id}.json"
    current = inspect_lifecycle(selected)
    existing = read_json(receipt_path)
    if existing is not None:
        if (
            existing.get("plan_digest") != expected_plan_digest
            or existing.get("confirmation_digest") != confirmation_digest
            or existing.get("state") != "complete"
        ):
            raise PermissionError("existing lifecycle receipt does not match a completed operation")
        desired_digest = _digest(plan["desired_state"])
        services_stopped = all(
            current.get("services", {}).get(name)
            not in {"running", "current", "enabled"}
            for name in (
                "watcher",
                "capture",
                "continuity",
                "console",
                "login_restoration",
            )
        )
        completed_state_matches = (
            current.get("enrollment_state") == "not_configured"
            and current.get("desired_state_digest") is None
            and current.get("status") == "ok"
            and services_stopped
            if execution_kind == "remove"
            else current.get("enrollment_state") == "configured"
            and current.get("desired_state_digest") == desired_digest
            and current.get("status") == "ok"
        )
        if not completed_state_matches:
            raise StaleLifecyclePlanError(
                "completed receipt no longer matches current lifecycle state"
            )
        return {
            "status": "ok",
            "state": "removed" if execution_kind == "remove" else "complete",
            "operation_id": operation_id,
            "plan_digest": expected_plan_digest,
            "desired_state_digest": desired_digest,
            "receipt_path": str(receipt_path),
            "idempotent_replay": True,
            "steps": existing.get("steps", []),
        }
    if current["observed_state_digest"] != plan["observed_state_digest"]:
        raise StaleLifecyclePlanError("observed state changed after lifecycle planning")
    claim_path = control_root / "operation.lock"
    owner_identity = process_identity(os.getpid())
    if owner_identity is None:
        raise RuntimeError("lifecycle operation process identity is unavailable")
    _acquire_operation_claim(
        claim_path,
        {
            "schema": LIFECYCLE_SCHEMA,
            "operation_id": operation_id,
            "plan_digest": expected_plan_digest,
            "pid": os.getpid(),
            "process_identity": owner_identity,
        },
    )
    claimed_state = inspect_lifecycle(selected)
    if claimed_state["observed_state_digest"] != plan["observed_state_digest"]:
        _release_operation_claim(claim_path, operation_id)
        raise StaleLifecyclePlanError("observed state changed while claiming lifecycle plan")
    selected["control_root"] = control_root
    source_schema = current["health_axes"]["database_health"]["schema_version"]
    selected["backup_path"] = (
        control_root
        / "backups"
        / f"schema-v{source_schema}-{expected_plan_digest[:16]}.sqlite"
    )
    journal_path = control_root / "inflight" / f"{operation_id}.json"
    journal = {
        "schema": LIFECYCLE_SCHEMA,
        "operation_id": operation_id,
        "state": "in_progress",
        "execution_kind": execution_kind,
        "attempt": attempt,
        "plan_digest": expected_plan_digest,
        "confirmation_digest": confirmation_digest,
        "observed_state_digest": current["observed_state_digest"],
        "desired_state": plan["desired_state"],
        "desired_state_digest": _digest(plan["desired_state"]),
        "execution_context_digest": plan["execution_context_digest"],
        "migration_phase": (
            "pending"
            if any(
                step.get("operation") == "migrate_database"
                for step in plan["steps"]
            )
            else "not_applicable"
        ),
        "publication_phase": "pending",
        "current_step": None,
        "steps": [],
    }
    try:
        write_json(journal_path, journal, label="lifecycle inflight journal")
    except BaseException:
        _release_operation_claim(claim_path, operation_id)
        raise
    step_results = []
    try:
        for step in plan["steps"]:
            operation = step["operation"]
            journal["current_step"] = operation
            journal["steps"] = step_results
            write_json(journal_path, journal, label="lifecycle inflight journal")
            result = _run_service_operation(operation, selected)
            if result.get("state") not in {
                "running", "current", "stopped", "complete", "verified",
                "enabled", "disabled",
            }:
                raise RuntimeError(
                    f"{operation} did not reach its expected state: {result.get('state')}"
                )
            step_result = {
                "operation": operation,
                "state": "complete",
                "observed_service_state": result.get("state"),
            }
            if result.get("backup_digest"):
                selected["backup_digest"] = result["backup_digest"]
                step_result["backup_digest"] = result["backup_digest"]
                step_result["backup_size"] = result["backup_size"]
                journal["backup_digest"] = result["backup_digest"]
                journal["backup_size"] = result["backup_size"]
                journal["migration_phase"] = "backup_verified"
            elif operation == "migrate_database":
                journal["migration_phase"] = "migrated_uncommitted"
            step_results.append(step_result)
            if operation == "validate_database":
                journal["migration_phase"] = "committed"
            journal["current_step"] = None
            journal["steps"] = step_results
            write_json(journal_path, journal, label="lifecycle inflight journal")
    except Exception as exc:  # noqa: BLE001 - receipt records bounded failure evidence
        failed_operation = operation if "operation" in locals() else "unknown"
        step_results.append({
            "operation": failed_operation,
            "state": "failed",
            "error_class": exc.__class__.__name__,
        })
        compensations = []
        rollback_complete = journal["migration_phase"] != "migrated_uncommitted"
        for completed in reversed(step_results):
            compensation = _compensation_for(
                completed["operation"],
                migration_committed=journal["migration_phase"] == "committed",
            )
            if compensation is None:
                continue
            try:
                result = _run_service_operation(compensation, selected)
                compensation_state = "complete" if result.get("state") in {
                    "running", "current", "stopped", "complete", "restored",
                    "enabled", "disabled",
                } else "failed"
                rollback_complete = rollback_complete and compensation_state == "complete"
                compensations.append({
                    "operation": compensation,
                    "state": compensation_state,
                    "observed_service_state": result.get("state"),
                })
            except Exception as compensation_error:  # noqa: BLE001
                rollback_complete = False
                compensations.append({
                    "operation": compensation,
                    "state": "failed",
                    "error_class": compensation_error.__class__.__name__,
                })
        failed_receipt = {
            "schema": LIFECYCLE_SCHEMA,
            "operation_id": operation_id,
            "state": "failed",
            "execution_kind": execution_kind,
            "attempt": attempt,
            "plan_digest": expected_plan_digest,
            "confirmation_digest": confirmation_digest,
            "observed_state_digest": current["observed_state_digest"],
            "desired_state_digest": _digest(plan["desired_state"]),
            "error_class": exc.__class__.__name__,
            "rollback_state": "complete" if rollback_complete else "partial",
            "migration_phase": journal["migration_phase"],
            "steps": step_results,
            "compensations": compensations,
        }
        journal.update({
            "state": "failed",
            "current_step": None,
            "steps": step_results,
            "rollback_state": failed_receipt["rollback_state"],
            "migration_phase": journal["migration_phase"],
        })
        try:
            write_json(journal_path, journal, label="lifecycle inflight journal")
            _write_once_json(receipt_path, failed_receipt)
        finally:
            _release_operation_claim(claim_path, operation_id)
        return {
            "status": "error",
            "state": "failed",
            "operation_id": operation_id,
            "plan_digest": expected_plan_digest,
            "receipt_path": str(receipt_path),
            "error_class": exc.__class__.__name__,
            "rollback_state": failed_receipt["rollback_state"],
            "migration_phase": journal["migration_phase"],
            "steps": step_results,
            "compensations": compensations,
        }
    except BaseException:
        journal.update({
            "state": "interrupted",
            "steps": step_results,
        })
        try:
            write_json(journal_path, journal, label="lifecycle inflight journal")
        finally:
            _release_operation_claim(claim_path, operation_id)
        raise

    desired_path = control_root / "desired-state.json"
    removed_desired_payload: dict[str, Any] | None = None
    try:
        journal["current_step"] = (
            "remove_enrollment"
            if execution_kind == "remove"
            else "publish_desired_state"
        )
        write_json(journal_path, journal, label="lifecycle inflight journal")
        if execution_kind == "remove":
            current_payload = read_json(desired_path)
            if current_payload is None or not is_safe_regular_file(desired_path):
                raise PermissionError(
                    "lifecycle desired state changed before removal"
                )
            current_desired = _normalize_desired_state(
                current_payload.get("desired_state", {})
            )
            if (
                _digest(current_desired)
                != plan.get("source_desired_state_digest")
            ):
                raise PermissionError(
                    "lifecycle desired state changed before removal"
                )
            removed_desired_payload = dict(current_payload)
            desired_path.unlink()
            journal["publication_phase"] = "enrollment_removed"
        else:
            write_json(desired_path, {
                "schema": LIFECYCLE_SCHEMA,
                "project": selected["project"],
                "db_path": str(selected["db_path"]),
                "root": str(selected["root"]),
                "sessions_root": (
                    str(selected["sessions_root"])
                    if selected["sessions_root"] is not None
                    else None
                ),
                "desired_state": plan["desired_state"],
                "plan_digest": expected_plan_digest,
                "execution_context_digest": plan["execution_context_digest"],
            }, label="lifecycle desired state")
            journal["publication_phase"] = "desired_written"
        journal["current_step"] = "publish_receipt"
        write_json(journal_path, journal, label="lifecycle inflight journal")
        receipt = {
            "schema": LIFECYCLE_SCHEMA,
            "operation_id": operation_id,
            "state": "complete",
            "execution_kind": execution_kind,
            "attempt": attempt,
            "plan_digest": expected_plan_digest,
            "confirmation_digest": confirmation_digest,
            "observed_state_digest": current["observed_state_digest"],
            "desired_state_digest": _digest(plan["desired_state"]),
            "migration_phase": journal["migration_phase"],
            "steps": step_results,
        }
        _write_once_json(receipt_path, receipt)
        journal.update({
            "state": "complete",
            "current_step": None,
            "publication_phase": "receipt_written",
            "steps": step_results,
        })
        write_json(journal_path, journal, label="lifecycle inflight journal")
    except BaseException as exc:
        if (
            execution_kind == "remove"
            and journal.get("publication_phase") == "enrollment_removed"
            and removed_desired_payload is not None
            and not desired_path.exists()
        ):
            try:
                write_json(
                    desired_path,
                    removed_desired_payload,
                    label="lifecycle desired state",
                )
                journal["publication_phase"] = "enrollment_restored_after_failure"
            except Exception as restore_error:  # noqa: BLE001
                exc.add_note(
                    "lifecycle enrollment restoration failed: "
                    f"{restore_error.__class__.__name__}"
                )
        journal.update({
            "state": "interrupted",
            "error_class": exc.__class__.__name__,
            "steps": step_results,
        })
        try:
            write_json(journal_path, journal, label="lifecycle inflight journal")
        except Exception as journal_error:  # noqa: BLE001
            exc.add_note(
                "lifecycle recovery journal update failed: "
                f"{journal_error.__class__.__name__}"
            )
        raise
    finally:
        _release_operation_claim(claim_path, operation_id)
    return {
        "status": "ok",
        "state": "removed" if execution_kind == "remove" else "complete",
        "operation_id": operation_id,
        "plan_digest": expected_plan_digest,
        "observed_state_digest": current["observed_state_digest"],
        "desired_state_digest": _digest(plan["desired_state"]),
        "receipt_path": str(receipt_path),
        "idempotent_replay": False,
        "migration_phase": journal["migration_phase"],
        "steps": step_results,
    }


def _load_desired_state(request: Mapping[str, Any]) -> tuple[Path, dict[str, Any]]:
    selected = _request_paths(request)
    desired_path = _control_root(selected) / "desired-state.json"
    payload = read_json(desired_path)
    if payload is None:
        raise ValueError("trusted lifecycle desired state is not configured")
    if (
        payload.get("schema") != LIFECYCLE_SCHEMA
        or payload.get("project") != selected["project"]
        or Path(str(payload.get("db_path", ""))).expanduser().resolve()
        != selected["db_path"]
        or Path(str(payload.get("root", ""))).expanduser().resolve()
        != selected["root"]
    ):
        raise PermissionError("trusted lifecycle desired state binding is invalid")
    desired = _normalize_desired_state(payload.get("desired_state", {}))
    return desired_path, desired


def attach_lifecycle_mcp_proof(
    request: Mapping[str, Any],
    configuration_receipt_path: Path,
    evidence: Mapping[str, Any],
    confirmation: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind protocol evidence to one exact trusted lifecycle desired state."""

    _desired_path, desired = _load_desired_state(request)
    desired_digest = _digest(desired)
    if (
        not confirmation.get("approved")
        or confirmation.get("desired_state_digest") != desired_digest
    ):
        raise PermissionError("MCP lifecycle proof requires matching desired-state approval")
    proof = record_fresh_session_proof(
        configuration_receipt_path,
        evidence,
        {
            "approved": True,
            "configuration_plan_digest": confirmation.get(
                "configuration_plan_digest"
            ),
        },
    )
    if proof.get("state") != "protocol_verified":
        return proof
    profile_id = str(proof.get("profile_id") or "")
    if profile_id not in desired["mcp_hosts"]:
        raise PermissionError("MCP host proof is not part of the desired lifecycle state")
    configuration_validation = validate_installed_configuration(
        configuration_receipt_path,
        expected_plan_digest=str(proof["configuration_plan_digest"]),
    )
    payload = {
        "schema": LIFECYCLE_SCHEMA,
        "kind": "mcp-protocol-session-proof",
        "state": "protocol_verified",
        "verification_level": "protocol_verified",
        "host_verified": False,
        "profile_id": profile_id,
        "desired_state_digest": desired_digest,
        "configuration_plan_digest": proof["configuration_plan_digest"],
        "configuration_receipt_path": str(
            Path(configuration_receipt_path).expanduser().resolve()
        ),
        "configuration_receipt_digest": configuration_validation["receipt_digest"],
        "proof_digest": proof["proof_digest"],
        "evidence": proof["evidence"],
    }
    path = (
        _control_root(request)
        / "mcp-proofs"
        / f"{profile_id}-{proof['proof_digest']}.json"
    )
    _write_once_json(path, payload)
    return {
        "status": "ok",
        "state": "protocol_verified",
        "verification_level": "protocol_verified",
        "host_verified": False,
        "profile_id": profile_id,
        "desired_state_digest": desired_digest,
        "configuration_plan_digest": proof["configuration_plan_digest"],
        "proof_digest": proof["proof_digest"],
        "evidence": proof["evidence"],
    }


def verify_lifecycle(
    request: Mapping[str, Any],
    proof_level: str = "process",
) -> dict[str, Any]:
    """Verify persisted desired state against independent observed health axes."""

    if proof_level not in {"process", "data-flow", "fresh-session"}:
        raise ValueError(f"unsupported lifecycle proof level: {proof_level}")
    _desired_path, desired = _load_desired_state(request)
    snapshot = inspect_lifecycle(request)
    services = snapshot["services"]
    mismatches = []
    for service in ("watcher", "capture", "continuity", "console"):
        running = services[service] in {"running", "current"}
        if running != desired[service]:
            mismatches.append(f"{service}_state_mismatch")
    login_enabled = services["login_restoration"] == "enabled"
    if login_enabled != desired["login_restoration"]:
        mismatches.append("login_restoration_state_mismatch")
    database_ready = (
        snapshot["health_axes"]["database_health"]["state"] == "healthy"
    )
    project_ready = (
        snapshot["health_axes"]["project_integrity"]["state"] == "healthy"
    )
    if not database_ready:
        mismatches.append("database_not_healthy")
    if not project_ready:
        mismatches.append("project_integrity_not_healthy")
    if (
        proof_level in {"data-flow", "fresh-session"}
        and desired["continuity"]
        and not snapshot["health_axes"]["continuation_health"].get(
            "automatic_capture_ready"
        )
    ):
        mismatches.append("continuity_data_flow_unproven")
    if (
        proof_level == "fresh-session"
        and desired["mcp_hosts"]
        and snapshot["health_axes"]["mcp_health"]["state"] != "healthy"
    ):
        mcp_state = snapshot["health_axes"]["mcp_health"]["state"]
        if mcp_state == "configuration_drifted":
            mismatches.append("mcp_configuration_drifted")
        elif mcp_state == "protocol_verified":
            mismatches.append("mcp_host_verification_unproven")
        else:
            mismatches.append("mcp_fresh_session_proof_pending")
    return {
        "status": "ok" if not mismatches else "attention_required",
        "state": "verified" if not mismatches else "degraded",
        "ready": not mismatches,
        "proof_level": proof_level,
        "desired_state_digest": _digest(desired),
        "observed_state_digest": snapshot["observed_state_digest"],
        "reason_codes": mismatches,
        "health_axes": snapshot["health_axes"],
    }


def lifecycle_review_bundle(
    request: Mapping[str, Any], *, receipt_limit: int = 200,
    audience: str = "local-operator",
    privacy_ceiling: str = "internal",
    evidence_references: list[Mapping[str, Any]] | None = None,
    redaction_manifest: list[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a path-free, digest-sealed review view of lifecycle evidence."""

    limit = max(1, min(int(receipt_limit), 1_000))
    snapshot = inspect_lifecycle(request)
    receipts = []
    receipts_dir = _control_root(request) / "receipts"
    if receipts_dir.is_dir() and not receipts_dir.is_symlink():
        for path in sorted(receipts_dir.glob("*.json"), reverse=True):
            if len(receipts) >= limit:
                break
            payload = read_json(path)
            if not payload or payload.get("schema") != LIFECYCLE_SCHEMA:
                continue
            receipts.append({
                "operation_id": payload.get("operation_id"),
                "state": payload.get("state"),
                "execution_kind": payload.get("execution_kind"),
                "attempt": payload.get("attempt"),
                "plan_digest": payload.get("plan_digest"),
                "observed_state_digest": payload.get("observed_state_digest"),
                "desired_state_digest": payload.get("desired_state_digest"),
                "rollback_state": payload.get("rollback_state"),
                "error_class": payload.get("error_class"),
                "steps": [
                    {
                        "operation": step.get("operation"),
                        "state": step.get("state"),
                        "observed_service_state": step.get(
                            "observed_service_state"
                        ),
                        "error_class": step.get("error_class"),
                    }
                    for step in payload.get("steps", [])
                    if isinstance(step, Mapping)
                ],
            })
    automatic_references = [
        {
            "kind": "lifecycle-receipt",
            "reference": f"receipt:{receipt['operation_id']}",
            "digest": _digest(receipt),
        }
        for receipt in receipts
        if receipt.get("operation_id")
    ]
    references = normalize_evidence_references(
        [*automatic_references, *(evidence_references or [])]
    )
    redactions = normalize_redaction_manifest(
        redaction_manifest
        or [
            {"field": "local_paths", "action": "fingerprinted"},
            {"field": "receipt_paths", "action": "omitted"},
            {"field": "error_messages", "action": "class_only"},
            {"field": "event_content", "action": "omitted"},
        ]
    )
    body = {
        "schema": "rta-smriti.trusted-lifecycle-review/v1",
        "bundle_version": 1,
        "status": "ok",
        "summary_authority": "non_authoritative",
        "summary_label": "Non-authoritative operational summary",
        "audience": normalize_audience(audience),
        "privacy_ceiling": normalize_privacy_ceiling(privacy_ceiling),
        "project_fingerprint": snapshot["project_fingerprint"],
        "database_fingerprint": snapshot["database_fingerprint"],
        "root_fingerprint": snapshot["root_fingerprint"],
        "enrollment_state": snapshot["enrollment_state"],
        "reason_codes": snapshot["reason_codes"],
        "observed_state_digest": snapshot["observed_state_digest"],
        "desired_state_digest": snapshot["desired_state_digest"],
        "health_axes": snapshot["health_axes"],
        "evidence_reference_manifest": references,
        "redaction_manifest": redactions,
        "receipt_count": len(receipts),
        "receipts": receipts,
    }
    return {**body, "bundle_digest": _digest(body)}


def repair_lifecycle(
    request: Mapping[str, Any],
    confirmation: Mapping[str, Any],
) -> dict[str, Any]:
    """Reconcile observed process state with the persisted desired state."""

    recovery = _recoverable_journal(_control_root(request))
    plan = plan_repair_lifecycle(request)
    desired_digest = (
        plan.get("source_desired_state_digest")
        or _digest(plan["desired_state"])
    )
    if (
        not confirmation.get("approved")
        or confirmation.get("plan_digest") != plan["plan_digest"]
        or confirmation.get("desired_state_digest") != desired_digest
        or confirmation.get("observed_state_digest")
        != plan["observed_state_digest"]
    ):
        raise PermissionError(
            "lifecycle repair confirmation does not match the plan digest, desired state, and observed state"
        )
    if plan["blocked"]:
        raise PermissionError("blocked lifecycle repair plan cannot be applied")
    if not plan["steps"] and recovery is None:
        verified = verify_lifecycle(request, "process")
        return {
            **verified,
            "state": "verified",
            "idempotent_replay": True,
            "operation_id": None,
        }
    receipts_dir = _control_root(request) / "receipts"
    prior_attempts = 0
    if receipts_dir.is_dir():
        for index, path in enumerate(receipts_dir.glob("*.json")):
            if index >= 10_000:
                break
            receipt = read_json(path)
            if receipt and receipt.get("plan_digest") == plan["plan_digest"]:
                prior_attempts += 1
    plan._attempt = prior_attempts + 1
    result = apply_lifecycle(
        plan,
        {
            "approved": True,
            "plan_digest": plan["plan_digest"],
            "observed_state_digest": plan["observed_state_digest"],
        },
    )
    if recovery is not None and result.get("state") == "complete":
        recovery_payload = dict(recovery[1])
        recovery_payload.update({
            "state": "recovered",
            "recovery_operation_id": result.get("operation_id"),
        })
        write_json(
            recovery[0], recovery_payload, label="lifecycle inflight journal"
        )
    return result


def _confirmed_operation_plan(
    plan_or_request: Mapping[str, Any],
    confirmation: Mapping[str, Any],
    *,
    execution_kind: str,
) -> LifecyclePlan:
    if isinstance(plan_or_request, LifecyclePlan):
        plan = plan_or_request
    else:
        planner = (
            plan_stop_lifecycle
            if execution_kind == "stop"
            else plan_remove_lifecycle
        )
        plan = planner(plan_or_request)
    if plan.get("execution_kind") != execution_kind:
        raise PermissionError(
            f"lifecycle {execution_kind} requires its exact previewed plan"
        )
    if (
        confirmation.get("plan_digest") != plan.get("plan_digest")
        or confirmation.get("observed_state_digest")
        != plan.get("observed_state_digest")
    ):
        raise PermissionError(
            f"lifecycle {execution_kind} confirmation does not match the plan digest and observed state"
        )
    return plan


def stop_lifecycle(
    plan_or_request: Mapping[str, Any],
    confirmation: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply an explicitly previewed stop plan while retaining enrollment."""

    plan = _confirmed_operation_plan(
        plan_or_request, confirmation, execution_kind="stop"
    )
    return apply_lifecycle(plan, confirmation)


def remove_lifecycle(
    plan_or_request: Mapping[str, Any],
    confirmation: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply an explicitly previewed remove plan and preserve its receipt."""

    plan = _confirmed_operation_plan(
        plan_or_request, confirmation, execution_kind="remove"
    )
    return apply_lifecycle(plan, confirmation)


def derive_continuation_health(
    lifecycle: Mapping[str, Any] | None,
    *,
    manual_checkpoint_available: bool,
) -> dict[str, Any]:
    """Derive continuity health from data-flow evidence, not process liveness alone."""

    if lifecycle is None:
        return {
            "state": "not_observed",
            "automatic_capture_ready": None,
            "manual_continuation_ready": manual_checkpoint_available,
            "reason_codes": [],
        }

    worker_state = str(lifecycle.get("state") or "not_configured")
    pending = max(0, int(lifecycle.get("sessions_pending") or 0))
    consecutive_errors = max(0, int(lifecycle.get("consecutive_errors") or 0))
    has_error = bool(
        lifecycle.get("has_error")
        or lifecycle.get("last_error")
        or consecutive_errors
    )
    discovered_known = "sessions_discovered" in lifecycle
    discovered = max(0, int(lifecycle.get("sessions_discovered") or 0))
    binding = lifecycle.get("binding_diagnostics")
    binding = binding if isinstance(binding, Mapping) else {}
    matching_known = "matching_sessions" in lifecycle or "matching_sessions" in binding
    matching = max(
        0,
        int(
            lifecycle.get("matching_sessions")
            if "matching_sessions" in lifecycle
            else binding.get("matching_sessions", 0)
        ),
    )
    events_inserted = max(0, int(lifecycle.get("events_inserted") or 0))

    not_running = worker_state != "running"
    awaiting_first_session = (
        not not_running and discovered_known and discovered == 0
    )
    unbound = (
        not not_running
        and matching_known
        and discovered > 0
        and matching == 0
    )
    reasons: list[str] = []
    if not_running:
        reasons.append("continuity_not_running")
    if pending:
        reasons.append("continuity_capture_backlog")
    if has_error:
        reasons.append("continuity_capture_errors")
    if awaiting_first_session:
        reasons.append("continuity_awaiting_first_session")
    if unbound:
        reasons.append("continuity_unbound")

    if not_running:
        state = worker_state if worker_state in {
            "disabled", "unavailable", "stale", "error", "stopped",
        } else "unavailable"
    elif has_error:
        state = "degraded"
    elif pending:
        state = "backlogged"
    elif awaiting_first_session:
        state = "awaiting_first_session"
    elif unbound:
        state = "unbound"
    elif matching_known and matching > 0 and events_inserted == 0:
        state = "idle"
    else:
        state = "healthy"

    return {
        "state": state,
        "automatic_capture_ready": not reasons,
        "manual_continuation_ready": manual_checkpoint_available,
        "reason_codes": reasons,
        "sessions_discovered": discovered if discovered_known else None,
        "matching_sessions": matching if matching_known else None,
        "sessions_pending": pending,
        "events_inserted": events_inserted,
    }
