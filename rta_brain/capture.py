"""Append-only, policy-bound journal for normalized capture observations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sqlite3
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import db
from .binding_guard import binding_gate
from .capture_adapters import capture_attribute_allowlist
from .capture_types import (
    CAPTURE_PRIVACY_CLASSES,
    CAPTURE_VERIFICATION_STATES,
    CapturePolicy,
    CaptureSource,
    NormalizedEvent,
    canonical_json,
    capture_event_envelope,
)
from .privacy import (
    decrypt_local_payload,
    encrypt_local_payload,
    find_sensitive_text,
    redact_sensitive_data,
)
from .repository import (
    canonical_root,
    canonical_root_key,
    checkout_identity,
    repository_identity,
    same_root,
)

_CURSOR_KINDS = frozenset({"byte-offset", "sequence", "opaque"})
_GAP_STATES = frozenset({"none", "detected", "resolved"})
_SYSTEM_ATTRIBUTE = "_capture"
_TIME_SKEW_SECONDS = 5 * 60
_PROJECTION_NAME = "capture-runtime"
_PROJECTION_SCHEMA_VERSION = 1
_FORENSIC_GRANT_SCHEMA = "rta-smriti.capture-forensic-grant/v1"
_KEY_REFERENCE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DELETION_CONFIRMATION_TTL_SECONDS = 300


def _required_text(name: str, value: Any, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    selected = value.strip()
    if not selected or len(selected) > maximum or "\0" in selected:
        raise ValueError(f"{name} must contain 1 to {maximum} safe characters")
    return selected


def _reject_sensitive_identifier(name: str, value: str) -> str:
    if find_sensitive_text(value):
        raise ValueError(f"{name} contains sensitive content")
    return value


def _optional_text(name: str, value: Any, *, maximum: int = 512) -> str | None:
    if value is None:
        return None
    return _required_text(name, value, maximum=maximum)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def _root_fingerprint(root: str | Path) -> str:
    return _digest_text(canonical_root_key(root))


def _validate_digest(name: str, value: str | None) -> str | None:
    selected = _optional_text(name, value, maximum=64)
    if selected is None:
        return None
    if len(selected) != 64 or any(
        character not in "0123456789abcdef" for character in selected
    ):
        raise ValueError(f"{name} must be a 64-character lower-case hexadecimal digest")
    return selected


def _parse_timestamp(name: str, value: str | None) -> datetime | None:
    if value is None:
        return None
    selected = _required_text(name, value, maximum=64)
    try:
        parsed = datetime.fromisoformat(selected)
    except ValueError as exc:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    return parsed


def _forensic_key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("forensic grant key must contain exactly 32 bytes")
    return value


def _forensic_claims(grant: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": grant["schema_version"],
        "project": grant["project"],
        "source_id": grant["source_id"],
        "policy_digest": grant["policy_digest"],
        "actor_id": grant["actor_id"],
        "key_reference": grant["key_reference"],
        "issued_at": grant["issued_at"],
        "expires_at": grant["expires_at"],
    }


def issue_forensic_grant(
    *,
    project: str,
    source_id: str,
    policy_digest: str,
    actor_id: str,
    key_reference: str,
    expires_at: str,
    signing_key: bytes,
    issued_at: str | None = None,
) -> dict[str, Any]:
    """Issue a time-bounded local operator capability for encrypted payload capture."""

    selected_key = _forensic_key(signing_key)
    selected_reference = _required_text("key_reference", key_reference, maximum=128)
    if _KEY_REFERENCE_PATTERN.fullmatch(selected_reference) is None:
        raise ValueError("key_reference must be an opaque local key identifier")
    issued = _parse_timestamp(
        "issued_at",
        issued_at or datetime.now(UTC).isoformat(),
    )
    expires = _parse_timestamp("expires_at", expires_at)
    if issued is None or expires is None or expires <= issued:
        raise ValueError("forensic grant expiry must follow its issue time")
    claims = {
        "schema_version": _FORENSIC_GRANT_SCHEMA,
        "project": _required_text("project", project, maximum=256),
        "source_id": _required_text("source_id", source_id, maximum=256),
        "policy_digest": _validate_digest("policy_digest", policy_digest),
        "actor_id": _required_text("actor_id", actor_id, maximum=256),
        "key_reference": selected_reference,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
    }
    grant_id = _digest_text(canonical_json(claims))
    signed = {**claims, "grant_id": grant_id}
    signature = hmac.new(
        selected_key,
        canonical_json(signed).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return {**signed, "signature": signature}


def _validate_forensic_grant(
    grant: Mapping[str, Any] | None,
    *,
    project: str,
    source_id: str,
    policy_digest: str,
    key: bytes,
    now: datetime | None = None,
    require_current: bool = True,
) -> dict[str, Any]:
    if grant is None:
        raise ValueError("forensic grant is required for retained payload capture")
    if not isinstance(grant, Mapping):
        raise TypeError("forensic grant must be a mapping")
    required = {
        "schema_version",
        "project",
        "source_id",
        "policy_digest",
        "actor_id",
        "key_reference",
        "issued_at",
        "expires_at",
        "grant_id",
        "signature",
    }
    if set(grant) != required:
        raise ValueError("forensic grant fields are invalid")
    try:
        claims = _forensic_claims(grant)
    except KeyError as exc:
        raise ValueError("forensic grant fields are invalid") from exc
    expected_boundary = {
        "schema_version": _FORENSIC_GRANT_SCHEMA,
        "project": project,
        "source_id": source_id,
        "policy_digest": policy_digest,
    }
    if any(claims[name] != value for name, value in expected_boundary.items()):
        raise ValueError("forensic grant does not match the capture boundary")
    _reject_sensitive_identifier(
        "forensic grant actor_id",
        _required_text("forensic grant actor_id", claims["actor_id"], maximum=256),
    )
    selected_reference = _required_text(
        "key_reference",
        claims["key_reference"],
        maximum=128,
    )
    if _KEY_REFERENCE_PATTERN.fullmatch(selected_reference) is None:
        raise ValueError("forensic grant key reference is invalid")
    expected_id = _digest_text(canonical_json(claims))
    if not hmac.compare_digest(str(grant["grant_id"]), expected_id):
        raise ValueError("forensic grant identity is invalid")
    signed = {**claims, "grant_id": str(grant["grant_id"])}
    expected_signature = hmac.new(
        _forensic_key(key),
        canonical_json(signed).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(grant["signature"]), expected_signature):
        raise ValueError("forensic grant signature is invalid")
    issued = _parse_timestamp("forensic grant issued_at", str(claims["issued_at"]))
    expires = _parse_timestamp("forensic grant expires_at", str(claims["expires_at"]))
    current = now or datetime.now(UTC)
    if issued is None or expires is None or expires <= issued:
        raise ValueError("forensic grant validity interval is invalid")
    if require_current and (current < issued or current >= expires):
        raise ValueError("forensic grant is not currently valid")
    return {**claims, "grant_id": str(grant["grant_id"])}


def _payload_key(master_key: bytes, event_id: str) -> bytes:
    return hmac.new(
        _forensic_key(master_key),
        b"rta-smriti/capture-payload/v1\0" + event_id.encode("ascii"),
        hashlib.sha256,
    ).digest()


def _payload_associated_data(
    *,
    project: str,
    source_id: str,
    policy_digest: str,
    event_id: str,
    payload_sha256: str,
    grant_id: str,
    key_reference: str,
) -> bytes:
    return canonical_json(
        {
            "schema_version": "rta-smriti.capture-payload/v1",
            "project": project,
            "source_id": source_id,
            "policy_digest": policy_digest,
            "event_id": event_id,
            "payload_sha256": payload_sha256,
            "grant_id": grant_id,
            "key_reference": key_reference,
        }
    ).encode("ascii")


def _numeric_cursor(kind: str, value: str) -> int | None:
    selected = _required_text("source_cursor", value, maximum=512)
    if kind == "opaque":
        return None
    if not selected.isascii() or not selected.isdecimal():
        raise ValueError(f"{kind} cursor must be an unsigned decimal integer")
    number = int(selected)
    if number < 0 or number > 2**63 - 1:
        raise ValueError(f"{kind} cursor is outside the supported range")
    return number


def _begin(conn: sqlite3.Connection) -> None:
    if conn.in_transaction:
        raise RuntimeError("capture writes require an independent database transaction")
    conn.execute("BEGIN IMMEDIATE")


def verify_capture_project_binding(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
) -> sqlite3.Row:
    """Verify that an operation is bound to the exact live project checkout."""

    selected_project = _required_text("project", project, maximum=128)
    row = conn.execute(
        """
        SELECT id, root_path, repository_identity, checkout_identity
        FROM projects WHERE name = ?
        """,
        (selected_project,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown project: {selected_project}")
    requested_root = canonical_root(active_root)
    if not row["root_path"] or not same_root(str(row["root_path"]), requested_root):
        raise ValueError("capture access requires the exact canonical project root")
    try:
        live_repository = repository_identity(requested_root, create_marker=False)
        live_checkout = checkout_identity(requested_root, create_marker=False)
    except (OSError, ValueError) as exc:
        raise ValueError(
            "capture access could not verify the canonical project binding"
        ) from exc
    if (
        live_repository != row["repository_identity"]
        or live_checkout != row["checkout_identity"]
    ):
        raise ValueError("capture access rejected because the project binding drifted")
    for candidate in conn.execute(
        "SELECT id, root_path FROM projects WHERE id != ? AND root_path IS NOT NULL",
        (int(row["id"]),),
    ):
        try:
            duplicate = same_root(str(candidate["root_path"]), requested_root)
        except (OSError, ValueError):
            duplicate = False
        if duplicate:
            raise ValueError(
                "capture routing is ambiguous across canonical project bindings"
            )
    return row


def _project_for_write(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
) -> sqlite3.Row:
    return verify_capture_project_binding(
        conn,
        project=project,
        active_root=active_root,
    )


def _policy_result(row: sqlite3.Row, *, idempotent_replay: bool) -> dict[str, Any]:
    return {
        "policy_id": str(row["policy_id"]),
        "policy_version": int(row["policy_version"]),
        "policy_digest": str(row["policy_digest"]),
        "idempotent_replay": idempotent_replay,
    }


def register_policy(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    policy_id: str,
    policy_version: int,
    policy: CapturePolicy,
) -> dict[str, Any]:
    """Register one immutable capture policy version for a canonical project."""

    if not isinstance(policy, CapturePolicy):
        raise TypeError("policy must be a CapturePolicy")
    selected_policy_id = _required_text("policy_id", policy_id, maximum=128)
    if type(policy_version) is not int or policy_version <= 0:
        raise ValueError("policy_version must be a positive integer")
    db.init_schema(conn)
    try:
        _begin(conn)
        project_row = _project_for_write(
            conn,
            project=project,
            active_root=active_root,
        )
        project_id = int(project_row["id"])
        existing = conn.execute(
            """
            SELECT * FROM capture_policies
            WHERE project_id = ? AND policy_id = ? AND policy_version = ?
            """,
            (project_id, selected_policy_id, policy_version),
        ).fetchone()
        if existing is not None:
            if not hmac.compare_digest(str(existing["policy_digest"]), policy.digest):
                raise ValueError(
                    "capture policy version is already bound to different content"
                )
            conn.commit()
            return _policy_result(existing, idempotent_replay=True)
        digest_owner = conn.execute(
            "SELECT policy_id, policy_version FROM capture_policies WHERE project_id = ? AND policy_digest = ?",
            (project_id, policy.digest),
        ).fetchone()
        if digest_owner is not None:
            raise ValueError(
                "capture policy content is already registered under another identity"
            )
        policy_data = policy.as_dict()
        created_at = db.now_iso()
        conn.execute(
            """
            INSERT INTO capture_policies(
                project_id, policy_id, policy_version, profile,
                enabled_event_names_json, field_allowlist_json, privacy_ceiling,
                retain_payloads, retention_seconds, max_event_bytes,
                max_field_chars, max_collection_items, policy_digest, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                selected_policy_id,
                policy_version,
                policy.profile,
                canonical_json(policy_data["enabled_event_names"]),
                canonical_json(policy_data["field_allowlist"]),
                policy.privacy_ceiling,
                int(policy.retain_payloads),
                policy.retention_seconds,
                policy.max_event_bytes,
                policy.max_field_chars,
                policy.max_collection_items,
                policy.digest,
                created_at,
            ),
        )
        row = conn.execute(
            """
            SELECT * FROM capture_policies
            WHERE project_id = ? AND policy_id = ? AND policy_version = ?
            """,
            (project_id, selected_policy_id, policy_version),
        ).fetchone()
        conn.commit()
        return _policy_result(row, idempotent_replay=False)
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def retire_capture_policy(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    policy_digest: str,
) -> dict[str, Any]:
    """Retire immutable policy content through a guarded one-way transition."""

    selected_digest = _validate_digest("policy_digest", policy_digest)
    db.init_schema(conn)
    try:
        _begin(conn)
        project_row = _project_for_write(conn, project=project, active_root=active_root)
        project_id = int(project_row["id"])
        policy = conn.execute(
            "SELECT * FROM capture_policies WHERE project_id = ? AND policy_digest = ?",
            (project_id, selected_digest),
        ).fetchone()
        if policy is None:
            raise ValueError("capture policy was not found")
        if policy["retired_at"] is not None:
            conn.commit()
            return {
                **_policy_result(policy, idempotent_replay=True),
                "retired_at": str(policy["retired_at"]),
            }
        dependencies = int(
            conn.execute(
                """
            SELECT COUNT(*) FROM capture_sources
            WHERE project_id = ? AND policy_digest = ? AND state != 'removed'
            """,
                (project_id, selected_digest),
            ).fetchone()[0]
        )
        if dependencies:
            raise ValueError(
                "capture policy cannot retire while active capture sources depend on it"
            )
        retired_at = db.now_iso()
        conn.execute(
            "UPDATE capture_policies SET retired_at = ? WHERE id = ?",
            (retired_at, int(policy["id"])),
        )
        retired = conn.execute(
            "SELECT * FROM capture_policies WHERE id = ?",
            (int(policy["id"]),),
        ).fetchone()
        conn.commit()
        return {
            **_policy_result(retired, idempotent_replay=False),
            "retired_at": str(retired["retired_at"]),
        }
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def list_capture_policies(
    conn: sqlite3.Connection,
    *,
    project: str,
    include_retired: bool = False,
) -> dict[str, Any]:
    """List bounded, content-free capture policy metadata."""

    db.init_schema(conn)
    project_row = conn.execute(
        "SELECT id FROM projects WHERE name = ?",
        (_required_text("project", project, maximum=128),),
    ).fetchone()
    if project_row is None:
        raise ValueError(f"unknown project: {project}")
    where = "" if include_retired else "AND retired_at IS NULL"
    rows = conn.execute(
        f"""
        SELECT policy_id, policy_version, profile, privacy_ceiling,
               retain_payloads, retention_seconds, max_event_bytes,
               max_field_chars, max_collection_items, policy_digest,
               created_at, retired_at
        FROM capture_policies
        WHERE project_id = ? {where}
        ORDER BY policy_id, policy_version
        """,  # nosec B608 - closed internal predicate only
        (int(project_row["id"]),),
    ).fetchall()
    return {
        "status": "ok",
        "policies": [
            {
                **dict(row),
                "retain_payloads": bool(row["retain_payloads"]),
            }
            for row in rows
        ],
    }


def register_source(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    source: CaptureSource,
    policy_digest: str,
) -> dict[str, Any]:
    """Register a source against an exact immutable policy and checkout identity."""

    if not isinstance(source, CaptureSource):
        raise TypeError("source must be a CaptureSource")
    selected_digest = _validate_digest("policy_digest", policy_digest)
    db.init_schema(conn)
    try:
        _begin(conn)
        project_row = _project_for_write(
            conn,
            project=project,
            active_root=active_root,
        )
        project_id = int(project_row["id"])
        policy_row = conn.execute(
            """
            SELECT * FROM capture_policies
            WHERE project_id = ? AND policy_digest = ? AND retired_at IS NULL
            """,
            (project_id, selected_digest),
        ).fetchone()
        if policy_row is None:
            raise ValueError(
                "capture source requires an active registered policy digest"
            )
        existing = conn.execute(
            "SELECT * FROM capture_sources WHERE project_id = ? AND source_id = ?",
            (project_id, source.source_id),
        ).fetchone()
        expected = {
            "adapter": source.adapter,
            "adapter_version": source.adapter_version,
            "installation_scope": source.installation_scope,
            "config_fingerprint": source.config_fingerprint,
            "policy_row_id": int(policy_row["id"]),
            "policy_digest": selected_digest,
            "repository_identity": project_row["repository_identity"],
            "checkout_identity": project_row["checkout_identity"],
        }
        if existing is not None:
            if any(existing[key] != value for key, value in expected.items()):
                raise ValueError(
                    "capture source ID is already bound to different configuration"
                )
            conn.commit()
            return {
                "source_id": source.source_id,
                "policy_digest": selected_digest,
                "state": str(existing["state"]),
                "idempotent_replay": True,
            }
        now = db.now_iso()
        conn.execute(
            """
            INSERT INTO capture_sources(
                project_id, source_id, adapter, adapter_version, installation_scope,
                config_fingerprint, policy_row_id, policy_digest,
                repository_identity, checkout_identity, state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (
                project_id,
                source.source_id,
                source.adapter,
                source.adapter_version,
                source.installation_scope,
                source.config_fingerprint,
                int(policy_row["id"]),
                selected_digest,
                project_row["repository_identity"],
                project_row["checkout_identity"],
                now,
                now,
            ),
        )
        conn.commit()
        return {
            "source_id": source.source_id,
            "policy_digest": selected_digest,
            "state": "active",
            "idempotent_replay": False,
        }
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def list_capture_sources(
    conn: sqlite3.Connection,
    *,
    project: str,
) -> dict[str, Any]:
    """List bounded source lifecycle metadata without configuration paths."""

    db.init_schema(conn)
    project_row = conn.execute(
        "SELECT id FROM projects WHERE name = ?",
        (_required_text("project", project, maximum=128),),
    ).fetchone()
    if project_row is None:
        raise ValueError(f"unknown project: {project}")
    rows = conn.execute(
        """
        SELECT source_id, adapter, adapter_version, installation_scope,
               config_fingerprint, policy_digest, state, last_heartbeat_at,
               last_event_at, last_error_class, consecutive_errors,
               created_at, updated_at, removed_at
        FROM capture_sources
        WHERE project_id = ?
        ORDER BY source_id
        LIMIT 1024
        """,
        (int(project_row["id"]),),
    ).fetchall()
    return {"status": "ok", "sources": [dict(row) for row in rows]}


def set_capture_source_state(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    source_id: str,
    state: str,
) -> dict[str, Any]:
    """Apply a guarded source lifecycle transition."""

    selected_source = _required_text("source_id", source_id, maximum=256)
    selected_state = _required_text("state", state, maximum=16).lower()
    if selected_state not in {"active", "paused", "removed"}:
        raise ValueError("capture source state must be active, paused, or removed")
    db.init_schema(conn)
    try:
        _begin(conn)
        project_row = _project_for_write(conn, project=project, active_root=active_root)
        row = conn.execute(
            "SELECT * FROM capture_sources WHERE project_id = ? AND source_id = ?",
            (int(project_row["id"]), selected_source),
        ).fetchone()
        if row is None:
            raise ValueError("unknown capture source")
        current = str(row["state"])
        if current == "removed" and selected_state != "removed":
            raise ValueError("removed capture sources cannot be reactivated")
        if current == "error" and selected_state == "active":
            raise ValueError("errored capture sources require repair before resume")
        now = db.now_iso()
        conn.execute(
            """
            UPDATE capture_sources
            SET state = ?, updated_at = ?,
                removed_at = CASE WHEN ? = 'removed' THEN ? ELSE removed_at END
            WHERE id = ?
            """,
            (selected_state, now, selected_state, now, int(row["id"])),
        )
        conn.commit()
        return {
            "status": "ok",
            "source_id": selected_source,
            "previous_state": current,
            "state": selected_state,
            "idempotent_replay": current == selected_state,
        }
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def _connection_database(conn: sqlite3.Connection) -> Path:
    row = conn.execute("PRAGMA database_list").fetchone()
    if row is None or not row[2] or str(row[2]) == ":memory:":
        raise ValueError("session binding requires a file-backed brain database")
    return Path(str(row[2])).expanduser().resolve()


def _validated_database(conn: sqlite3.Connection, database: str | Path) -> Path:
    connected = _connection_database(conn)
    requested = Path(database).expanduser().resolve()
    if connected != requested:
        raise ValueError("session binding database does not match the active brain")
    return connected


def bind_session(
    conn: sqlite3.Connection,
    *,
    database: str | Path,
    project: str,
    active_root: str | Path,
    source_id: str,
    external_session_id: str,
    cursor_kind: str,
    start_cursor: str,
    operator_id: str,
) -> dict[str, Any]:
    """Create a privacy-safe receipt accepting only the current cursor forward."""

    selected_source = _required_text("source_id", source_id, maximum=256)
    selected_session = _reject_sensitive_identifier(
        "external_session_id",
        _required_text("external_session_id", external_session_id, maximum=512),
    )
    selected_operator = _required_text("operator_id", operator_id, maximum=256)
    selected_kind = _required_text("cursor_kind", cursor_kind, maximum=32)
    if selected_kind not in _CURSOR_KINDS:
        raise ValueError(f"unsupported capture cursor kind: {selected_kind}")
    if selected_kind == "opaque":
        raise ValueError(
            "explicit session binding requires an ordered byte-offset or sequence cursor"
        )
    selected_cursor = _required_text("start_cursor", start_cursor, maximum=512)
    cursor_number = _numeric_cursor(selected_kind, selected_cursor)
    db.init_schema(conn)
    database_path = _validated_database(conn, database)
    with binding_gate(database_path, project):
        try:
            _begin(conn)
            project_row = _project_for_write(
                conn,
                project=project,
                active_root=active_root,
            )
            project_id = int(project_row["id"])
            source = conn.execute(
                "SELECT * FROM capture_sources WHERE project_id = ? AND source_id = ?",
                (project_id, selected_source),
            ).fetchone()
            if source is None or source["state"] != "active":
                raise ValueError(
                    "session binding requires an active registered capture source"
                )
            if (
                source["repository_identity"] != project_row["repository_identity"]
                or source["checkout_identity"] != project_row["checkout_identity"]
            ):
                raise ValueError(
                    "capture source binding drifted from the canonical checkout"
                )
            existing = conn.execute(
                """
                SELECT * FROM capture_session_bindings
                WHERE project_id = ? AND source_id = ? AND external_session_id = ?
                  AND start_cursor = ? AND status = 'active'
                """,
                (project_id, selected_source, selected_session, selected_cursor),
            ).fetchone()
            fingerprint = _root_fingerprint(active_root)
            if existing is not None:
                matches = (
                    existing["cursor_kind"] == selected_kind
                    and hmac.compare_digest(
                        str(existing["root_fingerprint"]), fingerprint
                    )
                    and existing["repository_identity"]
                    == project_row["repository_identity"]
                    and existing["checkout_identity"]
                    == project_row["checkout_identity"]
                )
                if not matches:
                    raise ValueError(
                        "existing session binding receipt conflicts with current identity"
                    )
                conn.commit()
                return {
                    "binding_id": str(existing["binding_id"]),
                    "start_cursor": str(existing["start_cursor"]),
                    "cursor_kind": str(existing["cursor_kind"]),
                    "status": "active",
                    "idempotent_replay": True,
                }
            now = db.now_iso()
            foreign_binding = conn.execute(
                """
                SELECT 1 FROM capture_session_bindings
                WHERE project_id != ? AND source_id = ?
                  AND external_session_id = ? AND status = 'active'
                LIMIT 1
                """,
                (project_id, selected_source, selected_session),
            ).fetchone()
            if foreign_binding is not None:
                raise ValueError(
                    "capture session is already bound to another project; "
                    "close that receipt before explicit rebinding"
                )
            conn.execute(
                """
                UPDATE capture_session_bindings
                SET status = 'closed', closed_at = ?
                WHERE project_id = ? AND source_id = ?
                  AND external_session_id = ? AND status = 'active'
                """,
                (now, project_id, selected_source, selected_session),
            )
            binding_id = uuid.uuid4().hex
            conn.execute(
                """
                INSERT INTO capture_session_bindings(
                    project_id, binding_id, source_id, external_session_id,
                    cursor_kind, start_cursor, root_fingerprint,
                    repository_identity, checkout_identity, status,
                    created_by_type, created_by_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'operator', ?, ?)
                """,
                (
                    project_id,
                    binding_id,
                    selected_source,
                    selected_session,
                    selected_kind,
                    selected_cursor,
                    fingerprint,
                    project_row["repository_identity"],
                    project_row["checkout_identity"],
                    selected_operator,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO capture_adapter_cursors(
                    project_id, source_id, adapter, stream_id, cursor, cursor_kind,
                    binding_offset, last_event_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)
                ON CONFLICT(project_id, source_id, stream_id) DO UPDATE SET
                    adapter = excluded.adapter,
                    cursor = excluded.cursor,
                    cursor_kind = excluded.cursor_kind,
                    binding_offset = excluded.binding_offset,
                    last_event_id = NULL,
                    updated_at = excluded.updated_at
                """,
                (
                    project_id,
                    selected_source,
                    source["adapter"],
                    selected_session,
                    selected_cursor,
                    selected_kind,
                    cursor_number or 0,
                    now,
                ),
            )
            conn.commit()
            return {
                "binding_id": binding_id,
                "start_cursor": selected_cursor,
                "cursor_kind": selected_kind,
                "status": "active",
                "idempotent_replay": False,
            }
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise


def close_session_binding(
    conn: sqlite3.Connection,
    *,
    database: str | Path,
    project: str,
    active_root: str | Path,
    binding_id: str,
    operator_id: str,
) -> dict[str, Any]:
    """Close an explicit session receipt without deleting its audit metadata."""

    selected_binding = _required_text("binding_id", binding_id, maximum=128)
    _required_text("operator_id", operator_id, maximum=256)
    db.init_schema(conn)
    database_path = _validated_database(conn, database)
    with binding_gate(database_path, project):
        try:
            _begin(conn)
            project_row = _project_for_write(
                conn,
                project=project,
                active_root=active_root,
            )
            row = conn.execute(
                "SELECT * FROM capture_session_bindings WHERE project_id = ? AND binding_id = ?",
                (int(project_row["id"]), selected_binding),
            ).fetchone()
            if row is None:
                raise ValueError("unknown capture session binding receipt")
            if row["status"] == "active":
                conn.execute(
                    """
                    UPDATE capture_session_bindings
                    SET status = 'closed', closed_at = ? WHERE id = ?
                    """,
                    (db.now_iso(), int(row["id"])),
                )
            conn.commit()
            return {"binding_id": selected_binding, "status": "closed"}
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise


def _normalized_document(
    event: NormalizedEvent,
    *,
    attributes: dict[str, Any],
) -> dict[str, Any]:
    return {
        "actor_id": event.actor_id,
        "actor_type": event.actor_type,
        "attributes": attributes,
        "causation_event_id": event.causation_event_id,
        "correlation_id": event.correlation_id,
        "event_name": event.event_name,
        "external_event_id": event.external_event_id,
        "external_session_id": event.session_id,
        "observed_at": event.observed_at,
        "occurred_at": event.occurred_at,
        "parent_span_id": event.parent_span_id,
        "source_cursor": event.source_cursor,
        "span_id": event.span_id,
        "trace_id": event.trace_id,
    }


def _policy_from_row(row: sqlite3.Row) -> CapturePolicy:
    field_allowlist = json.loads(str(row["field_allowlist_json"]))
    if not isinstance(field_allowlist, dict):
        raise TypeError("capture policy field allowlist is not an object")
    return CapturePolicy(
        profile=str(row["profile"]),
        enabled_event_names=tuple(json.loads(str(row["enabled_event_names_json"]))),
        field_allowlist={
            str(event_name): tuple(str(item) for item in values)
            for event_name, values in field_allowlist.items()
        },
        privacy_ceiling=str(row["privacy_ceiling"]),
        retain_payloads=bool(row["retain_payloads"]),
        retention_seconds=int(row["retention_seconds"]),
        max_event_bytes=int(row["max_event_bytes"]),
        max_field_chars=int(row["max_field_chars"]),
        max_collection_items=int(row["max_collection_items"]),
    )


def _validate_policy_attributes(
    event_name: str,
    attributes: dict[str, Any],
    policy: CapturePolicy,
) -> None:
    permitted = capture_attribute_allowlist(policy, event_name)
    unexpected = sorted(set(attributes).difference(permitted))
    if unexpected:
        raise ValueError(
            "capture attributes exceed the bound policy allowlist: "
            + ", ".join(unexpected)
        )
    pending = [(value, 1) for value in attributes.values()]
    collection_items = 0
    while pending:
        value, depth = pending.pop()
        if depth > 12:
            raise ValueError("capture attributes exceed the depth limit")
        if isinstance(value, str):
            if len(value) > policy.max_field_chars:
                raise ValueError("capture attribute exceeds the policy character limit")
            continue
        if value is None or type(value) in {bool, int, float}:
            continue
        if isinstance(value, dict):
            collection_items += len(value)
            if collection_items > policy.max_collection_items:
                raise ValueError(
                    "capture attributes exceed the policy collection limit"
                )
            for key, child in value.items():
                if not isinstance(key, str):
                    raise TypeError("capture attribute object keys must be strings")
                if len(key) > min(512, policy.max_field_chars):
                    raise ValueError(
                        "capture attribute object key exceeds the policy character limit"
                    )
                pending.append((child, depth + 1))
            continue
        if isinstance(value, (list, tuple)):
            collection_items += len(value)
            if collection_items > policy.max_collection_items:
                raise ValueError(
                    "capture attributes exceed the policy collection limit"
                )
            pending.extend((child, depth + 1) for child in value)
            continue
        raise TypeError("capture attributes must contain canonical JSON values")


def validate_capture_identifiers(event: NormalizedEvent) -> None:
    """Reject sensitive material before an event reaches any durable queue."""
    values = {
        "external_session_id": event.session_id,
        "source_cursor": event.source_cursor,
        "external_event_id": event.external_event_id,
        "causation_event_id": event.causation_event_id,
        "correlation_id": event.correlation_id,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
    }
    for name, value in values.items():
        if value is not None:
            _reject_sensitive_identifier(f"capture identifier {name}", str(value))


def _matching_duplicate(
    row: sqlite3.Row,
    *,
    source_id: str,
    event: NormalizedEvent,
    normalized_sha256: str,
    source_sha256: str | None,
    original_bytes: int,
    redaction_count: int,
    truncation_count: int,
    privacy_class: str,
    verification_status: str,
    policy_digest: str,
    gap_state: str,
    repository_ref: str | None,
    repository_commit: str | None,
    dirty_digest: str | None,
    cursor_kind: str,
    binding_id: str | None,
    retains_payload: bool,
) -> bool:
    expected = {
        "source_id": source_id,
        "external_session_id": event.session_id,
        "external_event_id": event.external_event_id,
        "source_cursor": event.source_cursor,
        "event_name": event.event_name,
        "observed_at": event.observed_at,
        "occurred_at": event.occurred_at,
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "parent_span_id": event.parent_span_id,
        "causation_event_id": event.causation_event_id,
        "correlation_id": event.correlation_id,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "source_sha256": source_sha256,
        "normalized_sha256": normalized_sha256,
        "original_bytes": original_bytes,
        "redaction_count": redaction_count,
        "truncation_count": truncation_count,
        "privacy_class": privacy_class,
        "verification_status": verification_status,
        "policy_digest": policy_digest,
        "gap_state": gap_state,
    }
    if any(row[key] != value for key, value in expected.items()):
        return False
    anchors = {
        "repository_ref": repository_ref,
        "repository_commit": repository_commit,
        "dirty_digest": dirty_digest,
    }
    if any(row[key] != value for key, value in anchors.items()):
        return False
    if (row["payload_row_id"] is not None) is not retains_payload:
        return False
    flags = json.loads(str(row["attributes_json"])).get(_SYSTEM_ATTRIBUTE, {})
    return (
        flags.get("cursor_kind") == cursor_kind
        and flags.get("binding_id") == binding_id
    )


def _event_result(row: sqlite3.Row, *, idempotent_replay: bool) -> dict[str, Any]:
    flags = json.loads(str(row["attributes_json"])).get(_SYSTEM_ATTRIBUTE, {})
    return {
        "event_id": str(row["event_id"]),
        "project_sequence": int(row["project_sequence"]),
        "event_hash": str(row["event_hash"]),
        "previous_event_hash": row["previous_event_hash"],
        "redaction_count": int(row["redaction_count"]),
        "truncation_count": int(row["truncation_count"]),
        "flags": flags,
        "idempotent_replay": idempotent_replay,
    }


def _event_content(row: sqlite3.Row) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Return integrity-checked mutable content plus immutable system flags."""

    metadata = json.loads(str(row["attributes_json"]))
    flags = metadata.pop(_SYSTEM_ATTRIBUTE, {})
    if not isinstance(flags, dict) or not isinstance(metadata, dict):
        raise TypeError("capture event metadata is malformed")
    keys = set(row.keys())
    if "content_json" not in keys:
        return metadata, flags, "legacy-observation" if metadata else "metadata-only"
    expired = False
    if "content_expires_at" in keys and row["content_expires_at"] is not None:
        expires_at = _parse_timestamp("content expires_at", row["content_expires_at"])
        if expires_at is not None and expires_at <= datetime.now(UTC):
            expired = True
    content_json = row["content_json"]
    if content_json is None:
        return (
            {},
            flags,
            (
                "expired"
                if row["content_deleted_at"] is not None or expired
                else "metadata-only"
            ),
        )
    if not hmac.compare_digest(
        str(row["content_sha256"]),
        _digest_text(str(content_json)),
    ):
        raise ValueError("capture event content integrity check failed")
    content = json.loads(str(content_json))
    if not isinstance(content, dict):
        raise TypeError("capture event content must be an object")
    if expired:
        return {}, flags, "expired"
    return content, flags, "redacted-observation"


def append_event(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    source_id: str,
    event: NormalizedEvent,
    idempotency_key: str,
    cursor_kind: str,
    original_bytes: int,
    redaction_count: int = 0,
    truncation_count: int = 0,
    privacy_class: str = "internal",
    verification_status: str = "unverified",
    source_sha256: str | None = None,
    gap_state: str = "none",
    binding_id: str | None = None,
    repository_ref: str | None = None,
    repository_commit: str | None = None,
    dirty_digest: str | None = None,
    payload: bytes | str | None = None,
    payload_key: bytes | None = None,
    forensic_grant: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one normalized observation after all identity and policy checks."""

    if not isinstance(event, NormalizedEvent):
        raise TypeError("event must be a NormalizedEvent")
    attribute_snapshot = json.loads(canonical_json(dict(event.attributes)))
    if not isinstance(attribute_snapshot, dict):
        raise TypeError("normalized capture attributes must be an object")
    if _SYSTEM_ATTRIBUTE in attribute_snapshot:
        raise ValueError(f"capture attributes reserve the {_SYSTEM_ATTRIBUTE!r} key")
    selected_source = _required_text("source_id", source_id, maximum=256)
    selected_key = _required_text("idempotency_key", idempotency_key, maximum=512)
    selected_kind = _required_text("cursor_kind", cursor_kind, maximum=32)
    if selected_kind not in _CURSOR_KINDS:
        raise ValueError(f"unsupported capture cursor kind: {selected_kind}")
    cursor_number = _numeric_cursor(selected_kind, event.source_cursor)
    selected_binding = _optional_text("binding_id", binding_id, maximum=128)
    if type(original_bytes) is not int or not 0 <= original_bytes <= 1_048_576:
        raise ValueError("original_bytes must be between 0 and 1048576")
    if type(redaction_count) is not int or redaction_count < 0:
        raise ValueError("redaction_count must be a non-negative integer")
    if type(truncation_count) is not int or truncation_count < 0:
        raise ValueError("truncation_count must be a non-negative integer")
    selected_privacy = _required_text(
        "privacy_class", privacy_class, maximum=32
    ).lower()
    if selected_privacy not in CAPTURE_PRIVACY_CLASSES:
        raise ValueError(f"unsupported capture privacy class: {selected_privacy}")
    selected_verification = _required_text(
        "verification_status",
        verification_status,
        maximum=32,
    ).lower()
    if selected_verification not in CAPTURE_VERIFICATION_STATES:
        raise ValueError(
            f"unsupported capture verification state: {selected_verification}"
        )
    selected_gap = _required_text("gap_state", gap_state, maximum=32).lower()
    if selected_gap not in _GAP_STATES:
        raise ValueError(f"unsupported capture gap state: {selected_gap}")
    selected_source_sha = _validate_digest("source_sha256", source_sha256)
    selected_ref = _optional_text("repository_ref", repository_ref, maximum=512)
    selected_commit = _optional_text(
        "repository_commit", repository_commit, maximum=128
    )
    selected_dirty = _validate_digest("dirty_digest", dirty_digest)
    retained_payload = (
        payload.encode("utf-8", errors="strict")
        if isinstance(payload, str)
        else payload
    )
    if retained_payload is not None and not isinstance(retained_payload, bytes):
        raise TypeError("capture payload must be bytes, text, or None")
    if retained_payload is None and (
        payload_key is not None or forensic_grant is not None
    ):
        raise ValueError("forensic grant and payload key require a retained payload")
    validate_capture_identifiers(event)
    occurred = _parse_timestamp("occurred_at", event.occurred_at)
    observed = _parse_timestamp("observed_at", event.observed_at)
    db.init_schema(conn)
    try:
        _begin(conn)
        project_row = _project_for_write(
            conn,
            project=project,
            active_root=active_root,
        )
        project_id = int(project_row["id"])
        source = conn.execute(
            "SELECT * FROM capture_sources WHERE project_id = ? AND source_id = ?",
            (project_id, selected_source),
        ).fetchone()
        if source is None or source["state"] != "active":
            raise ValueError("capture append requires an active registered source")
        if (
            source["repository_identity"] != project_row["repository_identity"]
            or source["checkout_identity"] != project_row["checkout_identity"]
        ):
            raise ValueError(
                "capture source binding drifted from the canonical checkout"
            )
        policy = conn.execute(
            """
            SELECT * FROM capture_policies
            WHERE id = ? AND project_id = ? AND policy_digest = ? AND retired_at IS NULL
            """,
            (int(source["policy_row_id"]), project_id, source["policy_digest"]),
        ).fetchone()
        if policy is None:
            raise ValueError("capture source policy binding is missing or retired")
        bound_policy = _policy_from_row(policy)
        if event.event_name not in bound_policy.enabled_event_names:
            raise ValueError("capture event is not enabled by the bound policy")
        if not hmac.compare_digest(bound_policy.digest, str(policy["policy_digest"])):
            raise ValueError("capture source policy digest does not match its content")
        # Reject smuggled fields before inspecting or transforming their values.
        _validate_policy_attributes(event.event_name, attribute_snapshot, bound_policy)
        redacted_attributes, automatic_redactions = redact_sensitive_data(
            attribute_snapshot,
            max_chars=bound_policy.max_event_bytes,
            max_items=bound_policy.max_collection_items,
            max_depth=12,
        )
        if not isinstance(redacted_attributes, dict):
            raise TypeError("redacted capture attributes must be an object")
        _validate_policy_attributes(event.event_name, redacted_attributes, bound_policy)
        redacted_attributes_json = canonical_json(redacted_attributes)
        if find_sensitive_text(
            redacted_attributes_json,
            max_chars=bound_policy.max_event_bytes,
        ):
            raise ValueError("capture event failed its final privacy verification")
        effective_redaction_count = redaction_count + automatic_redactions
        normalized_json = canonical_json(
            _normalized_document(event, attributes=redacted_attributes)
        )
        normalized_sha256 = _digest_text(normalized_json)
        if len(normalized_json.encode("utf-8")) > bound_policy.max_event_bytes:
            raise ValueError(
                "normalized capture event exceeds the bound policy byte limit"
            )
        if CAPTURE_PRIVACY_CLASSES.index(
            selected_privacy
        ) > CAPTURE_PRIVACY_CLASSES.index(str(policy["privacy_ceiling"])):
            raise ValueError("capture event exceeds the bound policy privacy ceiling")
        grant_claims = None
        payload_sha256 = None
        if retained_payload is not None:
            if bound_policy.profile != "forensic" or not bound_policy.retain_payloads:
                raise ValueError("retained payload capture requires a forensic policy")
            if len(retained_payload) > int(policy["max_event_bytes"]):
                raise ValueError("retained payload exceeds the bound policy byte limit")
            payload_sha256 = hashlib.sha256(retained_payload).hexdigest()
            if selected_source_sha is not None and not hmac.compare_digest(
                selected_source_sha,
                payload_sha256,
            ):
                raise ValueError("source_sha256 does not match the retained payload")
            selected_source_sha = payload_sha256

        binding = None
        if selected_binding is not None:
            binding = conn.execute(
                """
                SELECT * FROM capture_session_bindings
                WHERE project_id = ? AND binding_id = ?
                """,
                (project_id, selected_binding),
            ).fetchone()
            if binding is None:
                raise ValueError("capture session binding is not active")
            if (
                binding["source_id"] != selected_source
                or binding["external_session_id"] != event.session_id
            ):
                raise ValueError(
                    "capture session binding does not match the source session"
                )
            if (
                binding["repository_identity"] != project_row["repository_identity"]
                or binding["checkout_identity"] != project_row["checkout_identity"]
                or not hmac.compare_digest(
                    str(binding["root_fingerprint"]),
                    _root_fingerprint(active_root),
                )
            ):
                raise ValueError(
                    "capture session binding drifted from the canonical checkout"
                )

        duplicate = conn.execute(
            """
            SELECT * FROM capture_events
            WHERE project_id = ? AND source_id = ? AND idempotency_key = ?
            """,
            (project_id, selected_source, selected_key),
        ).fetchone()
        if duplicate is not None:
            if retained_payload is not None:
                if payload_key is None:
                    raise ValueError("forensic grant and payload key are required")
                replay_claims = _validate_forensic_grant(
                    forensic_grant,
                    project=project,
                    source_id=selected_source,
                    policy_digest=str(policy["policy_digest"]),
                    key=payload_key,
                    require_current=False,
                )
                stored_grant = conn.execute(
                    "SELECT grant_id, key_reference FROM capture_payloads WHERE id = ?",
                    (duplicate["payload_row_id"],),
                ).fetchone()
                if stored_grant is None or any(
                    (
                        not hmac.compare_digest(
                            str(stored_grant["grant_id"]),
                            str(replay_claims["grant_id"]),
                        ),
                        stored_grant["key_reference"] != replay_claims["key_reference"],
                    )
                ):
                    raise ValueError("capture retry requires the exact forensic grant")
            if not _matching_duplicate(
                duplicate,
                source_id=selected_source,
                event=event,
                normalized_sha256=normalized_sha256,
                source_sha256=selected_source_sha,
                original_bytes=original_bytes,
                redaction_count=effective_redaction_count,
                truncation_count=truncation_count,
                privacy_class=selected_privacy,
                verification_status=selected_verification,
                policy_digest=str(policy["policy_digest"]),
                gap_state=selected_gap,
                repository_ref=selected_ref,
                repository_commit=selected_commit,
                dirty_digest=selected_dirty,
                cursor_kind=selected_kind,
                binding_id=selected_binding,
                retains_payload=retained_payload is not None,
            ):
                raise ValueError(
                    "idempotency key is already bound to a different capture request"
                )
            conn.commit()
            return _event_result(duplicate, idempotent_replay=True)

        if retained_payload is not None:
            if payload_key is None:
                raise ValueError("forensic grant and payload key are required")
            grant_claims = _validate_forensic_grant(
                forensic_grant,
                project=project,
                source_id=selected_source,
                policy_digest=str(policy["policy_digest"]),
                key=payload_key,
            )

        if binding is not None:
            if binding["status"] != "active":
                raise ValueError("capture session binding is not active")
            if binding["cursor_kind"] != selected_kind:
                raise ValueError(
                    "capture session binding cursor kind does not match the event"
                )
            start_number = _numeric_cursor(selected_kind, str(binding["start_cursor"]))
            if (
                start_number is not None
                and cursor_number is not None
                and cursor_number < start_number
            ):
                raise ValueError(
                    "capture event cursor predates the explicit session binding"
                )

        cursor = conn.execute(
            """
            SELECT * FROM capture_adapter_cursors
            WHERE project_id = ? AND source_id = ? AND stream_id = ?
            """,
            (project_id, selected_source, event.session_id),
        ).fetchone()
        if cursor is not None:
            if cursor["cursor_kind"] != selected_kind:
                raise ValueError("capture cursor kind changed within one source stream")
            current_number = _numeric_cursor(selected_kind, str(cursor["cursor"]))
            first_after_binding = (
                cursor["last_event_id"] is None and binding is not None
            )
            if current_number is not None and cursor_number is not None:
                if cursor_number < current_number or (
                    cursor_number == current_number and not first_after_binding
                ):
                    raise ValueError("capture source cursor must advance monotonically")
            elif cursor["cursor"] == event.source_cursor and not first_after_binding:
                raise ValueError("capture opaque cursor was already consumed")

        previous_session_time = conn.execute(
            """
            SELECT occurred_at FROM capture_events
            WHERE project_id = ? AND source_id = ?
              AND external_session_id = ? AND occurred_at IS NOT NULL
            ORDER BY julianday(occurred_at) DESC LIMIT 1
            """,
            (project_id, selected_source, event.session_id),
        ).fetchone()
        late = bool(
            occurred is not None
            and previous_session_time is not None
            and occurred
            < _parse_timestamp("occurred_at", previous_session_time["occurred_at"])
        )
        time_skew = bool(
            occurred is not None
            and observed is not None
            and abs((observed - occurred).total_seconds()) > _TIME_SKEW_SECONDS
        )
        flags = {
            "cursor_kind": selected_kind,
            "late": late,
            "time_skew": time_skew,
        }
        if binding is not None:
            flags["binding_id"] = str(binding["binding_id"])
        content_json = redacted_attributes_json
        content_bytes = len(content_json.encode("utf-8"))
        attributes_json = canonical_json({_SYSTEM_ATTRIBUTE: flags})
        stored_bytes = len(attributes_json.encode("utf-8")) + content_bytes
        if stored_bytes > int(policy["max_event_bytes"]):
            raise ValueError(
                "normalized capture event exceeds the bound policy byte limit"
            )
        previous = conn.execute(
            """
            SELECT project_sequence, event_hash FROM capture_events
            WHERE project_id = ? ORDER BY project_sequence DESC LIMIT 1
            """,
            (project_id,),
        ).fetchone()
        project_sequence = int(previous["project_sequence"]) + 1 if previous else 1
        previous_hash = str(previous["event_hash"]) if previous else None
        event_id = uuid.uuid4().hex
        recorded_at = db.now_iso()
        payload_record = None
        event_row_id = int(
            conn.execute(
                "SELECT COALESCE(MAX(id), 0) + 1 FROM capture_events"
            ).fetchone()[0]
        )
        payload_row_id = None
        if retained_payload is not None:
            payload_row_id = int(
                conn.execute(
                    "SELECT COALESCE(MAX(id), 0) + 1 FROM capture_payloads"
                ).fetchone()[0]
            )
            associated_data = _payload_associated_data(
                project=project,
                source_id=selected_source,
                policy_digest=str(policy["policy_digest"]),
                event_id=event_id,
                payload_sha256=str(payload_sha256),
                grant_id=str(grant_claims["grant_id"]),
                key_reference=str(grant_claims["key_reference"]),
            )
            payload_record = encrypt_local_payload(
                retained_payload,
                key=_payload_key(payload_key, event_id),
                associated_data=associated_data,
            )
        row_data = {
            "actor_id": event.actor_id,
            "actor_type": event.actor_type,
            "attributes_json": attributes_json,
            "payload_row_id": payload_row_id,
            "causation_event_id": event.causation_event_id,
            "checkout_identity": project_row["checkout_identity"],
            "correlation_id": event.correlation_id,
            "dirty_digest": selected_dirty,
            "event_id": event_id,
            "event_name": event.event_name,
            "external_event_id": event.external_event_id,
            "external_session_id": event.session_id,
            "gap_state": selected_gap,
            "idempotency_key": selected_key,
            "normalized_sha256": normalized_sha256,
            "observed_at": event.observed_at,
            "occurred_at": event.occurred_at,
            "original_bytes": original_bytes,
            "parent_span_id": event.parent_span_id,
            "policy_digest": policy["policy_digest"],
            "previous_event_hash": previous_hash,
            "privacy_class": selected_privacy,
            "project_id": project_id,
            "project_sequence": project_sequence,
            "recorded_at": recorded_at,
            "redaction_count": effective_redaction_count,
            "repository_commit": selected_commit,
            "repository_identity": project_row["repository_identity"],
            "repository_ref": selected_ref,
            "source_cursor": event.source_cursor,
            "source_id": selected_source,
            "source_sha256": selected_source_sha,
            "span_id": event.span_id,
            "stored_bytes": stored_bytes,
            "trace_id": event.trace_id,
            "truncation_count": truncation_count,
            "verification_status": selected_verification,
        }
        event_hash = _digest_text(canonical_json(capture_event_envelope(row_data)))
        conn.execute(
            """
            INSERT INTO capture_events(
                id, project_id, project_sequence, event_id, source_row_id, source_id,
                external_session_id, external_event_id, source_cursor, idempotency_key,
                event_name, occurred_at, observed_at, recorded_at, trace_id, span_id,
                parent_span_id, causation_event_id, correlation_id, actor_type, actor_id,
                repository_identity, checkout_identity, repository_ref, repository_commit,
                dirty_digest, attributes_json, payload_row_id, source_sha256, normalized_sha256,
                previous_event_hash, event_hash, original_bytes, stored_bytes,
                redaction_count, truncation_count, privacy_class, verification_status,
                policy_row_id, policy_digest, gap_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_row_id,
                project_id,
                project_sequence,
                event_id,
                int(source["id"]),
                selected_source,
                event.session_id,
                event.external_event_id,
                event.source_cursor,
                selected_key,
                event.event_name,
                event.occurred_at,
                event.observed_at,
                recorded_at,
                event.trace_id,
                event.span_id,
                event.parent_span_id,
                event.causation_event_id,
                event.correlation_id,
                event.actor_type,
                event.actor_id,
                project_row["repository_identity"],
                project_row["checkout_identity"],
                selected_ref,
                selected_commit,
                selected_dirty,
                attributes_json,
                payload_row_id,
                selected_source_sha,
                normalized_sha256,
                previous_hash,
                event_hash,
                original_bytes,
                stored_bytes,
                effective_redaction_count,
                truncation_count,
                selected_privacy,
                selected_verification,
                int(policy["id"]),
                policy["policy_digest"],
                selected_gap,
            ),
        )
        if redacted_attributes:
            expires_at = (
                datetime.fromisoformat(recorded_at)
                + timedelta(seconds=int(policy["retention_seconds"]))
            ).isoformat()
            conn.execute(
                """
                INSERT INTO capture_event_content(
                    event_row_id, project_id, content_json, content_sha256,
                    content_bytes, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event_row_id,
                    project_id,
                    content_json,
                    _digest_text(content_json),
                    content_bytes,
                    expires_at,
                ),
            )
        if payload_record is not None:
            expires_at = (
                datetime.fromisoformat(recorded_at)
                + timedelta(seconds=int(policy["retention_seconds"]))
            ).isoformat()
            conn.execute(
                """
                INSERT INTO capture_payloads(
                    id, event_row_id, project_id, storage_mode, content_encoding,
                    key_reference, grant_id, nonce, payload_blob, payload_sha256,
                    payload_bytes, expires_at
                ) VALUES (?, ?, ?, 'encrypted', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload_row_id,
                    event_row_id,
                    project_id,
                    payload_record["content_encoding"],
                    grant_claims["key_reference"],
                    grant_claims["grant_id"],
                    payload_record["nonce"],
                    payload_record["ciphertext"],
                    payload_record["sha256"],
                    payload_record["bytes"],
                    expires_at,
                ),
            )
        conn.execute(
            """
            INSERT INTO capture_adapter_cursors(
                project_id, source_id, adapter, stream_id, cursor, cursor_kind,
                binding_offset, last_event_id, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, source_id, stream_id) DO UPDATE SET
                adapter = excluded.adapter,
                cursor = excluded.cursor,
                cursor_kind = excluded.cursor_kind,
                last_event_id = excluded.last_event_id,
                updated_at = excluded.updated_at
            """,
            (
                project_id,
                selected_source,
                source["adapter"],
                event.session_id,
                event.source_cursor,
                selected_kind,
                int(binding["start_cursor"])
                if binding is not None and selected_kind != "opaque"
                else 0,
                event_id,
                recorded_at,
            ),
        )
        conn.execute(
            """
            UPDATE capture_sources
            SET state = 'active', last_event_at = ?, last_heartbeat_at = CASE
                    WHEN ? = 'adapter.heartbeat.v1' THEN ? ELSE last_heartbeat_at END,
                last_error_class = CASE WHEN ? = 'adapter.error.v1' THEN 'adapter_error' ELSE NULL END,
                consecutive_errors = CASE WHEN ? = 'adapter.error.v1'
                    THEN consecutive_errors + 1 ELSE 0 END,
                updated_at = ?
            WHERE id = ?
            """,
            (
                recorded_at,
                event.event_name,
                recorded_at,
                event.event_name,
                event.event_name,
                recorded_at,
                int(source["id"]),
            ),
        )
        inserted = conn.execute(
            "SELECT * FROM capture_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        conn.commit()
        return _event_result(inserted, idempotent_replay=False)
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def read_forensic_payload(
    conn: sqlite3.Connection,
    *,
    project: str,
    event_id: str,
    grant: Mapping[str, Any],
    payload_key: bytes,
) -> bytes:
    """Read one retained payload only through its exact active forensic grant."""

    selected_event = _required_text("event_id", event_id, maximum=128)
    db.init_schema(conn)
    row = conn.execute(
        """
        SELECT e.event_id, e.source_id, e.policy_digest, p.storage_mode,
               p.key_reference, p.grant_id, p.nonce, p.payload_blob, p.payload_sha256,
               p.payload_bytes, p.expires_at, p.deleted_at
        FROM capture_events e
        JOIN projects pr ON pr.id = e.project_id
        JOIN capture_payloads p ON p.id = e.payload_row_id
        WHERE pr.name = ? AND e.event_id = ?
        """,
        (project, selected_event),
    ).fetchone()
    if row is None:
        raise ValueError("retained capture payload was not found")
    now = datetime.now(UTC)
    grant_claims = _validate_forensic_grant(
        grant,
        project=project,
        source_id=str(row["source_id"]),
        policy_digest=str(row["policy_digest"]),
        key=payload_key,
        now=now,
    )
    if any(
        (
            not hmac.compare_digest(
                str(row["grant_id"]), str(grant_claims["grant_id"])
            ),
            row["key_reference"] != grant_claims["key_reference"],
        )
    ):
        raise ValueError("payload read requires the exact forensic grant")
    if row["deleted_at"] is not None or row["payload_blob"] is None:
        raise ValueError("retained capture payload was deleted")
    expires = _parse_timestamp("payload expires_at", row["expires_at"])
    if expires is not None and now >= expires:
        raise ValueError("retained capture payload has expired")
    if row["storage_mode"] != "encrypted":
        raise ValueError("retained capture payload is not encrypted")
    associated_data = _payload_associated_data(
        project=project,
        source_id=str(row["source_id"]),
        policy_digest=str(row["policy_digest"]),
        event_id=selected_event,
        payload_sha256=str(row["payload_sha256"]),
        grant_id=str(row["grant_id"]),
        key_reference=str(row["key_reference"]),
    )
    clear = decrypt_local_payload(
        bytes(row["payload_blob"]),
        key=_payload_key(payload_key, selected_event),
        nonce_hex=str(row["nonce"]),
        associated_data=associated_data,
    )
    if len(clear) != int(row["payload_bytes"]) or not hmac.compare_digest(
        hashlib.sha256(clear).hexdigest(),
        str(row["payload_sha256"]),
    ):
        raise ValueError("retained capture payload integrity check failed")
    return clear


def _retention_result(
    row: sqlite3.Row,
    *,
    wal_checkpoint: dict[str, int],
    idempotent_replay: bool,
) -> dict[str, Any]:
    active_store_cleanup = "complete" if int(wal_checkpoint["busy"]) == 0 else "pending"
    return {
        "run_id": str(row["run_id"]),
        "policy_digest": str(row["policy_digest"]),
        "cutoff_at": str(row["cutoff_at"]),
        "state": str(row["state"]),
        "cursor": row["cursor"],
        "examined_events": int(row["examined_events"]),
        "deleted_payloads": int(row["deleted_payloads"]),
        "redacted_events": int(row["redacted_events"]),
        "error_class": row["error_class"],
        "wal_checkpoint": wal_checkpoint,
        "active_store_cleanup": active_store_cleanup,
        "physical_cleanup_complete": False,
        "idempotent_replay": idempotent_replay,
    }


def _expire_payload(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    deleted_at: str,
) -> bool:
    expires = _parse_timestamp("payload expires_at", row["expires_at"])
    cutoff = _parse_timestamp("retention cutoff", deleted_at)
    if (
        expires is None
        or cutoff is None
        or expires > cutoff
        or row["deleted_at"] is not None
    ):
        return False
    conn.execute(
        """
        UPDATE capture_payloads
        SET payload_blob = NULL, deleted_at = ?, deletion_reason = 'retention-expired'
        WHERE id = ? AND deleted_at IS NULL
        """,
        (deleted_at, int(row["id"])),
    )
    return True


def _expire_event_content(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    deleted_at: str,
) -> bool:
    if row["content_event_row_id"] is None:
        return False
    expires = _parse_timestamp("content expires_at", row["content_expires_at"])
    cutoff = _parse_timestamp("retention cutoff", deleted_at)
    if (
        expires is None
        or cutoff is None
        or expires > cutoff
        or row["content_deleted_at"] is not None
    ):
        return False
    conn.execute(
        """
        UPDATE capture_event_content
        SET content_json = NULL, deleted_at = ?, deletion_reason = 'retention-expired'
        WHERE event_row_id = ? AND deleted_at IS NULL
        """,
        (deleted_at, int(row["content_event_row_id"])),
    )
    return True


def _expire_legacy_session_payload(
    conn: sqlite3.Connection,
    row: sqlite3.Row,
    *,
    project_id: int,
    retention_seconds: int,
    deleted_at: str,
) -> bool:
    if row["source_id"] != "legacy-session-events":
        return False
    prefix = "legacy-session-event:"
    identity = str(row["idempotency_key"])
    if not identity.startswith(prefix) or not identity[len(prefix):].isdigit():
        raise ValueError("legacy capture event identity is malformed")
    if conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_events'"
    ).fetchone() is None:
        raise ValueError("legacy capture event payload table is missing")
    recorded_at = _parse_timestamp("legacy event recorded_at", row["recorded_at"])
    cutoff = _parse_timestamp("retention cutoff", deleted_at)
    if recorded_at is None or cutoff is None:
        return False
    if recorded_at + timedelta(seconds=retention_seconds) > cutoff:
        return False
    updated = conn.execute(
        """
        UPDATE session_events SET payload_json = 'null'
        WHERE id = ? AND project_id = ? AND payload_json <> 'null'
        """,
        (int(identity[len(prefix):]), project_id),
    )
    return updated.rowcount == 1


def run_capture_retention(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    policy_digest: str,
    run_id: str,
    batch_size: int = 100,
    now: str | None = None,
    _authorization_claims: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Process one bounded, resumable payload-retention batch."""

    selected_digest = _validate_digest("policy_digest", policy_digest)
    selected_run = _reject_sensitive_identifier(
        "run_id",
        _required_text("run_id", run_id, maximum=128),
    )
    if type(batch_size) is not int or not 1 <= batch_size <= 1_000:
        raise ValueError("retention batch_size must be between 1 and 1000")
    requested_cutoff = (
        _parse_timestamp("retention now", now) if now is not None else None
    )
    if now is not None and requested_cutoff is None:
        raise ValueError("retention now is required")
    db.init_schema(conn)

    try:
        _begin(conn)
        project_row = _project_for_write(conn, project=project, active_root=active_root)
        project_id = int(project_row["id"])
        policy = conn.execute(
            "SELECT id, retention_seconds FROM capture_policies "
            "WHERE project_id = ? AND policy_digest = ?",
            (project_id, selected_digest),
        ).fetchone()
        if policy is None:
            raise ValueError("retention requires a registered capture policy")
        run = conn.execute(
            "SELECT * FROM capture_retention_runs WHERE project_id = ? AND run_id = ?",
            (project_id, selected_run),
        ).fetchone()
        if run is not None:
            if not hmac.compare_digest(str(run["policy_digest"]), str(selected_digest)):
                raise ValueError("retention run is bound to a different policy")
            stored_cutoff = _parse_timestamp("retention cutoff", str(run["cutoff_at"]))
            if stored_cutoff is None:  # pragma: no cover - schema requires the value
                raise ValueError("retention run cutoff is missing")
            if requested_cutoff is not None and requested_cutoff != stored_cutoff:
                raise ValueError("retention run is bound to a different cutoff")
            cutoff_text = str(run["cutoff_at"])
        else:
            started = db.now_iso()
            cutoff_text = (requested_cutoff or datetime.now(UTC)).isoformat()
        if _authorization_claims is not None:
            authorization_claims = _retention_authorization_claims(
                conn,
                project_id=project_id,
                policy_digest=selected_digest,
                retention_seconds=int(policy["retention_seconds"]),
                run_id=selected_run,
                batch_size=batch_size,
                actor_id=str(_authorization_claims.get("actor_id", "")),
                cutoff_at=cutoff_text,
            )
            expected_claims = {
                key: value
                for key, value in _authorization_claims.items()
                if key != "expires_at"
            }
            if authorization_claims != expected_claims:
                raise PermissionError(
                    "capture retention confirmation does not match the current preview"
                )
        if run is not None and run["state"] == "complete":
            conn.commit()
            return _retention_result(
                run,
                wal_checkpoint=_wal_checkpoint(conn),
                idempotent_replay=True,
            )
        if run is None:
            conn.execute(
                """
                INSERT INTO capture_retention_runs(
                    project_id, run_id, policy_digest, cutoff_at,
                    state, started_at, updated_at
                ) VALUES (?, ?, ?, ?, 'running', ?, ?)
                """,
                (
                    project_id,
                    selected_run,
                    selected_digest,
                    cutoff_text,
                    started,
                    started,
                ),
            )
        conn.commit()
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise

    try:
        _begin(conn)
        project_row = _project_for_write(conn, project=project, active_root=active_root)
        project_id = int(project_row["id"])
        run = conn.execute(
            "SELECT * FROM capture_retention_runs WHERE project_id = ? AND run_id = ?",
            (project_id, selected_run),
        ).fetchone()
        cutoff_text = str(run["cutoff_at"])
        cursor = int(run["cursor"] or 0)
        candidates = conn.execute(
            """
            SELECT e.id AS event_row_id,
                   e.source_id,
                   e.idempotency_key,
                   e.recorded_at,
                   c.event_row_id AS content_event_row_id,
                   c.expires_at AS content_expires_at,
                   c.deleted_at AS content_deleted_at,
                   p.id AS payload_id,
                   p.expires_at AS payload_expires_at,
                   p.deleted_at AS payload_deleted_at
            FROM capture_events e
            LEFT JOIN capture_event_content c ON c.event_row_id = e.id
            LEFT JOIN capture_payloads p ON p.event_row_id = e.id
            WHERE e.project_id = ? AND e.policy_digest = ? AND e.id > ?
            ORDER BY e.id
            LIMIT ?
            """,
            (project_id, selected_digest, cursor, batch_size + 1),
        ).fetchall()
        batch = candidates[:batch_size]
        deleted_payloads = 0
        redacted_events = 0
        for row in batch:
            if _expire_event_content(conn, row, deleted_at=cutoff_text):
                redacted_events += 1
            if _expire_legacy_session_payload(
                conn,
                row,
                project_id=project_id,
                retention_seconds=int(policy["retention_seconds"]),
                deleted_at=cutoff_text,
            ):
                redacted_events += 1
            if row["payload_id"] is not None:
                payload_view = {
                    "id": row["payload_id"],
                    "expires_at": row["payload_expires_at"],
                    "deleted_at": row["payload_deleted_at"],
                }
                deleted_payloads += int(
                    _expire_payload(conn, payload_view, deleted_at=cutoff_text)
                )
        next_cursor = int(batch[-1]["event_row_id"]) if batch else cursor
        complete = len(candidates) <= batch_size
        state = "complete" if complete else "partial"
        updated_at = db.now_iso()
        conn.execute(
            """
            UPDATE capture_retention_runs
            SET state = ?, cursor = ?,
                examined_events = examined_events + ?,
                deleted_payloads = deleted_payloads + ?,
                redacted_events = redacted_events + ?,
                error_class = NULL, updated_at = ?,
                completed_at = CASE WHEN ? = 'complete' THEN ? ELSE NULL END
            WHERE id = ?
            """,
            (
                state,
                str(next_cursor),
                len(batch),
                deleted_payloads,
                redacted_events,
                updated_at,
                state,
                updated_at,
                int(run["id"]),
            ),
        )
        result = conn.execute(
            "SELECT * FROM capture_retention_runs WHERE id = ?",
            (int(run["id"]),),
        ).fetchone()
        conn.commit()
        return _retention_result(
            result,
            wal_checkpoint=_wal_checkpoint(conn),
            idempotent_replay=False,
        )
    except (sqlite3.Error, ValueError, TypeError, RuntimeError, OverflowError) as exc:
        if conn.in_transaction:
            conn.rollback()
        try:
            _begin(conn)
            conn.execute(
                """
                UPDATE capture_retention_runs
                SET state = 'failed', error_class = ?, updated_at = ?, completed_at = NULL
                WHERE project_id = ? AND run_id = ?
                """,
                (type(exc).__name__, db.now_iso(), project_id, selected_run),
            )
            failed = conn.execute(
                "SELECT * FROM capture_retention_runs WHERE project_id = ? AND run_id = ?",
                (project_id, selected_run),
            ).fetchone()
            conn.commit()
            return _retention_result(
                failed,
                wal_checkpoint=_wal_checkpoint(conn),
                idempotent_replay=False,
            )
        except (sqlite3.Error, ValueError, TypeError, RuntimeError, OverflowError):
            if conn.in_transaction:
                conn.rollback()
            raise exc


def _deletion_scope(
    scope: str, token: str, *, project: str
) -> tuple[str, tuple[Any, ...]]:
    if scope == "event-content":
        return "e.event_id = ?", (token,)
    if scope == "session-content":
        return "e.external_session_id = ?", (token,)
    if scope == "source-content":
        return "e.source_id = ?", (token,)
    if scope == "project-content":
        if token not in {project, "*"}:
            raise ValueError(
                "project-content scope token must name the selected project"
            )
        return "1 = 1", ()
    raise ValueError("unsupported capture deletion scope")


def _deletion_confirmation_key(conn: sqlite3.Connection) -> bytes:
    database_rows = conn.execute("PRAGMA database_list").fetchall()
    database_path = next(
        (str(row[2]) for row in database_rows if str(row[1]) == "main"), ""
    )
    if not database_path:
        raise ValueError(
            "capture deletion confirmation requires a file-backed brain database"
        )
    # Imported lazily to avoid the context-host/context-snapshot capture cycle.
    from .context_host import load_context_authority_secret

    return hmac.new(
        load_context_authority_secret(Path(database_path)),
        b"rta-smriti.capture-deletion-confirmation/v1",
        hashlib.sha256,
    ).digest()


def _deletion_confirmation_token(
    claims: Mapping[str, Any], *, confirmation_key: bytes
) -> str:
    payload = canonical_json(dict(claims)).encode("ascii")
    signature = hmac.new(
        confirmation_key,
        payload,
        hashlib.sha256,
    ).digest()
    return (
        base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        + "."
        + base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    )


def _verify_deletion_confirmation(
    token: str | None,
    expected: Mapping[str, Any],
    *,
    confirmation_key: bytes,
) -> None:
    if not isinstance(token, str) or not token or len(token) > 4_096:
        raise PermissionError(
            "capture deletion requires its preview confirmation token"
        )
    try:
        payload_text, signature_text = token.split(".", 1)
        payload = base64.urlsafe_b64decode(
            payload_text + "=" * (-len(payload_text) % 4)
        )
        signature = base64.urlsafe_b64decode(
            signature_text + "=" * (-len(signature_text) % 4)
        )
        claims = json.loads(payload.decode("ascii"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise PermissionError(
            "capture deletion confirmation token is malformed"
        ) from exc
    if (
        not isinstance(claims, dict)
        or canonical_json(claims).encode("ascii") != payload
    ):
        raise PermissionError("capture deletion confirmation token is non-canonical")
    expected_signature = hmac.new(
        confirmation_key,
        payload,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(signature, expected_signature):
        raise PermissionError("capture deletion confirmation token is invalid")
    expires_at = _parse_timestamp(
        "deletion confirmation expires_at", claims.get("expires_at")
    )
    if expires_at is None or datetime.now(UTC) >= expires_at:
        raise PermissionError("capture deletion confirmation token expired")
    if any(claims.get(key) != value for key, value in expected.items()):
        raise PermissionError(
            "capture deletion confirmation does not match the preview"
        )


def _retention_confirmation_key(conn: sqlite3.Connection) -> bytes:
    return hmac.new(
        _deletion_confirmation_key(conn),
        b"rta-smriti.capture-retention-confirmation/v1",
        hashlib.sha256,
    ).digest()


def _verify_retention_confirmation(
    token: str | None,
    expected: Mapping[str, Any],
    *,
    confirmation_key: bytes,
) -> dict[str, Any]:
    if not isinstance(token, str) or not token or len(token) > 4_096:
        raise PermissionError(
            "capture retention requires its preview confirmation token"
        )
    try:
        payload_text, signature_text = token.split(".", 1)
        payload = base64.urlsafe_b64decode(
            payload_text + "=" * (-len(payload_text) % 4)
        )
        signature = base64.urlsafe_b64decode(
            signature_text + "=" * (-len(signature_text) % 4)
        )
        claims = json.loads(payload.decode("ascii"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise PermissionError(
            "capture retention confirmation token is malformed"
        ) from exc
    if (
        not isinstance(claims, dict)
        or canonical_json(claims).encode("ascii") != payload
    ):
        raise PermissionError("capture retention confirmation token is non-canonical")
    expected_signature = hmac.new(
        confirmation_key,
        payload,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(signature, expected_signature):
        raise PermissionError("capture retention confirmation token is invalid")
    expires_at = _parse_timestamp(
        "retention confirmation expires_at", claims.get("expires_at")
    )
    if expires_at is None or datetime.now(UTC) >= expires_at:
        raise PermissionError("capture retention confirmation token expired")
    if any(claims.get(key) != value for key, value in expected.items()):
        raise PermissionError(
            "capture retention confirmation does not match the preview"
        )
    return claims


def _retention_authorization_claims(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    policy_digest: str,
    retention_seconds: int,
    run_id: str,
    batch_size: int,
    actor_id: str,
    cutoff_at: str,
) -> dict[str, Any]:
    has_legacy_events = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_events'"
    ).fetchone() is not None
    legacy_clause = (
        """
        OR (
            e.source_id = 'legacy-session-events'
            AND julianday(e.recorded_at) + (? / 86400.0) <= julianday(?)
            AND EXISTS (
                SELECT 1 FROM session_events legacy
                WHERE legacy.project_id = e.project_id
                  AND legacy.id = CAST(substr(e.idempotency_key, 22) AS INTEGER)
                  AND e.idempotency_key = 'legacy-session-event:' || legacy.id
                  AND legacy.payload_json <> 'null'
            )
        )
        """
        if has_legacy_events
        else ""
    )
    legacy_params: tuple[Any, ...] = (
        (retention_seconds, cutoff_at) if has_legacy_events else ()
    )
    row = conn.execute(
        f"""
        SELECT
            COUNT(DISTINCT CASE WHEN (
                (c.deleted_at IS NULL AND c.content_json IS NOT NULL
                 AND julianday(c.expires_at) <= julianday(?))
                OR (p.deleted_at IS NULL AND p.payload_blob IS NOT NULL
                    AND julianday(p.expires_at) <= julianday(?))
                {legacy_clause}
            ) THEN e.id END) AS affected_events,
            COUNT(DISTINCT CASE WHEN
                c.deleted_at IS NULL AND c.content_json IS NOT NULL
                AND julianday(c.expires_at) <= julianday(?)
                THEN c.event_row_id END) AS affected_content_records,
            COUNT(DISTINCT CASE WHEN
                p.deleted_at IS NULL AND p.payload_blob IS NOT NULL
                AND julianday(p.expires_at) <= julianday(?)
                THEN p.id END) AS affected_payloads,
            COALESCE(MAX(e.project_sequence), 0) AS state_fence
        FROM capture_events e
        LEFT JOIN capture_event_content c ON c.event_row_id = e.id
        LEFT JOIN capture_payloads p ON p.event_row_id = e.id
        WHERE e.project_id = ? AND e.policy_digest = ?
        """,  # nosec B608 - the optional clause is selected from a closed internal set.
        (
            cutoff_at,
            cutoff_at,
            *legacy_params,
            cutoff_at,
            cutoff_at,
            project_id,
            policy_digest,
        ),
    ).fetchone()
    affected_content = int(row["affected_content_records"])
    if has_legacy_events:
        affected_content += int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM capture_events e
                JOIN session_events legacy
                  ON legacy.project_id = e.project_id
                 AND e.source_id = 'legacy-session-events'
                 AND e.idempotency_key = 'legacy-session-event:' || legacy.id
                WHERE e.project_id = ? AND e.policy_digest = ?
                  AND legacy.payload_json <> 'null'
                  AND julianday(e.recorded_at) + (? / 86400.0) <= julianday(?)
                """,
                (project_id, policy_digest, retention_seconds, cutoff_at),
            ).fetchone()[0]
        )
    return {
        "schema_version": "rta-smriti.capture-retention-confirmation/v1",
        "operation": "retention",
        "project_id": project_id,
        "policy_digest": policy_digest,
        "run_id": run_id,
        "batch_size": batch_size,
        "actor_id": actor_id,
        "cutoff_at": cutoff_at,
        "affected_events": int(row["affected_events"]),
        "affected_content_records": affected_content,
        "affected_payloads": int(row["affected_payloads"]),
        "state_fence": int(row["state_fence"]),
    }


def control_capture_retention(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    policy_digest: str,
    run_id: str,
    actor_id: str,
    batch_size: int = 100,
    now: str | None = None,
    confirm: bool = False,
    confirmation_token: str | None = None,
) -> dict[str, Any]:
    """Preview or confirm one bounded retention batch for an operator surface."""

    selected_digest = _validate_digest("policy_digest", policy_digest)
    selected_run = _reject_sensitive_identifier(
        "run_id", _required_text("run_id", run_id, maximum=128)
    )
    selected_actor = _reject_sensitive_identifier(
        "actor_id", _required_text("actor_id", actor_id, maximum=256)
    )
    if type(batch_size) is not int or not 1 <= batch_size <= 1_000:
        raise ValueError("retention batch_size must be between 1 and 1000")
    if type(confirm) is not bool:
        raise TypeError("retention confirmation must be a boolean")
    requested_cutoff = (
        _parse_timestamp("retention now", now) if now is not None else None
    )
    db.init_schema(conn)
    confirmation_key = _retention_confirmation_key(conn)
    stable_claims: dict[str, Any]
    if confirm:
        stable_claims = {
            "schema_version": "rta-smriti.capture-retention-confirmation/v1",
            "operation": "retention",
            "policy_digest": selected_digest,
            "run_id": selected_run,
            "batch_size": batch_size,
            "actor_id": selected_actor,
        }
        claims = _verify_retention_confirmation(
            confirmation_token,
            stable_claims,
            confirmation_key=confirmation_key,
        )
        cutoff_at = str(claims.get("cutoff_at", ""))
        parsed_cutoff = _parse_timestamp("retention cutoff", cutoff_at)
        if parsed_cutoff is None:
            raise PermissionError("capture retention confirmation cutoff is invalid")
        if requested_cutoff is not None and requested_cutoff != parsed_cutoff:
            raise PermissionError(
                "capture retention confirmation does not match the requested cutoff"
            )
        return run_capture_retention(
            conn,
            project=project,
            active_root=active_root,
            policy_digest=selected_digest,
            run_id=selected_run,
            batch_size=batch_size,
            now=cutoff_at,
            _authorization_claims=claims,
        )

    try:
        _begin(conn)
        project_row = _project_for_write(conn, project=project, active_root=active_root)
        project_id = int(project_row["id"])
        policy = conn.execute(
            "SELECT retention_seconds FROM capture_policies "
            "WHERE project_id = ? AND policy_digest = ?",
            (project_id, selected_digest),
        ).fetchone()
        if policy is None:
            raise ValueError("retention requires a registered capture policy")
        run = conn.execute(
            "SELECT cutoff_at, policy_digest FROM capture_retention_runs "
            "WHERE project_id = ? AND run_id = ?",
            (project_id, selected_run),
        ).fetchone()
        if run is not None and not hmac.compare_digest(
            str(run["policy_digest"]), selected_digest
        ):
            raise ValueError("retention run is bound to a different policy")
        cutoff_at = (
            str(run["cutoff_at"])
            if run is not None
            else (requested_cutoff or datetime.now(UTC)).isoformat()
        )
        if run is not None and requested_cutoff is not None and (
            requested_cutoff != _parse_timestamp("retention cutoff", cutoff_at)
        ):
            raise ValueError("retention run is bound to a different cutoff")
        claims = _retention_authorization_claims(
            conn,
            project_id=project_id,
            policy_digest=selected_digest,
            retention_seconds=int(policy["retention_seconds"]),
            run_id=selected_run,
            batch_size=batch_size,
            actor_id=selected_actor,
            cutoff_at=cutoff_at,
        )
        expires_at = (
            datetime.now(UTC) + timedelta(seconds=_DELETION_CONFIRMATION_TTL_SECONDS)
        ).replace(microsecond=0).isoformat()
        conn.commit()
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise
    return {
        "operation": "preview",
        **{
            key: claims[key]
            for key in (
                "run_id",
                "policy_digest",
                "cutoff_at",
                "affected_events",
                "affected_content_records",
                "affected_payloads",
                "state_fence",
            )
        },
        "confirmation_token": _deletion_confirmation_token(
            {**claims, "expires_at": expires_at},
            confirmation_key=confirmation_key,
        ),
        "confirmation_expires_at": expires_at,
        "physical_media_erasure_guaranteed": False,
    }


def _wal_checkpoint(conn: sqlite3.Connection) -> dict[str, int]:
    row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    return {
        "busy": int(row[0]),
        "log": int(row[1]),
        "checkpointed": int(row[2]),
    }


def _tombstone_envelope(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "project_id": int(row["project_id"]),
        "scope": str(row["scope"]),
        "scope_token": str(row["scope_token"]),
        "reason_class": str(row["reason_class"]),
        "actor_type": str(row["actor_type"]),
        "actor_id": str(row["actor_id"]),
        "policy_digest": str(row["policy_digest"]),
        "affected_events": int(row["affected_events"]),
        "affected_payloads": int(row["affected_payloads"]),
        "verification_json": str(row["verification_json"]),
        "created_at": str(row["created_at"]),
    }


def _verify_tombstone(row: Mapping[str, Any]) -> None:
    expected = _digest_text(canonical_json(_tombstone_envelope(row)))
    if not hmac.compare_digest(str(row["tombstone_id"]), expected):
        raise ValueError("capture deletion receipt integrity check failed")


def _tombstone_fences(
    rows: Iterable[Mapping[str, Any]],
) -> dict[str, dict[str, int]]:
    """Return the latest verified deletion fence for each scoped token."""

    fences: dict[str, dict[str, int]] = {
        "event-content": {},
        "session-content": {},
        "source-content": {},
        "project-content": {},
    }
    for row in rows:
        _verify_tombstone(row)
        scope = str(row["scope"])
        if scope not in fences:
            raise ValueError("capture deletion receipt scope is invalid")
        try:
            verification = json.loads(str(row["verification_json"]))
        except json.JSONDecodeError as exc:
            raise ValueError("capture deletion receipt verification is invalid") from exc
        state_fence = verification.get("state_fence") if isinstance(verification, dict) else None
        if type(state_fence) is not int or state_fence < 0:
            raise ValueError("capture deletion receipt state fence is invalid")
        token = str(row["scope_token"])
        fences[scope][token] = max(fences[scope].get(token, -1), state_fence)
    return fences


def _content_deleted_at_sequence(
    row: Mapping[str, Any],
    fences: Mapping[str, Mapping[str, int]],
    *,
    project_tokens: set[str],
) -> bool:
    sequence = int(row["project_sequence"])
    scoped_tokens = {
        "event-content": _digest_text(str(row["event_id"])),
        "session-content": _digest_text(str(row["external_session_id"])),
        "source-content": _digest_text(str(row["source_id"])),
    }
    if any(
        sequence <= fences["project-content"].get(token, -1)
        for token in project_tokens
    ):
        return True
    return any(
        sequence <= fences[scope].get(token, -1)
        for scope, token in scoped_tokens.items()
    )


def _deletion_result(
    row: sqlite3.Row,
    *,
    wal_checkpoint: dict[str, int],
    idempotent_replay: bool,
    compaction_completed: bool = False,
) -> dict[str, Any]:
    _verify_tombstone(row)
    verification = json.loads(str(row["verification_json"]))
    erasure = dict(verification["erasure"])
    if compaction_completed:
        erasure["database_compaction"] = "best-effort-complete"
    active_store_cleanup = "complete" if int(wal_checkpoint["busy"]) == 0 else "pending"
    if active_store_cleanup == "pending":
        erasure["journal_content"] = "logically-deleted; active-wal-cleanup-pending"
    return {
        "operation": "logical-delete",
        "tombstone_id": str(row["tombstone_id"]),
        "scope": str(row["scope"]),
        "scope_token_sha256": str(row["scope_token"]),
        "affected_events": int(row["affected_events"]),
        "affected_payloads": int(row["affected_payloads"]),
        "affected_content_records": int(
            verification.get("affected_content_records", 0)
        ),
        "erasure": erasure,
        "wal_checkpoint": wal_checkpoint,
        "active_store_cleanup": active_store_cleanup,
        "logical_deletion_complete": True,
        "physical_cleanup_complete": bool(
            compaction_completed and active_store_cleanup == "complete"
        ),
        "idempotent_replay": idempotent_replay,
    }


def delete_capture_content(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    scope: str,
    scope_token: str,
    reason_class: str,
    actor_id: str,
    policy_digest: str,
    confirm: bool = False,
    confirmation_token: str | None = None,
    secure_compact: bool = False,
) -> dict[str, Any]:
    """Preview or record logical deletion without rewriting journal history."""

    selected_scope = _required_text("scope", scope, maximum=32)
    selected_token = _required_text("scope_token", scope_token, maximum=512)
    selected_reason = _required_text("reason_class", reason_class, maximum=64)
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", selected_reason) is None:
        raise ValueError("reason_class must be a low-cardinality identifier")
    selected_actor = _reject_sensitive_identifier(
        "actor_id",
        _required_text("actor_id", actor_id, maximum=256),
    )
    selected_digest = _validate_digest("policy_digest", policy_digest)
    if type(confirm) is not bool or type(secure_compact) is not bool:
        raise TypeError("deletion confirmation and secure_compact must be booleans")
    predicate, predicate_values = _deletion_scope(
        selected_scope,
        selected_token,
        project=project,
    )
    token_digest = _digest_text(selected_token)
    db.init_schema(conn)
    confirmation_key = _deletion_confirmation_key(conn)
    try:
        _begin(conn)
        project_row = _project_for_write(conn, project=project, active_root=active_root)
        project_id = int(project_row["id"])
        if (
            conn.execute(
                "SELECT 1 FROM capture_policies WHERE project_id = ? AND policy_digest = ?",
                (project_id, selected_digest),
            ).fetchone()
            is None
        ):
            raise ValueError("capture deletion requires a registered policy digest")
        existing_rows = conn.execute(
            """
            SELECT * FROM capture_tombstones
            WHERE project_id = ? AND scope = ? AND scope_token = ?
              AND reason_class = ? AND actor_id = ? AND policy_digest = ?
            """,
            (
                project_id,
                selected_scope,
                token_digest,
                selected_reason,
                selected_actor,
                selected_digest,
            ),
        ).fetchall()
        # _deletion_scope selects the SQL fragment from a closed internal set.
        counts_query = f"""
            SELECT COUNT(DISTINCT e.id) AS events,
                   COALESCE(MAX(e.project_sequence), 0) AS state_fence,
                   COUNT(DISTINCT CASE
                       WHEN c.deleted_at IS NULL AND c.content_json IS NOT NULL
                       THEN c.event_row_id
                   END) AS content_records,
                   COUNT(DISTINCT CASE
                       WHEN p.deleted_at IS NULL AND p.payload_blob IS NOT NULL THEN p.id
                   END) AS payloads
            FROM capture_events e
            LEFT JOIN capture_event_content c ON c.event_row_id = e.id
            LEFT JOIN capture_payloads p ON p.event_row_id = e.id
            WHERE e.project_id = ? AND {predicate}
            """  # nosec B608
        counts = conn.execute(
            counts_query,
            (project_id, *predicate_values),
        ).fetchone()
        affected_events = int(counts["events"])
        affected_content = int(counts["content_records"])
        has_legacy_events = conn.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'session_events'"
        ).fetchone() is not None
        if has_legacy_events:
            legacy_counts_query = f"""
                SELECT COUNT(*)
                FROM session_events legacy
                WHERE legacy.project_id = ? AND legacy.payload_json <> 'null'
                  AND EXISTS (
                      SELECT 1 FROM capture_events e
                      WHERE e.project_id = legacy.project_id
                        AND e.source_id = 'legacy-session-events'
                        AND e.idempotency_key = 'legacy-session-event:' || legacy.id
                        AND {predicate}
                  )
                """  # nosec B608 - predicate comes from the closed scope set.
            affected_content += int(conn.execute(
                legacy_counts_query,
                (project_id, *predicate_values),
            ).fetchone()[0])
        affected_payloads = int(counts["payloads"])
        state_fence = int(counts["state_fence"])
        if existing_rows and affected_content == 0 and affected_payloads == 0:
            existing = max(existing_rows, key=lambda row: int(row["id"]))
            conn.commit()
            checkpoint = _wal_checkpoint(conn)
            compaction_completed = False
            if secure_compact:
                conn.execute("PRAGMA secure_delete = ON")
                conn.execute("VACUUM")
                checkpoint = _wal_checkpoint(conn)
                compaction_completed = True
            return _deletion_result(
                existing,
                wal_checkpoint=checkpoint,
                idempotent_replay=True,
                compaction_completed=compaction_completed,
            )
        confirmation_claims = {
            "schema_version": "rta-smriti.capture-deletion-confirmation/v1",
            "project_id": project_id,
            "scope": selected_scope,
            "scope_token_sha256": token_digest,
            "reason_class": selected_reason,
            "actor_id": selected_actor,
            "policy_digest": selected_digest,
            "affected_events": affected_events,
            "affected_content_records": affected_content,
            "affected_payloads": affected_payloads,
            "state_fence": state_fence,
        }
        if not confirm:
            expires_at = (
                (
                    datetime.now(UTC)
                    + timedelta(seconds=_DELETION_CONFIRMATION_TTL_SECONDS)
                )
                .replace(microsecond=0)
                .isoformat()
            )
            conn.commit()
            return {
                "operation": "preview",
                "scope": selected_scope,
                "scope_token_sha256": token_digest,
                "affected_events": affected_events,
                "affected_content_records": affected_content,
                "affected_payloads": affected_payloads,
                "confirmation_token": _deletion_confirmation_token(
                    {
                        **confirmation_claims,
                        "expires_at": expires_at,
                    },
                    confirmation_key=confirmation_key,
                ),
                "confirmation_expires_at": expires_at,
                "physical_media_erasure_guaranteed": False,
            }
        _verify_deletion_confirmation(
            confirmation_token,
            confirmation_claims,
            confirmation_key=confirmation_key,
        )
        deleted_at = db.now_iso()
        content_delete_query = f"""
            UPDATE capture_event_content
            SET content_json = NULL, deleted_at = ?, deletion_reason = ?
            WHERE deleted_at IS NULL AND content_json IS NOT NULL
              AND event_row_id IN (
                  SELECT e.id FROM capture_events e
                  WHERE e.project_id = ? AND {predicate}
              )
            """  # nosec B608
        conn.execute(
            content_delete_query,
            (deleted_at, selected_reason, project_id, *predicate_values),
        )
        if has_legacy_events:
            legacy_delete_query = f"""
                UPDATE session_events SET payload_json = 'null'
                WHERE project_id = ? AND payload_json <> 'null'
                  AND EXISTS (
                      SELECT 1 FROM capture_events e
                      WHERE e.project_id = session_events.project_id
                        AND e.source_id = 'legacy-session-events'
                        AND e.idempotency_key = 'legacy-session-event:' || session_events.id
                        AND {predicate}
                  )
                """  # nosec B608 - predicate comes from the closed scope set.
            conn.execute(
                legacy_delete_query,
                (project_id, *predicate_values),
            )
        # _deletion_scope selects the SQL fragment from a closed internal set.
        delete_query = f"""
            UPDATE capture_payloads
            SET payload_blob = NULL, deleted_at = ?, deletion_reason = ?
            WHERE deleted_at IS NULL AND payload_blob IS NOT NULL
              AND event_row_id IN (
                  SELECT e.id FROM capture_events e
                  WHERE e.project_id = ? AND {predicate}
              )
            """  # nosec B608
        conn.execute(
            delete_query,
            (deleted_at, selected_reason, project_id, *predicate_values),
        )
        erasure = {
            "journal_content": "logically-deleted-from-queryable-state",
            "event_integrity_metadata": "retained",
            "payload_material": "removed",
            "database_compaction": (
                "best-effort-requested" if secure_compact else "not-requested"
            ),
            "physical_media_erasure_guaranteed": False,
            "storage_device_copies_addressed": False,
            "external_backups_addressed": False,
        }
        verification = {
            "schema_version": "rta-smriti.capture-deletion/v1",
            "scope_token_sha256": token_digest,
            "affected_content_records": affected_content,
            "state_fence": state_fence,
            "journal_rewritten": False,
            "erasure": erasure,
        }
        verification_json = canonical_json(verification)
        tombstone_values = {
            "project_id": project_id,
            "scope": selected_scope,
            "scope_token": token_digest,
            "reason_class": selected_reason,
            "actor_type": "operator",
            "actor_id": selected_actor,
            "policy_digest": selected_digest,
            "affected_events": affected_events,
            "affected_payloads": affected_payloads,
            "verification_json": verification_json,
            "created_at": deleted_at,
        }
        tombstone_id = _digest_text(canonical_json(tombstone_values))
        conn.execute(
            """
            INSERT INTO capture_tombstones(
                project_id, tombstone_id, scope, scope_token, reason_class,
                actor_type, actor_id, policy_digest, affected_events,
                affected_payloads, verification_json, created_at
            ) VALUES (?, ?, ?, ?, ?, 'operator', ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                tombstone_id,
                selected_scope,
                token_digest,
                selected_reason,
                selected_actor,
                selected_digest,
                affected_events,
                affected_payloads,
                verification_json,
                deleted_at,
            ),
        )
        created = conn.execute(
            "SELECT * FROM capture_tombstones WHERE project_id = ? AND tombstone_id = ?",
            (project_id, tombstone_id),
        ).fetchone()
        conn.commit()
        checkpoint = _wal_checkpoint(conn)
        if secure_compact:
            conn.execute("PRAGMA secure_delete = ON")
            conn.execute("VACUUM")
            checkpoint = _wal_checkpoint(conn)
        return _deletion_result(
            created,
            wal_checkpoint=checkpoint,
            idempotent_replay=False,
            compaction_completed=secure_compact,
        )
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def _verified_capture_page(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    after_sequence: int,
    limit: int,
    privacy_rank: int,
    max_bytes: int,
    operation: str,
) -> tuple[
    list[sqlite3.Row],
    list[tuple[dict[str, Any], dict[str, Any], str]],
    int,
    bool,
    str | None,
]:
    """Verify an anchor and every following chain link before privacy projection."""

    if operation not in {"export", "replay"}:
        raise ValueError("unsupported capture verification operation")

    previous_hash = None
    expected_sequence = 1
    scanned_through = 0
    if after_sequence:
        anchor = conn.execute(
            """
            SELECT e.*, c.content_json, c.content_sha256,
                   c.deleted_at AS content_deleted_at,
                   c.expires_at AS content_expires_at
            FROM capture_events e
            LEFT JOIN capture_event_content c ON c.event_row_id = e.id
            WHERE e.project_id = ? AND e.project_sequence <= ?
            ORDER BY e.project_sequence DESC LIMIT 1
            """,
            (project_id, after_sequence),
        ).fetchone()
        if anchor is not None:
            anchor_sequence = int(anchor["project_sequence"])
            predecessor = conn.execute(
                """
                SELECT event_hash FROM capture_events
                WHERE project_id = ? AND project_sequence = ?
                """,
                (project_id, anchor_sequence - 1),
            ).fetchone()
            anchor_previous_hash = (
                None if predecessor is None else str(predecessor["event_hash"])
            )
            _verify_event(
                anchor,
                sequence=anchor_sequence,
                previous_hash=anchor_previous_hash,
            )
            previous_hash = str(anchor["event_hash"])
            expected_sequence = anchor_sequence + 1
            scanned_through = anchor_sequence

    cursor = conn.execute(
        """
        SELECT e.*, c.content_json, c.content_sha256,
               c.deleted_at AS content_deleted_at,
               c.expires_at AS content_expires_at
        FROM capture_events e
        LEFT JOIN capture_event_content c ON c.event_row_id = e.id
        WHERE e.project_id = ? AND e.project_sequence > ?
        ORDER BY e.project_sequence
        """,
        (project_id, after_sequence),
    )
    rows: list[sqlite3.Row] = []
    verified_content: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    consumed = 0
    exhausted = False
    truncated_by = None
    while len(rows) < limit + 1:
        row = cursor.fetchone()
        if row is None:
            exhausted = True
            break
        estimate = (
            len(str(row["attributes_json"]).encode("utf-8"))
            + len(str(row["content_json"] or "").encode("utf-8"))
            + 1_024
        )
        if consumed + estimate > max_bytes:
            if scanned_through <= after_sequence:
                raise ValueError(
                    f"one capture {operation} event exceeds the verification byte budget"
                )
            truncated_by = "byte-budget"
            break
        actual_sequence = int(row["project_sequence"])
        content = _verify_event(
            row,
            sequence=expected_sequence,
            previous_hash=previous_hash,
        )
        expected_sequence = actual_sequence + 1
        previous_hash = str(row["event_hash"])
        scanned_through = actual_sequence
        consumed += estimate
        row_privacy_rank = CAPTURE_PRIVACY_CLASSES.index(str(row["privacy_class"]))
        if row_privacy_rank <= privacy_rank:
            rows.append(row)
            verified_content.append(content)
    if len(rows) > limit:
        truncated_by = truncated_by or "row-limit"
    return rows, verified_content, scanned_through, exhausted, truncated_by


def _privacy_project_capture_event(
    event: dict[str, Any], privacy_ceiling: str
) -> dict[str, Any]:
    """Remove local integrity and repository correlation fields from public views."""

    if privacy_ceiling != "public":
        return event
    hidden_fields = {
        "dirty_digest",
        "event_hash",
        "normalized_sha256",
        "policy_digest",
        "previous_event_hash",
        "repository_commit",
        "repository_ref",
        "source_cursor",
    }
    return {key: value for key, value in event.items() if key not in hidden_fields}


def _public_capture_anchor(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    public_cursor: int,
) -> int:
    """Translate a visible ordinal without exposing hidden journal positions."""

    if public_cursor == 0:
        return 0
    visible_count = int(
        conn.execute(
            """
            SELECT COUNT(*)
            FROM capture_events
            WHERE project_id = ? AND privacy_class = 'public'
            """,
            (project_id,),
        ).fetchone()[0]
    )
    if public_cursor > visible_count:
        raise ValueError("public capture cursor is outside the visible stream")
    row = conn.execute(
        """
        SELECT project_sequence
        FROM capture_events
        WHERE project_id = ? AND privacy_class = 'public'
        ORDER BY project_sequence
        LIMIT 1 OFFSET ?
        """,
        (project_id, public_cursor - 1),
    ).fetchone()
    if row is None:
        raise ValueError("public capture cursor is outside the visible stream")
    return int(row["project_sequence"])


def _verified_public_capture_page(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    after_sequence: int,
    limit: int,
    max_bytes: int,
    operation: str,
) -> tuple[
    list[sqlite3.Row],
    list[tuple[dict[str, Any], dict[str, Any], str]],
    int,
    bool,
    str | None,
]:
    """Verify visible events and their immediate journal predecessor links."""

    if operation not in {"export", "replay"}:
        raise ValueError("unsupported capture verification operation")
    cursor = conn.execute(
        """
        SELECT e.*, c.content_json, c.content_sha256,
               c.deleted_at AS content_deleted_at,
               c.expires_at AS content_expires_at,
               predecessor.event_hash AS predecessor_event_hash
        FROM capture_events e
        LEFT JOIN capture_event_content c ON c.event_row_id = e.id
        LEFT JOIN capture_events predecessor
          ON predecessor.project_id = e.project_id
         AND predecessor.project_sequence = e.project_sequence - 1
        WHERE e.project_id = ? AND e.privacy_class = 'public'
          AND e.project_sequence > ?
        ORDER BY e.project_sequence
        """,
        (project_id, after_sequence),
    )
    rows: list[sqlite3.Row] = []
    verified_content: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    consumed = 0
    exhausted = False
    truncated_by = None
    scanned_through = after_sequence
    while len(rows) < limit + 1:
        row = cursor.fetchone()
        if row is None:
            exhausted = True
            break
        estimate = (
            len(str(row["attributes_json"]).encode("utf-8"))
            + len(str(row["content_json"] or "").encode("utf-8"))
            + 1_024
        )
        if consumed + estimate > max_bytes:
            if not rows:
                raise ValueError(
                    f"one capture {operation} event exceeds the verification byte budget"
                )
            truncated_by = "byte-budget"
            break
        actual_sequence = int(row["project_sequence"])
        verified_content.append(
            _verify_event(
                row,
                sequence=actual_sequence,
                previous_hash=row["predecessor_event_hash"],
            )
        )
        rows.append(row)
        consumed += estimate
        scanned_through = actual_sequence
    if len(rows) > limit:
        truncated_by = truncated_by or "row-limit"
    return rows, verified_content, scanned_through, exhausted, truncated_by


def export_capture_events(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    after_sequence: int = 0,
    limit: int = 100,
    privacy_ceiling: str = "internal",
    max_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Return one bounded, tombstone-aware, privacy-verified capture page."""

    if type(after_sequence) is not int or after_sequence < 0:
        raise ValueError("after_sequence must be a non-negative integer")
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("capture export limit must be between 1 and 500")
    if type(max_bytes) is not int or not 1_024 <= max_bytes <= 16_000_000:
        raise ValueError("capture export max_bytes must be between 1024 and 16000000")
    selected_privacy = _required_text(
        "privacy_ceiling",
        privacy_ceiling,
        maximum=32,
    ).lower()
    if selected_privacy not in CAPTURE_PRIVACY_CLASSES:
        raise ValueError("unsupported capture export privacy ceiling")
    privacy_rank = CAPTURE_PRIVACY_CLASSES.index(selected_privacy)
    db.init_schema(conn)
    try:
        _begin(conn)
        project_row = _project_for_write(conn, project=project, active_root=active_root)
        project_id = int(project_row["id"])
        journal_after_sequence = (
            _public_capture_anchor(
                conn,
                project_id=project_id,
                public_cursor=after_sequence,
            )
            if selected_privacy == "public"
            else after_sequence
        )
        page_reader = (
            _verified_public_capture_page
            if selected_privacy == "public"
            else _verified_capture_page
        )
        page_options = {
            "conn": conn,
            "project_id": project_id,
            "after_sequence": journal_after_sequence,
            "limit": limit,
            "max_bytes": max_bytes,
            "operation": "export",
        }
        if selected_privacy != "public":
            page_options["privacy_rank"] = privacy_rank
        (
            rows,
            verified_content,
            scanned_through,
            exhausted,
            truncated_by,
        ) = page_reader(**page_options)
        page = rows[:limit]
        page_content = verified_content[:limit]
        token_groups = {
            "event-content": {_digest_text(str(row["event_id"])) for row in page},
            "session-content": {
                _digest_text(str(row["external_session_id"])) for row in page
            },
            "source-content": {_digest_text(str(row["source_id"])) for row in page},
            "project-content": {_digest_text(project), _digest_text("*")},
        }
        tombstones = []
        for scope_name, tokens in token_groups.items():
            if not tokens:
                continue
            placeholders = ",".join("?" for _ in tokens)
            # Interpolation contains generated parameter placeholders only.
            tombstone_query = f"""
                SELECT * FROM capture_tombstones
                WHERE project_id = ? AND scope = ?
                  AND scope_token IN ({placeholders})
                """  # nosec B608
            tombstones.extend(
                conn.execute(
                    tombstone_query,
                    (project_id, scope_name, *sorted(tokens)),
                ).fetchall()
            )
        conn.commit()
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise

    tombstone_fences = _tombstone_fences(tombstones)
    project_tokens = {_digest_text(project), _digest_text("*")}
    events = []
    for public_offset, (row, content) in enumerate(
        zip(page, page_content, strict=True),
        start=1,
    ):
        attributes, flags, stored_content_state = content
        deleted = _content_deleted_at_sequence(
            row,
            tombstone_fences,
            project_tokens=project_tokens,
        )
        events.append(
            _privacy_project_capture_event({
                "project_sequence": (
                    after_sequence + public_offset
                    if selected_privacy == "public"
                    else int(row["project_sequence"])
                ),
                "event_id": str(row["event_id"]),
                "event_name": str(row["event_name"]),
                "source_id": str(row["source_id"]),
                "external_session_id": str(row["external_session_id"]),
                "source_cursor": str(row["source_cursor"]),
                "occurred_at": row["occurred_at"],
                "observed_at": str(row["observed_at"]),
                "recorded_at": str(row["recorded_at"]),
                "trace_id": row["trace_id"],
                "span_id": row["span_id"],
                "parent_span_id": row["parent_span_id"],
                "causation_event_id": row["causation_event_id"],
                "correlation_id": row["correlation_id"],
                "privacy_class": str(row["privacy_class"]),
                "verification_status": str(row["verification_status"]),
                "policy_digest": str(row["policy_digest"]),
                "normalized_sha256": str(row["normalized_sha256"]),
                "previous_event_hash": row["previous_event_hash"],
                "event_hash": str(row["event_hash"]),
                "flags": flags,
                "gap_state": str(row["gap_state"]),
                "attributes": {} if deleted else attributes,
                "content_state": "logically-deleted"
                if deleted
                else stored_content_state,
                "trust": (
                    "integrity-metadata-only"
                    if deleted or stored_content_state in {"expired", "metadata-only"}
                    else "untrusted-observation"
                ),
            }, selected_privacy)
        )
    selected_rows = list(page)
    selected_events = events
    while True:
        sanitized_events, export_redactions = redact_sensitive_data(
            selected_events,
            max_chars=16_000_000,
            max_items=100_000,
            max_depth=12,
        )
        stored_redactions = sum(int(row["redaction_count"]) for row in selected_rows)
        next_cursor = (
            after_sequence + len(selected_rows)
            if selected_privacy == "public"
            else (
                int(selected_rows[-1]["project_sequence"])
                if selected_rows
                else max(after_sequence, scanned_through)
            )
        )
        complete = exhausted and len(selected_rows) == len(rows)
        result = {
            "schema_version": "rta-smriti.capture-export/v1",
            "project_fingerprint": _digest_text(project),
            "privacy_ceiling": selected_privacy,
            "after_sequence": after_sequence,
            "next_cursor": next_cursor,
            "complete": complete,
            "truncated_by": None if complete else (truncated_by or "byte-budget"),
            "events": sanitized_events,
            "redaction_count": stored_redactions + export_redactions,
            "payloads_included": False,
            "journal_verified": True,
            "journal_verification_scope": (
                "privacy-projected-visible-events-with-predecessor-links"
                if selected_privacy == "public"
                else "page-with-anchor"
            ),
            "redaction_verified": False,
        }
        if selected_privacy != "public":
            result["verified_through_sequence"] = scanned_through
        serialized_bytes = len(
            json.dumps(result, ensure_ascii=True, sort_keys=True).encode("utf-8")
        )
        if serialized_bytes <= max_bytes:
            result["redaction_verified"] = not find_sensitive_text(
                canonical_json(result),
                max_chars=max_bytes,
            )
            if not result["redaction_verified"]:
                raise ValueError("capture export failed its final privacy verification")
            return result
        if len(selected_events) <= 1:
            raise ValueError("one capture export event exceeds the total byte budget")
        selected_events = selected_events[:-1]
        selected_rows = selected_rows[:-1]
        truncated_by = "byte-budget"


def read_capture_replay(
    conn: sqlite3.Connection,
    *,
    project: str,
    mode: str = "chronological",
    after_sequence: int = 0,
    limit: int = 100,
    privacy_ceiling: str = "internal",
    max_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Read one replay page from a single SQLite snapshot."""

    if conn.in_transaction:
        raise RuntimeError("capture replay requires an independent read transaction")
    conn.execute("BEGIN")
    try:
        result = _read_capture_replay_snapshot(
            conn,
            project=project,
            mode=mode,
            after_sequence=after_sequence,
            limit=limit,
            privacy_ceiling=privacy_ceiling,
            max_bytes=max_bytes,
        )
        conn.commit()
        return result
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def _read_capture_replay_snapshot(
    conn: sqlite3.Connection,
    *,
    project: str,
    mode: str = "chronological",
    after_sequence: int = 0,
    limit: int = 100,
    privacy_ceiling: str = "internal",
    max_bytes: int = 2_000_000,
) -> dict[str, Any]:
    """Assemble a bounded replay while the caller holds one read snapshot."""

    selected_project = _required_text("project", project, maximum=128)
    selected_mode = _required_text("mode", mode, maximum=32).lower()
    if selected_mode not in {"chronological", "causal"}:
        raise ValueError("capture replay mode must be chronological or causal")
    if type(after_sequence) is not int or after_sequence < 0:
        raise ValueError("after_sequence must be a non-negative integer")
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("capture replay limit must be between 1 and 500")
    if type(max_bytes) is not int or not 1_024 <= max_bytes <= 16_000_000:
        raise ValueError("capture replay max_bytes must be between 1024 and 16000000")
    selected_privacy = _required_text(
        "privacy_ceiling",
        privacy_ceiling,
        maximum=32,
    ).lower()
    if selected_privacy not in CAPTURE_PRIVACY_CLASSES:
        raise ValueError("unsupported capture replay privacy ceiling")
    project_row = conn.execute(
        "SELECT id FROM projects WHERE name = ?",
        (selected_project,),
    ).fetchone()
    if project_row is None:
        raise ValueError(f"unknown project: {selected_project}")
    project_id = int(project_row["id"])
    privacy_rank = CAPTURE_PRIVACY_CLASSES.index(selected_privacy)
    journal_after_sequence = (
        _public_capture_anchor(
            conn,
            project_id=project_id,
            public_cursor=after_sequence,
        )
        if selected_privacy == "public"
        else after_sequence
    )
    page_reader = (
        _verified_public_capture_page
        if selected_privacy == "public"
        else _verified_capture_page
    )
    page_options = {
        "conn": conn,
        "project_id": project_id,
        "after_sequence": journal_after_sequence,
        "limit": limit,
        "max_bytes": max_bytes,
        "operation": "replay",
    }
    if selected_privacy != "public":
        page_options["privacy_rank"] = privacy_rank
    (
        rows,
        verified_content,
        scanned_through,
        exhausted,
        truncated_by,
    ) = page_reader(**page_options)
    page = rows[:limit]
    page_content = verified_content[:limit]

    token_groups = {
        "event-content": {_digest_text(str(row["event_id"])) for row in page},
        "session-content": {
            _digest_text(str(row["external_session_id"])) for row in page
        },
        "source-content": {_digest_text(str(row["source_id"])) for row in page},
        "project-content": {_digest_text(selected_project), _digest_text("*")},
    }
    tombstones = []
    for scope, tokens in token_groups.items():
        if not tokens:
            continue
        placeholders = ",".join("?" for _ in tokens)
        query = f"""
            SELECT * FROM capture_tombstones
            WHERE project_id = ? AND scope = ?
              AND scope_token IN ({placeholders})
            """  # nosec B608 - placeholders are generated, never caller-controlled.
        tombstones.extend(
            conn.execute(
                query,
                (project_id, scope, *sorted(tokens)),
            )
        )
    tombstone_fences = _tombstone_fences(tombstones)

    events = []
    stored_redactions = 0
    for public_offset, (row, content) in enumerate(
        zip(page, page_content, strict=True),
        start=1,
    ):
        attributes, flags, stored_content_state = content
        deleted = _content_deleted_at_sequence(
            row,
            tombstone_fences,
            project_tokens=token_groups["project-content"],
        )
        stored_redactions += int(row["redaction_count"])
        events.append(
            _privacy_project_capture_event({
                "project_sequence": (
                    after_sequence + public_offset
                    if selected_privacy == "public"
                    else int(row["project_sequence"])
                ),
                "event_id": str(row["event_id"]),
                "external_event_id": row["external_event_id"],
                "event_name": str(row["event_name"]),
                "source_id": str(row["source_id"]),
                "external_session_id": str(row["external_session_id"]),
                "source_cursor": str(row["source_cursor"]),
                "occurred_at": row["occurred_at"],
                "observed_at": str(row["observed_at"]),
                "recorded_at": str(row["recorded_at"]),
                "trace_id": row["trace_id"],
                "span_id": row["span_id"],
                "parent_span_id": row["parent_span_id"],
                "causation_event_id": row["causation_event_id"],
                "correlation_id": row["correlation_id"],
                "repository_ref": row["repository_ref"],
                "repository_commit": row["repository_commit"],
                "dirty_digest": row["dirty_digest"],
                "privacy_class": str(row["privacy_class"]),
                "verification_status": str(row["verification_status"]),
                "normalized_sha256": str(row["normalized_sha256"]),
                "event_hash": str(row["event_hash"]),
                "flags": flags,
                "gap_state": str(row["gap_state"]),
                "attributes": {} if deleted else attributes,
                "content_state": "logically-deleted"
                if deleted
                else stored_content_state,
            }, selected_privacy)
        )
    # Deep-redact only the adapter-owned payload surface. Envelope fields are
    # schema-bound and sensitive identifiers are rejected during ingestion;
    # the final whole-page scan below remains a fail-closed backstop.
    replay_item_budget = min(100_000, 10_000 + (limit * 128))
    redacted_attributes, replay_redactions = redact_sensitive_data(
        [event["attributes"] for event in events],
        max_chars=max_bytes,
        max_items=replay_item_budget,
        max_depth=12,
    )
    for event, attributes in zip(events, redacted_attributes, strict=True):
        event["attributes"] = attributes
    if find_sensitive_text(canonical_json(events), max_chars=max_bytes):
        raise ValueError("capture replay failed its final privacy verification")

    event_ids = {event["event_id"] for event in events}
    external_ids = {
        event["external_event_id"]: event["event_id"]
        for event in events
        if event.get("external_event_id")
    }
    span_owners = {
        event["span_id"]: event["event_id"] for event in events if event.get("span_id")
    }
    causal_edges = []
    unresolved_causes = 0
    if selected_mode == "causal":
        for event in events:
            parent = event.get("causation_event_id")
            if parent in external_ids:
                parent = external_ids[parent]
            if parent is None and event.get("parent_span_id"):
                parent = span_owners.get(event["parent_span_id"])
            if parent is None:
                continue
            if parent in event_ids:
                causal_edges.append({"from": parent, "to": event["event_id"]})
            else:
                unresolved_causes += 1

    sessions: dict[tuple[str, str], dict[str, Any]] = {}
    incomplete_spans: set[tuple[str, str, str]] = set()
    gap_events = 0
    for event in events:
        key = (str(event["source_id"]), str(event["external_session_id"]))
        state = sessions.setdefault(key, {"interrupted": False, "active": False})
        name = str(event["event_name"])
        if name in {"session.started.v1", "session.resumed.v1"}:
            state["active"] = True
        elif name == "session.ended.v1":
            state["active"] = False
            state["interrupted"] = False
        elif name == "turn.interrupted.v1":
            state["interrupted"] = True
        elif name == "turn.completed.v1":
            state["interrupted"] = False
        if name == "capture.gap.v1" or event["gap_state"] == "detected":
            gap_events += 1
        span = event.get("span_id")
        if span and name.endswith(".started.v1"):
            incomplete_spans.add((*key, str(span)))
        elif span and name.endswith((".completed.v1", ".failed.v1")):
            incomplete_spans.discard((*key, str(span)))
    interrupted = sorted(key for key, value in sessions.items() if value["interrupted"])
    latest = events[-1] if events else None
    interruption_snapshot = {
        "status": "interrupted"
        if interrupted or incomplete_spans or gap_events
        else "clear",
        "interrupted_sessions": len(interrupted),
        "incomplete_spans": len(incomplete_spans),
        "gap_events": gap_events,
    }
    if selected_privacy != "public":
        interruption_snapshot.update({
            "latest_sequence": None if latest is None else latest["project_sequence"],
            "latest_event_hash": None if latest is None else latest["event_hash"],
        })
    complete = exhausted and len(rows) <= limit
    result = {
        "schema_version": "rta-smriti.capture-replay/v1",
        "project_fingerprint": _digest_text(selected_project),
        "mode": selected_mode,
        "privacy_ceiling": selected_privacy,
        "after_sequence": after_sequence,
        "next_cursor": (
            after_sequence + len(events)
            if selected_privacy == "public"
            else (
                max(after_sequence, scanned_through)
                if latest is None
                else latest["project_sequence"]
            )
        ),
        "complete": complete,
        "truncated_by": None if complete else (truncated_by or "row-limit"),
        "events": events,
        "causal_edges": causal_edges,
        "coverage": {
            "selected_events": len(events),
            "gap_events": gap_events,
            "incomplete_spans": len(incomplete_spans),
            "interrupted_sessions": len(interrupted),
            "redactions": stored_redactions + replay_redactions,
            "journal_verified": True,
            "journal_verification_scope": (
                "privacy-projected-visible-events-with-predecessor-links"
                if selected_privacy == "public"
                else "page-with-anchor"
            ),
        },
        "interruption_snapshot": interruption_snapshot,
        "executes_actions": False,
    }
    if selected_privacy != "public":
        result["unresolved_causes"] = unresolved_causes
        result["coverage"]["verified_through_sequence"] = scanned_through
        result["replay_digest"] = _digest_text(canonical_json(result))
    return result


def _verify_event(
    row: sqlite3.Row, *, sequence: int, previous_hash: str | None
) -> tuple[dict[str, Any], dict[str, Any], str]:
    if int(row["project_sequence"]) != sequence:
        raise ValueError(
            f"capture event sequence gap: expected {sequence}, found {row['project_sequence']}"
        )
    if row["previous_event_hash"] != previous_hash:
        raise ValueError(f"capture event chain mismatch at sequence {sequence}")
    attributes, _flags, content_state = _event_content(row)
    if row["source_id"] == "legacy-session-events" and str(row["event_id"]).startswith(
        "legacy-"
    ):
        legacy_normalized_hash = _digest_text(str(row["attributes_json"]))
        if not hmac.compare_digest(
            str(row["normalized_sha256"]),
            legacy_normalized_hash,
        ):
            raise ValueError(f"capture normalized hash mismatch at sequence {sequence}")
    elif content_state != "expired" or row["content_json"] is not None:
        normalized_attributes = attributes
        if content_state == "expired":
            normalized_attributes = json.loads(str(row["content_json"]))
            if not isinstance(normalized_attributes, dict):
                raise TypeError("capture event content must be an object")
        normalized = {
            "actor_id": row["actor_id"],
            "actor_type": row["actor_type"],
            "attributes": normalized_attributes,
            "causation_event_id": row["causation_event_id"],
            "correlation_id": row["correlation_id"],
            "event_name": row["event_name"],
            "external_event_id": row["external_event_id"],
            "external_session_id": row["external_session_id"],
            "observed_at": row["observed_at"],
            "occurred_at": row["occurred_at"],
            "parent_span_id": row["parent_span_id"],
            "source_cursor": row["source_cursor"],
            "span_id": row["span_id"],
            "trace_id": row["trace_id"],
        }
        if not hmac.compare_digest(
            str(row["normalized_sha256"]),
            _digest_text(canonical_json(normalized)),
        ):
            raise ValueError(f"capture normalized hash mismatch at sequence {sequence}")
    expected_hash = _digest_text(canonical_json(capture_event_envelope(row)))
    if not hmac.compare_digest(str(row["event_hash"]), expected_hash):
        raise ValueError(f"capture event envelope hash mismatch at sequence {sequence}")
    return attributes, _flags, content_state


def verify_journal(
    conn: sqlite3.Connection,
    *,
    project: str,
    max_events: int | None = None,
) -> dict[str, Any]:
    """Verify a complete journal or one explicitly bounded prefix."""

    if max_events is not None and (
        type(max_events) is not int or not 1 <= max_events <= 100_000
    ):
        raise ValueError("max_events must be between 1 and 100000")

    db.init_schema(conn)
    row = conn.execute(
        "SELECT id FROM projects WHERE name = ?",
        (_required_text("project", project, maximum=128),),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown project: {project}")
    previous_hash = None
    count = 0
    expired_content = 0
    query = """
            SELECT e.*, c.content_json, c.content_sha256,
                   c.deleted_at AS content_deleted_at,
                   c.expires_at AS content_expires_at
            FROM capture_events e
            LEFT JOIN capture_event_content c ON c.event_row_id = e.id
            WHERE e.project_id = ? ORDER BY e.project_sequence
            """
    parameters: tuple[Any, ...] = (int(row["id"]),)
    if max_events is not None:
        query += " LIMIT ?"
        parameters += (max_events + 1,)
    events = conn.execute(query, parameters)
    verification_complete = True
    for count, event in enumerate(
        events,
        start=1,
    ):
        if max_events is not None and count > max_events:
            count -= 1
            verification_complete = False
            break
        _verify_event(event, sequence=count, previous_hash=previous_hash)
        if event["content_deleted_at"] is not None:
            expired_content += 1
        previous_hash = str(event["event_hash"])
    return {
        "chain_valid": True,
        "events_verified": count,
        "expired_content_records": expired_content,
        "event_chain_hash": previous_hash,
        "verification_complete": verification_complete,
        "verification_scope": "complete" if verification_complete else "prefix",
        "next_sequence": None if verification_complete else count,
    }


def _session_projection(source_id: str, external_session_id: str) -> dict[str, Any]:
    return {
        "active": False,
        "ended": False,
        "events": 0,
        "external_session_id": external_session_id,
        "gaps": 0,
        "incomplete_spans": [],
        "interrupted": False,
        "latest_checkpoint_sequence": None,
        "source_id": source_id,
        "uncheckpointed_events": 0,
    }


def rebuild_projections(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
) -> dict[str, Any]:
    """Rebuild deterministic operational state from the immutable capture journal."""

    db.init_schema(conn)
    _begin(conn)
    try:
        project_row = _project_for_write(
            conn,
            project=project,
            active_root=active_root,
        )
        project_id = int(project_row["id"])
        previous_hash = None
        sessions: dict[str, dict[str, Any]] = {}
        sources: dict[str, dict[str, Any]] = {}
        causal_links: list[dict[str, str]] = []
        unresolved_causes = 0
        event_count = 0
        for event_count, row in enumerate(
            conn.execute(
                """
                SELECT e.*, c.content_json, c.content_sha256,
                       c.deleted_at AS content_deleted_at,
                       c.expires_at AS content_expires_at
                FROM capture_events e
                LEFT JOIN capture_event_content c ON c.event_row_id = e.id
                WHERE e.project_id = ? ORDER BY e.project_sequence
                """,
                (project_id,),
            ),
            start=1,
        ):
            _verify_event(row, sequence=event_count, previous_hash=previous_hash)
            previous_hash = str(row["event_hash"])
            source_id = str(row["source_id"])
            external_session_id = str(row["external_session_id"])
            session_id = canonical_json([source_id, external_session_id])
            session = sessions.setdefault(
                session_id,
                _session_projection(source_id, external_session_id),
            )
            source = sources.setdefault(
                source_id,
                {
                    "events": 0,
                    "gaps": 0,
                    "last_cursor": None,
                    "last_event_id": None,
                    "late_events": 0,
                    "time_skew_events": 0,
                },
            )
            sequence = int(row["project_sequence"])
            event_name = str(row["event_name"])
            session["events"] += 1
            session["uncheckpointed_events"] += 1
            source["events"] += 1
            source["last_cursor"] = str(row["source_cursor"])
            source["last_event_id"] = str(row["event_id"])
            flags = json.loads(str(row["attributes_json"])).get(_SYSTEM_ATTRIBUTE, {})
            source["late_events"] += int(bool(flags.get("late")))
            source["time_skew_events"] += int(bool(flags.get("time_skew")))
            if event_name in {"session.started.v1", "session.resumed.v1"}:
                session["active"] = True
                session["ended"] = False
            elif event_name == "session.ended.v1":
                session["active"] = False
                session["ended"] = True
                session["interrupted"] = False
            elif event_name == "turn.interrupted.v1":
                session["interrupted"] = True
            elif event_name == "turn.completed.v1":
                session["interrupted"] = False
            if event_name == "checkpoint.created.v1":
                session["latest_checkpoint_sequence"] = sequence
                session["uncheckpointed_events"] = 0
            if event_name == "capture.gap.v1" or row["gap_state"] == "detected":
                session["gaps"] += 1
                source["gaps"] += 1
            if event_name.endswith(".started.v1") and row["span_id"]:
                span = str(row["span_id"])
                if span not in session["incomplete_spans"]:
                    session["incomplete_spans"].append(span)
            if event_name.endswith((".completed.v1", ".failed.v1")) and row["span_id"]:
                span = str(row["span_id"])
                if span in session["incomplete_spans"]:
                    session["incomplete_spans"].remove(span)
            if row["causation_event_id"]:
                selected_cause = str(row["causation_event_id"])
                direct = conn.execute(
                    """
                    SELECT event_id FROM capture_events
                    WHERE project_id = ? AND event_id = ? AND project_sequence < ?
                    """,
                    (project_id, selected_cause, sequence),
                ).fetchone()
                cause = str(direct["event_id"]) if direct is not None else None
                if cause is None:
                    candidates = conn.execute(
                        """
                        SELECT event_id FROM capture_events
                        WHERE project_id = ? AND source_id = ?
                          AND external_session_id = ? AND external_event_id = ?
                          AND project_sequence < ?
                        ORDER BY project_sequence LIMIT 2
                        """,
                        (
                            project_id,
                            source_id,
                            external_session_id,
                            selected_cause,
                            sequence,
                        ),
                    ).fetchall()
                    if len(candidates) == 1:
                        cause = str(candidates[0]["event_id"])
                if cause is None:
                    unresolved_causes += 1
                else:
                    causal_links.append(
                        {
                            "event_id": str(row["event_id"]),
                            "caused_by": cause,
                        }
                    )

        for session in sessions.values():
            session["incomplete_spans"].sort()
        projection = {
            "causal_links": causal_links,
            "event_chain_hash": previous_hash,
            "events": event_count,
            "sessions": {key: sessions[key] for key in sorted(sessions)},
            "sources": {key: sources[key] for key in sorted(sources)},
            "unresolved_causes": unresolved_causes,
        }
        projection_digest = _digest_text(canonical_json(projection))
        conn.execute(
            """
            INSERT INTO capture_projections(
                project_id, projection_name, schema_version, last_event_sequence,
                event_chain_hash, projection_digest, rebuilt_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, projection_name) DO UPDATE SET
                schema_version = excluded.schema_version,
                last_event_sequence = excluded.last_event_sequence,
                event_chain_hash = excluded.event_chain_hash,
                projection_digest = excluded.projection_digest,
                rebuilt_at = excluded.rebuilt_at
            """,
            (
                project_id,
                _PROJECTION_NAME,
                _PROJECTION_SCHEMA_VERSION,
                event_count,
                previous_hash,
                projection_digest,
                db.now_iso(),
            ),
        )
        conn.commit()
        return {**projection, "projection_digest": projection_digest}
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise
