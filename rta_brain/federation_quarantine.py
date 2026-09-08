"""Explicit, append-only operator dispositions for quarantined federation events."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .federation_crypto import FederationIdentity
from .federation_governance import (
    FederationAuthorizationError,
    authorize_operation,
    open_scope_key_for_epoch,
    validate_and_accept_event,
)
from .federation_types import FederationEventEnvelope, canonical_json_bytes


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _require_admin(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    actor: FederationIdentity,
) -> None:
    authority = authorize_operation(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=None,
        peer_id=actor.identity_id,
        operation="admin",
    )
    if not authority["allowed"]:
        raise FederationAuthorizationError(
            "quarantine disposition requires an active administrator"
        )


def _record(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    quarantine_id: int,
    action: str,
    actor: FederationIdentity,
    reason: str,
) -> dict[str, Any]:
    selected_reason = str(reason).strip()
    if action not in {"promoted", "rejected"}:
        raise ValueError("quarantine disposition is invalid")
    if not 1 <= len(selected_reason) <= 512 or "\0" in selected_reason:
        raise ValueError("quarantine reason must be a bounded string")
    body = {
        "action": action,
        "actor_peer_id": actor.identity_id,
        "nonce": os.urandom(16).hex(),
        "project_id": int(project_id),
        "quarantine_id": int(quarantine_id),
        "reason": selected_reason,
    }
    disposition_id = hashlib.sha256(
        b"rta-smriti-quarantine-disposition-v1\0" + canonical_json_bytes(body)
    ).hexdigest()
    recorded_at = _now_iso()
    conn.execute(
        "INSERT INTO federation_quarantine_receipts(project_id, quarantine_id, "
        "disposition_id, action, actor_peer_id, reason, recorded_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            project_id,
            quarantine_id,
            disposition_id,
            action,
            actor.identity_id,
            selected_reason,
            recorded_at,
        ),
    )
    return {
        "state": action,
        "disposition_id": disposition_id,
        "quarantine_id": quarantine_id,
        "recorded_at": recorded_at,
    }


def reject_quarantined_event(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    quarantine_id: int,
    actor: FederationIdentity,
    reason: str,
    commit: bool = True,
) -> dict[str, Any]:
    row = conn.execute(
        "SELECT space_id FROM federation_quarantine WHERE project_id = ? AND id = ?",
        (project_id, int(quarantine_id)),
    ).fetchone()
    if row is None or row["space_id"] is None:
        raise ValueError("quarantine record does not exist or has no federation space")
    _require_admin(
        conn,
        project_id=project_id,
        space_id=str(row["space_id"]),
        actor=actor,
    )
    if not commit:
        return _record(
            conn,
            project_id=project_id,
            quarantine_id=int(quarantine_id),
            action="rejected",
            actor=actor,
            reason=reason,
        )
    savepoint = "federation_quarantine_reject"
    conn.execute(f"SAVEPOINT {savepoint}")
    try:
        result = _record(
            conn,
            project_id=project_id,
            quarantine_id=int(quarantine_id),
            action="rejected",
            actor=actor,
            reason=reason,
        )
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        return result
    except Exception:
        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise


def promote_quarantined_event(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    quarantine_id: int,
    actor: FederationIdentity,
    envelope: FederationEventEnvelope,
    author_signing_public_key: bytes,
    scope_key: bytes,
    reason: str,
    commit: bool = True,
) -> dict[str, Any]:
    row = conn.execute(
        "SELECT space_id, claimed_event_id, envelope_sha256 FROM federation_quarantine "
        "WHERE project_id = ? AND id = ?",
        (project_id, int(quarantine_id)),
    ).fetchone()
    if row is None:
        raise ValueError("quarantine record does not exist")
    if (
        str(row["space_id"]) != envelope.space_id
        or str(row["claimed_event_id"]) != envelope.event_id
        or str(row["envelope_sha256"]) != envelope.envelope_sha256
    ):
        raise ValueError("quarantine record does not match the supplied envelope")
    _require_admin(
        conn,
        project_id=project_id,
        space_id=envelope.space_id,
        actor=actor,
    )
    enrolled_author = conn.execute(
        "SELECT signing_public_key FROM federation_peers "
        "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
        (project_id, envelope.space_id, envelope.author_peer_id),
    ).fetchone()
    if (
        enrolled_author is None
        or bytes(enrolled_author["signing_public_key"]) != author_signing_public_key
    ):
        raise FederationAuthorizationError(
            "quarantined event author key does not match the enrolled peer"
        )
    savepoint = "federation_quarantine_promote"
    if commit:
        conn.execute(f"SAVEPOINT {savepoint}")
    try:
        validation = validate_and_accept_event(
            conn,
            project_id=project_id,
            envelope=envelope,
            author_signing_public_key=author_signing_public_key,
            scope_key=scope_key,
            allow_quarantine_recheck=True,
            commit=False,
        )
        if validation["state"] != "accepted":
            raise FederationAuthorizationError(
                "quarantined event is not ready for promotion"
            )
        receipt = _record(
            conn,
            project_id=project_id,
            quarantine_id=int(quarantine_id),
            action="promoted",
            actor=actor,
            reason=reason,
        )
        if commit:
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        return {**receipt, "event_id": envelope.event_id}
    except Exception:
        if commit:
            conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise


def promote_quarantined_event_by_id(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    quarantine_id: int,
    actor: FederationIdentity,
    reason: str,
    commit: bool = True,
) -> dict[str, Any]:
    """Revalidate one stored quarantined envelope using governed local key material."""

    row = conn.execute(
        "SELECT q.space_id, q.claimed_event_id, e.* "
        "FROM federation_quarantine q "
        "JOIN federation_events e ON e.project_id = q.project_id "
        "AND e.space_id = q.space_id AND e.event_id = q.claimed_event_id "
        "WHERE q.project_id = ? AND q.id = ?",
        (project_id, int(quarantine_id)),
    ).fetchone()
    if row is None:
        raise ValueError("quarantine record has no stored federation event")
    envelope = FederationEventEnvelope(
        space_id=str(row["space_id"]),
        scope_id=str(row["scope_id"]),
        epoch=int(row["epoch"]),
        event_id=str(row["event_id"]),
        author_peer_id=str(row["author_peer_id"]),
        author_sequence=int(row["author_sequence"]),
        capability_event_id=str(row["capability_event_id"]),
        parents=tuple(json.loads(str(row["parents_json"]))),
        nonce=bytes(row["nonce"]),
        ciphertext=bytes(row["ciphertext"]),
        ciphertext_sha256=str(row["ciphertext_sha256"]),
        signature=bytes(row["signature"]),
        received_at=str(row["received_at"]),
    )
    author = conn.execute(
        "SELECT signing_public_key FROM federation_peers "
        "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
        (project_id, envelope.space_id, envelope.author_peer_id),
    ).fetchone()
    if author is None:
        raise FederationAuthorizationError("quarantined event author is unknown")
    scope_key = open_scope_key_for_epoch(
        conn,
        project_id=project_id,
        space_id=envelope.space_id,
        scope_id=envelope.scope_id,
        epoch=envelope.epoch,
        recipient=actor,
    )
    return promote_quarantined_event(
        conn,
        project_id=project_id,
        quarantine_id=quarantine_id,
        actor=actor,
        envelope=envelope,
        author_signing_public_key=bytes(author["signing_public_key"]),
        scope_key=scope_key,
        reason=reason,
        commit=commit,
    )
