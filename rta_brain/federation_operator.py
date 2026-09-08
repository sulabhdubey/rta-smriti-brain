"""Preview-bound operator contract for governed federation mutations."""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from .federation_crypto import (
    FederationIdentity,
    PublicFederationIdentity,
    generate_scope_key,
)
from .federation_governance import (
    ALL_CAPABILITIES,
    add_public_peer,
    create_scope,
    create_space,
    federation_status,
    grant_capabilities,
    resolve_capability_conflict,
    revoke_capabilities,
    rotate_scope_key,
)
from .federation_quarantine import (
    promote_quarantined_event_by_id,
    reject_quarantined_event,
)
from .federation_types import canonical_json_bytes

_ACTIONS = frozenset(
    {
        "space-create",
        "scope-create",
        "peer-add",
        "capability-grant",
        "capability-revoke",
        "capability-resolve",
        "scope-rotate",
        "quarantine-promote",
        "quarantine-reject",
    }
)
_HEX = frozenset("0123456789abcdef")
_STATE_DIGEST_TABLES = (
    "federation_spaces",
    "federation_scopes",
    "federation_peers",
    "federation_capability_events",
    "federation_scope_epochs",
    "federation_key_envelopes",
    "federation_events",
    "federation_event_validation",
    "federation_sync_cursors",
    "federation_quarantine",
    "federation_quarantine_receipts",
    "federation_projections",
    "federation_invitation_receipts",
    "federation_operation_receipts",
)


class FederationPlanConflict(ValueError):
    """The confirmed request no longer matches its previewed state."""


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _identifier(name: str, value: Any) -> str:
    selected = str(value)
    if len(selected) != 64 or set(selected) - _HEX or set(selected) == {"0"}:
        raise ValueError(f"{name} must be a non-zero lower-case SHA-256 identifier")
    return selected


def _text(name: str, value: Any, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")  # noqa: TRY004 - operator payload validation
    selected = value.strip()
    if not 1 <= len(selected) <= maximum or "\0" in selected:
        raise ValueError(f"{name} must be a bounded non-empty string")
    return selected


def _parameters(action: str, raw: Mapping[str, Any]) -> dict[str, Any]:
    if action not in _ACTIONS:
        raise ValueError("federation operator action is unsupported")
    if not isinstance(raw, Mapping):
        raise TypeError("federation operator parameters must be a mapping")
    if action == "space-create":
        if raw:
            raise ValueError("federation operator parameters contain unexpected fields")
        return {}
    if action in {"quarantine-promote", "quarantine-reject"}:
        if set(raw) != {"quarantine_id", "reason"}:
            raise ValueError("federation operator parameters contain unexpected fields")
        quarantine_id = int(raw.get("quarantine_id"))
        if quarantine_id < 1:
            raise ValueError("quarantine_id must be positive")
        return {
            "quarantine_id": quarantine_id,
            "reason": _text("reason", raw.get("reason"), 512),
        }
    selected: dict[str, Any] = {
        "space_id": _identifier("space_id", raw.get("space_id"))
    }
    expected = {"space_id"}
    if action == "scope-create":
        kind = _text("kind", raw.get("kind"), 32).casefold()
        if kind not in {"team", "review", "custom"}:
            raise ValueError("scope kind is invalid")
        selected.update(kind=kind, label=_text("label", raw.get("label")))
        expected.update({"kind", "label"})
    elif action == "peer-add":
        selected.update(
            peer_id=_identifier("peer_id", raw.get("peer_id")),
            label=_text("label", raw.get("label")),
        )
        expected.update({"peer_id", "label"})
    elif action in {"capability-grant", "capability-revoke", "capability-resolve"}:
        scope_value = raw.get("scope_id")
        selected.update(
            scope_id=(
                None if scope_value is None else _identifier("scope_id", scope_value)
            ),
            subject_peer_id=_identifier(
                "subject_peer_id", raw.get("subject_peer_id")
            ),
        )
        expected.update({"scope_id", "subject_peer_id"})
        if action != "capability-revoke":
            values = raw.get("capabilities")
            if not isinstance(values, (list, tuple)) or len(values) > len(ALL_CAPABILITIES):
                raise ValueError("capabilities must be a bounded list")
            capabilities = sorted({str(item) for item in values})
            if not capabilities or set(capabilities) - ALL_CAPABILITIES:
                raise ValueError("capabilities contain an unsupported operation")
            selected["capabilities"] = capabilities
            expected.add("capabilities")
    elif action == "scope-rotate":
        selected["scope_id"] = _identifier("scope_id", raw.get("scope_id"))
        expected.add("scope_id")
    if set(raw) != expected:
        raise ValueError("federation operator parameters contain unexpected fields")
    return selected


def _bounded_rows(
    conn: sqlite3.Connection, table: str, project_id: int
) -> list[dict[str, Any]]:
    if table not in _STATE_DIGEST_TABLES:
        raise ValueError("federation state table is not allowlisted")
    rows = list(
        conn.execute(
            f'SELECT * FROM "{table}" WHERE project_id = ? ORDER BY rowid LIMIT 10001',  # nosec B608 - table is allowlisted above
            (project_id,),
        )
    )
    if len(rows) > 10_000:
        raise ValueError("federation state exceeds the operator digest bound")
    normalized = []
    for row in rows:
        item = {}
        for key in row.keys():  # noqa: SIM118 - sqlite3.Row key API
            value = row[key]
            item[key] = (
                hashlib.sha256(bytes(value)).hexdigest()
                if isinstance(value, (bytes, bytearray))
                else value
            )
        normalized.append(item)
    return normalized


def _state_digest(conn: sqlite3.Connection, project_id: int) -> str:
    state = {
        table: _bounded_rows(conn, table, project_id)
        for table in _STATE_DIGEST_TABLES
    }
    return hashlib.sha256(canonical_json_bytes(state, max_bytes=16 * 1024 * 1024)).hexdigest()


def federation_inventory(
    conn: sqlite3.Connection, *, project_id: int, actor_peer_id: str | None = None
) -> dict[str, Any]:
    """Return a bounded, path-free operator view over federation state."""

    status = federation_status(
        conn, project_id=project_id, actor_peer_id=actor_peer_id
    )
    spaces = [
        dict(row)
        for row in conn.execute(
            "SELECT space_id, owner_peer_id, created_at FROM federation_spaces "
            "WHERE project_id = ? ORDER BY space_id LIMIT 101",
            (project_id,),
        )
    ]
    scopes = [
        dict(row)
        for row in conn.execute(
            "SELECT s.space_id, s.scope_id, s.scope_kind, s.label, s.created_at, "
            "COALESCE((SELECT MAX(e.epoch) FROM federation_scope_epochs e "
            "WHERE e.project_id = s.project_id AND e.space_id = s.space_id "
            "AND e.scope_id = s.scope_id), 0) AS current_epoch "
            "FROM federation_scopes s WHERE s.project_id = ? "
            "ORDER BY s.space_id, s.scope_id LIMIT 1001",
            (project_id,),
        )
    ]
    peers = [
        dict(row)
        for row in conn.execute(
            "SELECT space_id, peer_id, label, added_at FROM federation_peers "
            "WHERE project_id = ? ORDER BY space_id, peer_id LIMIT 1001",
            (project_id,),
        )
    ]
    if len(spaces) > 100 or len(scopes) > 1000 or len(peers) > 1000:
        raise ValueError("federation inventory exceeds the operator bound")
    quarantine = [
        dict(row)
        for row in conn.execute(
            "SELECT q.id AS quarantine_id, q.space_id, q.claimed_event_id, "
            "q.reason_code, q.encoded_bytes, q.recorded_at "
            "FROM federation_quarantine q WHERE q.project_id = ? AND NOT EXISTS ("
            "SELECT 1 FROM federation_quarantine_receipts r "
            "WHERE r.project_id = q.project_id AND r.quarantine_id = q.id) "
            "ORDER BY q.recorded_at, q.id LIMIT 257",
            (project_id,),
        )
    ]
    if len(quarantine) > 256:
        raise ValueError("federation quarantine inventory exceeds the operator bound")
    counts = {
        "capability_events": int(
            conn.execute(
                "SELECT COUNT(*) FROM federation_capability_events WHERE project_id = ?",
                (project_id,),
            ).fetchone()[0]
        ),
        "encrypted_events": int(
            conn.execute(
                "SELECT COUNT(*) FROM federation_events WHERE project_id = ?",
                (project_id,),
            ).fetchone()[0]
        ),
        "quarantine_pending": int(
            conn.execute(
                "SELECT COUNT(*) FROM federation_quarantine q "
                "WHERE q.project_id = ? AND NOT EXISTS ("
                "SELECT 1 FROM federation_quarantine_receipts r "
                "WHERE r.project_id = q.project_id AND r.quarantine_id = q.id)",
                (project_id,),
            ).fetchone()[0]
        ),
        "quarantine_promoted": int(
            conn.execute(
                "SELECT COUNT(*) FROM federation_quarantine_receipts "
                "WHERE project_id = ? AND action = 'promoted'",
                (project_id,),
            ).fetchone()[0]
        ),
        "quarantine_rejected": int(
            conn.execute(
                "SELECT COUNT(*) FROM federation_quarantine_receipts "
                "WHERE project_id = ? AND action = 'rejected'",
                (project_id,),
            ).fetchone()[0]
        ),
        "operation_receipts": int(
            conn.execute(
                "SELECT COUNT(*) FROM federation_operation_receipts WHERE project_id = ?",
                (project_id,),
            ).fetchone()[0]
        ),
    }
    counts["quarantined"] = counts["quarantine_pending"]
    return {
        "schema": "rta-smriti.federation-inventory/v1",
        "status": status,
        "spaces": spaces,
        "scopes": scopes,
        "peers": peers,
        "quarantine": quarantine,
        "counts": counts,
    }


def preview_federation_operation(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    action: str,
    actor_peer_id: str,
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    selected_action = str(action).strip().casefold()
    selected_actor = _identifier("actor_peer_id", actor_peer_id)
    selected_parameters = _parameters(selected_action, parameters)
    state_digest = _state_digest(conn, project_id)
    request = {
        "action": selected_action,
        "actor_peer_id": selected_actor,
        "parameters": selected_parameters,
        "project_id": int(project_id),
        "schema": "rta-smriti.federation-operation-plan/v1",
        "state_before_digest": state_digest,
    }
    confirmation = hashlib.sha256(
        b"rta-smriti-federation-operation-v1\0" + canonical_json_bytes(request)
    ).hexdigest()
    warnings = []
    if selected_action in {"capability-revoke", "scope-rotate"}:
        warnings.append(
            "Previously decrypted plaintext may remain on formerly authorized devices."
        )
    return {
        "state": "preview",
        "action": selected_action,
        "actor_peer_id": selected_actor,
        "parameters": selected_parameters,
        "state_before_digest": state_digest,
        "confirmation_digest": confirmation,
        "writes_performed": False,
        "warnings": warnings,
    }


def apply_federation_operation(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    action: str,
    actor: FederationIdentity,
    parameters: Mapping[str, Any],
    confirmation_digest: str,
    public_peer: PublicFederationIdentity | None = None,
) -> dict[str, Any]:
    """Apply the exact current preview and append a path-free immutable receipt."""

    plan = preview_federation_operation(
        conn,
        project_id=project_id,
        action=action,
        actor_peer_id=actor.identity_id,
        parameters=parameters,
    )
    supplied = str(confirmation_digest)
    if not hmac.compare_digest(supplied, plan["confirmation_digest"]):
        raise FederationPlanConflict(
            "federation state or request changed after preview"
        )
    selected = plan["parameters"]
    selected_action = plan["action"]
    savepoint = "federation_operator_apply"
    conn.execute(f"SAVEPOINT {savepoint}")
    try:
        if selected_action == "space-create":
            result = create_space(
                conn,
                project_id=project_id,
                owner=actor,
                owner_key_reference=f"managed-local-identity:{actor.identity_id}",
                commit=False,
            )
        elif selected_action == "scope-create":
            space_id = selected["space_id"]
            result = create_scope(
                conn,
                project_id=project_id,
                space_id=space_id,
                owner=actor,
                kind=selected["kind"],
                label=selected["label"],
                commit=False,
            )
        elif selected_action == "peer-add":
            space_id = selected["space_id"]
            if public_peer is None or public_peer.identity_id != selected["peer_id"]:
                raise ValueError("peer public identity does not match the preview")
            result = add_public_peer(
                conn,
                project_id=project_id,
                space_id=space_id,
                author=actor,
                peer=public_peer,
                label=selected["label"],
                commit=False,
            )
        elif selected_action == "capability-grant":
            space_id = selected["space_id"]
            result = grant_capabilities(
                conn,
                project_id=project_id,
                space_id=space_id,
                scope_id=selected["scope_id"],
                author=actor,
                subject_peer_id=selected["subject_peer_id"],
                capabilities=tuple(selected["capabilities"]),
                commit=False,
            )
        elif selected_action == "capability-revoke":
            space_id = selected["space_id"]
            result = revoke_capabilities(
                conn,
                project_id=project_id,
                space_id=space_id,
                scope_id=selected["scope_id"],
                author=actor,
                subject_peer_id=selected["subject_peer_id"],
                commit=False,
            )
        elif selected_action == "capability-resolve":
            space_id = selected["space_id"]
            result = resolve_capability_conflict(
                conn,
                project_id=project_id,
                space_id=space_id,
                scope_id=selected["scope_id"],
                author=actor,
                subject_peer_id=selected["subject_peer_id"],
                capabilities=tuple(selected["capabilities"]),
                commit=False,
            )
        elif selected_action == "scope-rotate":
            space_id = selected["space_id"]
            result = rotate_scope_key(
                conn,
                project_id=project_id,
                space_id=space_id,
                scope_id=selected["scope_id"],
                author=actor,
                scope_key=generate_scope_key(),
                commit=False,
            )
        elif selected_action == "quarantine-reject":
            result = reject_quarantined_event(
                conn,
                project_id=project_id,
                quarantine_id=selected["quarantine_id"],
                actor=actor,
                reason=selected["reason"],
                commit=False,
            )
        elif selected_action == "quarantine-promote":
            result = promote_quarantined_event_by_id(
                conn,
                project_id=project_id,
                quarantine_id=selected["quarantine_id"],
                actor=actor,
                reason=selected["reason"],
                commit=False,
            )
        else:
            raise ValueError("federation operator action is unsupported")
        state_after = _state_digest(conn, project_id)
        result_digest = hashlib.sha256(canonical_json_bytes(result)).hexdigest()
        recorded_at = _now_iso()
        operation_id = hashlib.sha256(
            os.urandom(32)
            + bytes.fromhex(plan["confirmation_digest"])
            + bytes.fromhex(state_after)
        ).hexdigest()
        conn.execute(
            """
            INSERT INTO federation_operation_receipts(
                project_id, operation_id, action, actor_peer_id, request_digest,
                state_before_digest, state_after_digest, result_digest, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                operation_id,
                selected_action,
                actor.identity_id,
                plan["confirmation_digest"],
                plan["state_before_digest"],
                state_after,
                result_digest,
                recorded_at,
            ),
        )
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise
    return {
        "state": "applied",
        "operation_id": operation_id,
        "action": selected_action,
        "result": result,
        "state_before_digest": plan["state_before_digest"],
        "state_after_digest": state_after,
        "result_digest": result_digest,
        "recorded_at": recorded_at,
    }
