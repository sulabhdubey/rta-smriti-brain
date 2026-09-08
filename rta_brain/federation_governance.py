"""Append-only capability governance for federation spaces and scopes."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .federation_crypto import (
    FederationCryptoError,
    FederationIdentity,
    PublicFederationIdentity,
    decrypt_event,
    open_scope_key,
    seal_scope_key,
)
from .federation_types import (
    FederationEventEnvelope,
    canonical_json_bytes,
    parse_canonical_json,
)

ALL_CAPABILITIES = frozenset(
    {"admin", "read", "write", "review", "index", "context", "sync", "export", "diagnose"}
)
_ACTIONS = frozenset({"grant", "suspend", "revoke", "readmit", "rotate", "resolve_conflict"})
_ALL_SCOPES = object()


class FederationAuthorizationError(PermissionError):
    """A peer lacks authority for a federation operation."""


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _new_id() -> str:
    return os.urandom(32).hex()


def _normalize_capabilities(capabilities: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(capabilities, tuple):
        raise TypeError("capabilities must be a tuple")
    selected = tuple(sorted(set(capabilities)))
    if len(selected) != len(capabilities) or set(selected) - ALL_CAPABILITIES:
        raise ValueError("capabilities must be unique supported values")
    return selected


def _public_key_bytes(identity: FederationIdentity) -> tuple[bytes, bytes]:
    return identity.signing_public_bytes, identity.envelope_public_bytes


def _insert_identity(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    identity: FederationIdentity,
    key_reference: str,
) -> None:
    signing_public, envelope_public = _public_key_bytes(identity)
    conn.execute(
        """
        INSERT OR IGNORE INTO federation_identities(
            project_id, identity_id, signing_public_key, envelope_public_key,
            key_fingerprint, key_reference, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            identity.identity_id,
            signing_public,
            envelope_public,
            identity.identity_id,
            key_reference,
            _now_iso(),
        ),
    )


def _capability_heads(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str | None | object = _ALL_SCOPES,
) -> tuple[str, ...]:
    rows = list(
        conn.execute(
            "SELECT event_id, parents_json, scope_id FROM federation_capability_events "
            "WHERE project_id = ? AND space_id = ?",
            (project_id, space_id),
        )
    )
    if scope_id is not _ALL_SCOPES:
        rows = [
            row
            for row in rows
            if row["scope_id"] is None or row["scope_id"] == scope_id
        ]
    referenced = {
        str(parent)
        for row in rows
        for parent in json.loads(str(row["parents_json"]))
    }
    return tuple(sorted(str(row["event_id"]) for row in rows if str(row["event_id"]) not in referenced))


def _next_author_sequence(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    author_peer_id: str,
) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(author_sequence), 0) AS value "
        "FROM federation_capability_events "
        "WHERE project_id = ? AND space_id = ? AND author_peer_id = ?",
        (project_id, space_id, author_peer_id),
    ).fetchone()
    return int(row["value"]) + 1


def _record_capability_event(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str | None,
    author: FederationIdentity,
    subject_peer_id: str,
    action: str,
    capabilities: tuple[str, ...],
    bootstrap: bool = False,
    commit: bool = True,
) -> dict[str, Any]:
    if action not in _ACTIONS:
        raise ValueError("capability event action is invalid")
    selected = _normalize_capabilities(capabilities)
    if not bootstrap:
        authority = authorize_operation(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            peer_id=author.identity_id,
            operation="admin",
        )
        if not authority["allowed"]:
            raise FederationAuthorizationError("author is not an active federation administrator")
    sequence = _next_author_sequence(
        conn,
        project_id=project_id,
        space_id=space_id,
        author_peer_id=author.identity_id,
    )
    parents = _capability_heads(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
    )
    recorded_at = _now_iso()
    body = {
        "action": action,
        "author_peer_id": author.identity_id,
        "author_sequence": sequence,
        "capabilities": list(selected),
        "parents": list(parents),
        "recorded_at": recorded_at,
        "schema": "rta-smriti.federation-capability/v1",
        "scope_id": scope_id,
        "space_id": space_id,
        "subject_peer_id": subject_peer_id,
    }
    canonical = canonical_json_bytes(body)
    event_id = hashlib.sha256(b"rta-smriti-capability-v1\0" + canonical).hexdigest()
    signature = author.signing_private_key.sign(
        canonical_json_bytes({**body, "event_id": event_id})
    )
    conn.execute(
        """
        INSERT INTO federation_capability_events(
            project_id, space_id, scope_id, event_id, subject_peer_id,
            action, capabilities_json, author_peer_id, author_sequence,
            parents_json, event_digest, signature, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            space_id,
            scope_id,
            event_id,
            subject_peer_id,
            action,
            json.dumps(list(selected), separators=(",", ":")),
            author.identity_id,
            sequence,
            json.dumps(list(parents), separators=(",", ":")),
            hashlib.sha256(canonical).hexdigest(),
            signature,
            recorded_at,
        ),
    )
    if commit:
        conn.commit()
    return {
        "event_id": event_id,
        "action": action,
        "subject_peer_id": subject_peer_id,
        "scope_id": scope_id,
        "capabilities": list(selected),
        "author_sequence": sequence,
        "parents": list(parents),
    }


def _capability_event_body(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "action": str(row["action"]),
        "author_peer_id": str(row["author_peer_id"]),
        "author_sequence": int(row["author_sequence"]),
        "capabilities": list(json.loads(str(row["capabilities_json"]))),
        "parents": list(json.loads(str(row["parents_json"]))),
        "recorded_at": str(row["recorded_at"]),
        "schema": "rta-smriti.federation-capability/v1",
        "scope_id": row["scope_id"],
        "space_id": str(row["space_id"]),
        "subject_peer_id": str(row["subject_peer_id"]),
    }


def export_capability_event(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    event_id: str,
) -> bytes:
    """Export one signed public control-plane event without local identifiers."""

    row = conn.execute(
        "SELECT * FROM federation_capability_events "
        "WHERE project_id = ? AND space_id = ? AND event_id = ?",
        (project_id, space_id, event_id),
    ).fetchone()
    if row is None:
        raise ValueError("federation capability event does not exist")
    body = _capability_event_body(row)
    return canonical_json_bytes(
        {
            **body,
            "event_digest": str(row["event_digest"]),
            "event_id": str(row["event_id"]),
            "signature": base64.b64encode(bytes(row["signature"])).decode("ascii"),
        }
    )


def import_capability_event(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    encoded: bytes,
    commit: bool = True,
) -> dict[str, Any]:
    """Verify and append one remote capability event at its causal frontier."""

    try:
        value = parse_canonical_json(encoded)
        expected = {
            "action", "author_peer_id", "author_sequence", "capabilities",
            "event_digest", "event_id", "parents", "recorded_at", "schema",
            "scope_id", "signature", "space_id", "subject_peer_id",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("capability event fields are invalid")
        if value["schema"] != "rta-smriti.federation-capability/v1":
            raise ValueError("capability event schema is invalid")
        if value["space_id"] != space_id:
            raise ValueError("capability event space does not match")
        action = str(value["action"])
        if action not in _ACTIONS:
            raise ValueError("capability event action is invalid")
        capabilities = _normalize_capabilities(tuple(value["capabilities"]))
        parents = tuple(value["parents"])
        if (
            len(parents) > 256
            or len(parents) != len(set(parents))
            or any(not isinstance(item, str) or len(item) != 64 for item in parents)
        ):
            raise ValueError("capability event parents are invalid")
        author_peer_id = str(value["author_peer_id"])
        subject_peer_id = str(value["subject_peer_id"])
        scope_id = value["scope_id"]
        sequence = int(value["author_sequence"])
        if sequence < 1 or not isinstance(scope_id, (str, type(None))):
            raise ValueError("capability event metadata is invalid")
        body = {
            key: value[key]
            for key in (
                "action", "author_peer_id", "author_sequence", "capabilities",
                "parents", "recorded_at", "schema", "scope_id", "space_id",
                "subject_peer_id",
            )
        }
        canonical = canonical_json_bytes(body)
        event_id = hashlib.sha256(
            b"rta-smriti-capability-v1\0" + canonical
        ).hexdigest()
        if value["event_id"] != event_id or value["event_digest"] != hashlib.sha256(canonical).hexdigest():
            raise ValueError("capability event digest is invalid")
        peer = conn.execute(
            "SELECT signing_public_key FROM federation_peers "
            "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
            (project_id, space_id, author_peer_id),
        ).fetchone()
        if peer is None:
            raise ValueError("capability event author is unknown")
        signature = base64.b64decode(value["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(bytes(peer["signing_public_key"])).verify(
            signature,
            canonical_json_bytes({**body, "event_id": event_id}),
        )
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise FederationAuthorizationError("capability event verification failed") from exc

    existing = conn.execute(
        "SELECT event_id FROM federation_capability_events "
        "WHERE project_id = ? AND space_id = ? AND event_id = ?",
        (project_id, space_id, event_id),
    ).fetchone()
    if existing is not None:
        if export_capability_event(
            conn,
            project_id=project_id,
            space_id=space_id,
            event_id=event_id,
        ) == encoded:
            return {"state": "duplicate", "event_id": event_id}
        raise FederationAuthorizationError("capability event identity collision")
    if conn.execute(
        "SELECT 1 FROM federation_capability_events WHERE project_id = ? "
        "AND space_id = ? AND author_peer_id = ? AND author_sequence = ?",
        (project_id, space_id, author_peer_id, sequence),
    ).fetchone() is not None:
        raise FederationAuthorizationError("capability author sequence collision")
    missing = [
        parent
        for parent in parents
        if conn.execute(
            "SELECT 1 FROM federation_capability_events WHERE project_id = ? "
            "AND space_id = ? AND event_id = ?",
            (project_id, space_id, parent),
        ).fetchone() is None
    ]
    if missing:
        raise FederationAuthorizationError("capability event parent is missing")
    if conn.execute(
        "SELECT 1 FROM federation_peers WHERE project_id = ? AND space_id = ? AND peer_id = ?",
        (project_id, space_id, subject_peer_id),
    ).fetchone() is None:
        raise FederationAuthorizationError("capability event subject is unknown")
    event_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM federation_capability_events "
            "WHERE project_id = ? AND space_id = ?",
            (project_id, space_id),
        ).fetchone()[0]
    )
    owner_row = conn.execute(
        "SELECT owner_peer_id FROM federation_spaces "
        "WHERE project_id = ? AND space_id = ?",
        (project_id, space_id),
    ).fetchone()
    bootstrap = (
        event_count == 0
        and owner_row is not None
        and author_peer_id == str(owner_row["owner_peer_id"])
        and subject_peer_id == author_peer_id
        and action == "grant"
        and set(capabilities) == ALL_CAPABILITIES
        and sequence == 1
        and not parents
        and scope_id is None
    )
    if not bootstrap:
        authority = authorize_operation(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            peer_id=author_peer_id,
            operation="admin",
            frontier_event_ids=parents,
        )
        if not authority["allowed"]:
            raise FederationAuthorizationError(
                "capability event author was not authorized at its frontier"
            )
        current_authority = authorize_operation(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            peer_id=author_peer_id,
            operation="admin",
        )
        if not current_authority["allowed"]:
            raise FederationAuthorizationError(
                "capability event author is not authorized at the current frontier"
            )
    conn.execute(
        """
        INSERT INTO federation_capability_events(
            project_id, space_id, scope_id, event_id, subject_peer_id,
            action, capabilities_json, author_peer_id, author_sequence,
            parents_json, event_digest, signature, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id, space_id, scope_id, event_id, subject_peer_id, action,
            json.dumps(list(capabilities), separators=(",", ":")), author_peer_id,
            sequence, json.dumps(list(parents), separators=(",", ":")),
            str(value["event_digest"]), signature, str(value["recorded_at"]),
        ),
    )
    if commit:
        conn.commit()
    return {"state": "imported", "event_id": event_id}


def create_space(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    owner: FederationIdentity,
    owner_key_reference: str,
    commit: bool = True,
) -> dict[str, Any]:
    space_id = _new_id()
    _insert_identity(
        conn,
        project_id=project_id,
        identity=owner,
        key_reference=owner_key_reference,
    )
    conn.execute(
        """
        INSERT INTO federation_spaces(
            project_id, space_id, wire_schema, owner_peer_id, created_at
        ) VALUES (?, ?, 'rta-smriti.federation/v1', ?, ?)
        """,
        (project_id, space_id, owner.identity_id, _now_iso()),
    )
    conn.execute(
        """
        INSERT INTO federation_peers(
            project_id, space_id, peer_id, label, signing_public_key,
            envelope_public_key, added_at
        ) VALUES (?, ?, ?, 'Owner', ?, ?, ?)
        """,
        (
            project_id,
            space_id,
            owner.identity_id,
            owner.signing_public_bytes,
            owner.envelope_public_bytes,
            _now_iso(),
        ),
    )
    bootstrap = _record_capability_event(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=None,
        author=owner,
        subject_peer_id=owner.identity_id,
        action="grant",
        capabilities=tuple(sorted(ALL_CAPABILITIES)),
        bootstrap=True,
        commit=False,
    )
    if commit:
        conn.commit()
    return {"space_id": space_id, "owner_peer_id": owner.identity_id, "bootstrap": bootstrap}


def create_scope(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    owner: FederationIdentity,
    kind: str,
    label: str,
    commit: bool = True,
) -> dict[str, Any]:
    authority = authorize_operation(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=None,
        peer_id=owner.identity_id,
        operation="admin",
    )
    if not authority["allowed"]:
        raise FederationAuthorizationError("scope creation requires an active administrator")
    if kind not in {"team", "review", "custom"}:
        raise ValueError("scope kind is invalid")
    selected_label = str(label).strip()
    if not 1 <= len(selected_label) <= 256 or "\0" in selected_label:
        raise ValueError("scope label must be a bounded string")
    scope_id = _new_id()
    conn.execute(
        """
        INSERT INTO federation_scopes(
            project_id, space_id, scope_id, scope_kind, label,
            created_by_peer_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (project_id, space_id, scope_id, kind, selected_label, owner.identity_id, _now_iso()),
    )
    if commit:
        conn.commit()
    return {"space_id": space_id, "scope_id": scope_id, "kind": kind, "label": selected_label}


def add_peer(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    author: FederationIdentity,
    peer: FederationIdentity,
    label: str,
    commit: bool = True,
) -> dict[str, Any]:
    return add_public_peer(
        conn,
        project_id=project_id,
        space_id=space_id,
        author=author,
        peer=PublicFederationIdentity(
            identity_id=peer.identity_id,
            signing_public_bytes=peer.signing_public_bytes,
            envelope_public_bytes=peer.envelope_public_bytes,
        ),
        label=label,
        commit=commit,
    )


def add_public_peer(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    author: FederationIdentity,
    peer: PublicFederationIdentity,
    label: str,
    commit: bool = True,
) -> dict[str, Any]:
    authority = authorize_operation(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=None,
        peer_id=author.identity_id,
        operation="admin",
    )
    if not authority["allowed"]:
        raise FederationAuthorizationError("adding a peer requires an active administrator")
    selected_label = str(label).strip()
    if not 1 <= len(selected_label) <= 256 or "\0" in selected_label:
        raise ValueError("peer label must be a bounded string")
    conn.execute(
        """
        INSERT INTO federation_peers(
            project_id, space_id, peer_id, label, signing_public_key,
            envelope_public_key, added_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            space_id,
            peer.identity_id,
            selected_label,
            peer.signing_public_bytes,
            peer.envelope_public_bytes,
            _now_iso(),
        ),
    )
    if commit:
        conn.commit()
    return {"space_id": space_id, "peer_id": peer.identity_id, "label": selected_label}


def grant_capabilities(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str | None,
    author: FederationIdentity,
    subject_peer_id: str,
    capabilities: tuple[str, ...],
    commit: bool = True,
) -> dict[str, Any]:
    return _record_capability_event(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        author=author,
        subject_peer_id=subject_peer_id,
        action="grant",
        capabilities=capabilities,
        commit=commit,
    )


def revoke_capabilities(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str | None,
    author: FederationIdentity,
    subject_peer_id: str,
    commit: bool = True,
) -> dict[str, Any]:
    try:
        result = _record_capability_event(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            author=author,
            subject_peer_id=subject_peer_id,
            action="revoke",
            capabilities=(),
            commit=False,
        )
        selected_scopes = (
            (scope_id,)
            if scope_id is not None
            else tuple(
                str(row["scope_id"])
                for row in conn.execute(
                    "SELECT scope_id FROM federation_scopes "
                    "WHERE project_id = ? AND space_id = ? ORDER BY scope_id",
                    (project_id, space_id),
                )
            )
        )
        rotations = [
            rotate_scope_key(
                conn,
                project_id=project_id,
                space_id=space_id,
                scope_id=selected_scope,
                author=author,
                scope_key=os.urandom(32),
                commit=False,
            )
            for selected_scope in selected_scopes
        ]
        if commit:
            conn.commit()
    except Exception:
        if commit:
            conn.rollback()
        raise
    return {
        **result,
        "prior_plaintext_may_remain": True,
        "relay_ciphertext_access_may_persist": True,
        "rotated_scope_count": len(rotations),
        "rotation_event_ids": [item["rotation_event_id"] for item in rotations],
    }


def _key_envelope_body(
    *,
    space_id: str,
    scope_id: str,
    epoch: int,
    recipient_peer_id: str,
    issuer_peer_id: str,
    hpke_ciphertext: bytes,
) -> dict[str, Any]:
    return {
        "epoch": epoch,
        "hpke_ciphertext": base64.b64encode(hpke_ciphertext).decode("ascii"),
        "issuer_peer_id": issuer_peer_id,
        "recipient_peer_id": recipient_peer_id,
        "schema": "rta-smriti.scope-key-envelope/v1",
        "scope_id": scope_id,
        "space_id": space_id,
    }


def rotate_scope_key(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    author: FederationIdentity,
    scope_key: bytes,
    commit: bool = True,
) -> dict[str, Any]:
    if not isinstance(scope_key, bytes) or len(scope_key) != 32:
        raise ValueError("scope key must contain exactly 32 bytes")
    authority = authorize_operation(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        peer_id=author.identity_id,
        operation="admin",
    )
    if not authority["allowed"]:
        raise FederationAuthorizationError("scope rotation requires an active administrator")
    scope = conn.execute(
        "SELECT 1 FROM federation_scopes WHERE project_id = ? AND space_id = ? AND scope_id = ?",
        (project_id, space_id, scope_id),
    ).fetchone()
    if scope is None:
        raise ValueError("federation scope does not exist")
    row = conn.execute(
        "SELECT COALESCE(MAX(epoch), 0) AS value FROM federation_scope_epochs "
        "WHERE project_id = ? AND space_id = ? AND scope_id = ?",
        (project_id, space_id, scope_id),
    ).fetchone()
    epoch = int(row["value"]) + 1
    rotation = _record_capability_event(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        author=author,
        subject_peer_id=author.identity_id,
        action="rotate",
        capabilities=(),
        commit=False,
    )
    conn.execute(
        """
        INSERT INTO federation_scope_epochs(
            project_id, space_id, scope_id, epoch, rotation_event_id,
            key_digest, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            space_id,
            scope_id,
            epoch,
            rotation["event_id"],
            hashlib.sha256(scope_key).hexdigest(),
            _now_iso(),
        ),
    )
    peer_rows = list(
        conn.execute(
            """
            SELECT peer_id, envelope_public_key FROM federation_peers
            WHERE project_id = ? AND space_id = ? ORDER BY peer_id
            """,
            (project_id, space_id),
        )
    )
    recipients: list[str] = []
    for peer in peer_rows:
        peer_id = str(peer["peer_id"])
        access = authorize_operation(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            peer_id=peer_id,
            operation="read",
        )
        if not access["allowed"]:
            continue
        sealed = seal_scope_key(
            scope_key,
            recipient_public_key=bytes(peer["envelope_public_key"]),
            space_id=space_id,
            scope_id=scope_id,
            epoch=epoch,
            recipient_peer_id=peer_id,
        )
        body = _key_envelope_body(
            space_id=space_id,
            scope_id=scope_id,
            epoch=epoch,
            recipient_peer_id=peer_id,
            issuer_peer_id=author.identity_id,
            hpke_ciphertext=sealed,
        )
        canonical = canonical_json_bytes(body)
        envelope_id = hashlib.sha256(b"rta-smriti-scope-envelope-v1\0" + canonical).hexdigest()
        signature = author.signing_private_key.sign(
            canonical_json_bytes({**body, "envelope_id": envelope_id})
        )
        conn.execute(
            """
            INSERT INTO federation_key_envelopes(
                project_id, space_id, scope_id, epoch, envelope_id,
                recipient_peer_id, issuer_peer_id, hpke_ciphertext,
                envelope_digest, signature, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                space_id,
                scope_id,
                epoch,
                envelope_id,
                peer_id,
                author.identity_id,
                sealed,
                hashlib.sha256(canonical).hexdigest(),
                signature,
                _now_iso(),
            ),
        )
        recipients.append(peer_id)
    if commit:
        conn.commit()
    return {
        "space_id": space_id,
        "scope_id": scope_id,
        "epoch": epoch,
        "rotation_event_id": rotation["event_id"],
        "recipient_peer_ids": recipients,
        "prior_plaintext_may_remain": True,
    }


def open_current_scope_key(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    recipient: FederationIdentity,
) -> bytes:
    row = conn.execute(
        "SELECT MAX(epoch) AS epoch FROM federation_scope_epochs "
        "WHERE project_id = ? AND space_id = ? AND scope_id = ?",
        (project_id, space_id, scope_id),
    ).fetchone()
    if row is None or row["epoch"] is None:
        raise FederationAuthorizationError("no active scope epoch exists")
    return open_scope_key_for_epoch(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        epoch=int(row["epoch"]),
        recipient=recipient,
    )


def open_scope_key_for_epoch(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    epoch: int,
    recipient: FederationIdentity,
) -> bytes:
    row = conn.execute(
        """
        SELECT envelope_id, epoch, recipient_peer_id, issuer_peer_id,
               hpke_ciphertext, envelope_digest, signature
        FROM federation_key_envelopes
        WHERE project_id = ? AND space_id = ? AND scope_id = ?
          AND recipient_peer_id = ? AND epoch = ?
        """,
        (
            project_id,
            space_id,
            scope_id,
            recipient.identity_id,
            int(epoch),
        ),
    ).fetchone()
    if row is None:
        raise FederationAuthorizationError("no scope key envelope exists for this active epoch")
    issuer = conn.execute(
        "SELECT signing_public_key FROM federation_peers "
        "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
        (project_id, space_id, str(row["issuer_peer_id"])),
    ).fetchone()
    if issuer is None:
        raise FederationCryptoError("scope key envelope issuer is unknown")
    body = _key_envelope_body(
        space_id=space_id,
        scope_id=scope_id,
        epoch=int(row["epoch"]),
        recipient_peer_id=str(row["recipient_peer_id"]),
        issuer_peer_id=str(row["issuer_peer_id"]),
        hpke_ciphertext=bytes(row["hpke_ciphertext"]),
    )
    canonical = canonical_json_bytes(body)
    envelope_id = hashlib.sha256(b"rta-smriti-scope-envelope-v1\0" + canonical).hexdigest()
    if (
        envelope_id != str(row["envelope_id"])
        or hashlib.sha256(canonical).hexdigest() != str(row["envelope_digest"])
    ):
        raise FederationCryptoError("scope key envelope digest is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(bytes(issuer["signing_public_key"])).verify(
            bytes(row["signature"]),
            canonical_json_bytes({**body, "envelope_id": envelope_id}),
        )
    except (InvalidSignature, ValueError) as exc:
        raise FederationCryptoError("scope key envelope signature is invalid") from exc
    return open_scope_key(
        bytes(row["hpke_ciphertext"]),
        recipient_private_key=recipient.envelope_private_key,
        space_id=space_id,
        scope_id=scope_id,
        epoch=int(row["epoch"]),
        recipient_peer_id=recipient.identity_id,
    )


def federation_status(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    actor_peer_id: str | None = None,
) -> dict[str, Any]:
    """Return bounded path-free federation health without claiming relay reachability."""

    spaces = list(
        conn.execute(
            "SELECT space_id, owner_peer_id FROM federation_spaces "
            "WHERE project_id = ? ORDER BY space_id LIMIT 101",
            (project_id,),
        )
    )
    if not spaces:
        return {
            "state": "not_configured",
            "operationally_ready": False,
            "space_count": 0,
            "scope_count": 0,
            "peer_count": 0,
            "axes": {
                "federation": "not_configured",
                "governance": "not_configured",
                "encryption": "not_configured",
                "projection": "not_configured",
                "sync": "not_configured",
                "relay": "not_configured",
            },
            "guidance": "Create a federation space only when selective team sharing is needed.",
        }
    if len(spaces) > 100:
        raise ValueError("federation space inventory exceeds the diagnostic bound")
    scope_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM federation_scopes WHERE project_id = ?",
            (project_id,),
        ).fetchone()[0]
    )
    peer_count = int(
        conn.execute(
            "SELECT COUNT(*) FROM federation_peers WHERE project_id = ?",
            (project_id,),
        ).fetchone()[0]
    )
    validation_counts = {
        str(row["validation_state"]): int(row["count"])
        for row in conn.execute(
            """
            SELECT v.validation_state, COUNT(*) AS count
            FROM federation_event_validation v
            WHERE v.project_id = ? GROUP BY v.validation_state
            """,
            (project_id,),
        )
    }
    projection_states = [
        str(row["state"])
        for row in conn.execute(
            "SELECT state FROM federation_projections WHERE project_id = ?",
            (project_id,),
        )
    ]
    scopes_without_epoch = int(
        conn.execute(
            """
            SELECT COUNT(*) FROM federation_scopes s
            WHERE s.project_id = ? AND NOT EXISTS (
                SELECT 1 FROM federation_scope_epochs e
                WHERE e.project_id = s.project_id AND e.space_id = s.space_id
                  AND e.scope_id = s.scope_id
            )
            """,
            (project_id,),
        ).fetchone()[0]
    )
    missing_actor_envelopes = 0
    actor_access = {
        "state": "not_evaluated",
        "authorized_scope_count": 0,
        "revoked_scope_count": 0,
        "conflict_scope_count": 0,
    }
    if actor_peer_id:
        peer_known = conn.execute(
            "SELECT 1 FROM federation_peers WHERE project_id = ? AND peer_id = ? LIMIT 1",
            (project_id, actor_peer_id),
        ).fetchone() is not None
        authorized_scopes = 0
        revoked_scopes = 0
        conflict_scopes = 0
        scope_rows = list(
            conn.execute(
                "SELECT space_id, scope_id FROM federation_scopes "
                "WHERE project_id = ? ORDER BY space_id, scope_id LIMIT 10001",
                (project_id,),
            )
        )
        if len(scope_rows) > 10_000:
            raise ValueError("federation scope inventory exceeds the diagnostic bound")
        for scope in scope_rows:
            space_id = str(scope["space_id"])
            scope_id = str(scope["scope_id"])
            access = authorize_operation(
                conn,
                project_id=project_id,
                space_id=space_id,
                scope_id=scope_id,
                peer_id=actor_peer_id,
                operation="read",
            )
            if access["allowed"]:
                authorized_scopes += 1
                latest = conn.execute(
                    "SELECT MAX(epoch) FROM federation_scope_epochs "
                    "WHERE project_id = ? AND space_id = ? AND scope_id = ?",
                    (project_id, space_id, scope_id),
                ).fetchone()[0]
                if latest is not None and conn.execute(
                    "SELECT 1 FROM federation_key_envelopes "
                    "WHERE project_id = ? AND space_id = ? AND scope_id = ? "
                    "AND epoch = ? AND recipient_peer_id = ?",
                    (project_id, space_id, scope_id, int(latest), actor_peer_id),
                ).fetchone() is None:
                    missing_actor_envelopes += 1
            elif access["reason"] == "peer_revoked":
                revoked_scopes += 1
            elif access["reason"] == "governance_conflict":
                conflict_scopes += 1
        if not peer_known:
            actor_state = "unknown"
        elif conflict_scopes:
            actor_state = "conflict"
        elif not authorized_scopes and revoked_scopes:
            actor_state = "revoked"
        elif authorized_scopes:
            actor_state = "active"
        else:
            actor_state = "no_access"
        actor_access = {
            "state": actor_state,
            "authorized_scope_count": authorized_scopes,
            "revoked_scope_count": revoked_scopes,
            "conflict_scope_count": conflict_scopes,
        }
    cursor_states = [
        str(row["state"])
        for row in conn.execute(
            "SELECT state FROM federation_sync_cursors WHERE project_id = ?",
            (project_id,),
        )
    ]
    quarantined = validation_counts.get("quarantined", 0)
    pending = validation_counts.get("pending_parent", 0)
    governance_conflicts: set[str] = set()
    for space in spaces:
        space_id = str(space["space_id"])
        rows = list(
            conn.execute(
                "SELECT scope_id, action, capabilities_json, event_id, "
                "subject_peer_id, parents_json FROM federation_capability_events "
                "WHERE project_id = ? AND space_id = ?",
                (project_id, space_id),
            )
        )
        if len(rows) > 10_000:
            raise ValueError("federation governance inventory exceeds the diagnostic bound")
        frontier = _capability_heads(
            conn, project_id=project_id, space_id=space_id
        )
        included = _capability_ancestors(rows, frontier) if frontier else set()
        layers = {
            (str(row["subject_peer_id"]), row["scope_id"])
            for row in rows
            if str(row["action"]) != "rotate"
        }
        for subject_peer_id, scope_id in layers:
            layer_state, _, conflicting_ids = _layer_state(
                rows,
                included=included,
                subject_peer_id=subject_peer_id,
                scope_id=scope_id,
            )
            if layer_state == "conflict":
                governance_conflicts.update(conflicting_ids)
                if len(governance_conflicts) > 256:
                    raise ValueError("federation governance conflicts exceed the diagnostic bound")
    projection_conflict = "conflict" in projection_states
    conflict = projection_conflict or bool(governance_conflicts)
    key_missing = scopes_without_epoch + missing_actor_envelopes
    if quarantined:
        state = "tampered_or_unauthorized"
    elif conflict:
        state = "conflict"
    elif actor_access["state"] == "revoked":
        state = "revoked"
    elif key_missing:
        state = "key_missing"
    elif "error" in cursor_states:
        state = "offline"
    elif pending or "partial" in cursor_states or "partial" in projection_states:
        state = "partial"
    else:
        state = "healthy"
    axes = {
        "federation": "healthy" if state == "healthy" else state,
        "governance": (
            "conflict" if governance_conflicts else
            "revoked" if actor_access["state"] == "revoked" else "healthy"
        ),
        "encryption": (
            "revoked" if actor_access["state"] == "revoked" else
            "healthy" if key_missing == 0 else "key_missing"
        ),
        "projection": (
            "conflict" if projection_conflict else "partial" if pending else "healthy"
        ),
        "sync": (
            "idle" if not cursor_states else
            "offline" if "error" in cursor_states else
            "partial" if "partial" in cursor_states else "healthy"
        ),
        "relay": (
            "not_configured" if not cursor_states else
            "relay_down" if "error" in cursor_states else "unverified"
        ),
    }
    return {
        "state": state,
        "operationally_ready": state == "healthy",
        "space_count": len(spaces),
        "scope_count": scope_count,
        "peer_count": peer_count,
        "event_validation": validation_counts,
        "governance_conflict_count": len(governance_conflicts),
        "governance_conflicting_event_ids": sorted(governance_conflicts),
        "key_missing_count": key_missing,
        "actor_access": actor_access,
        "axes": axes,
        "prior_plaintext_revocation_limit": True,
        "guidance": (
            "Configure and probe a relay separately; this local status does not prove relay reachability."
        ),
    }


def _capability_ancestors(
    rows: list[sqlite3.Row], frontier_event_ids: tuple[str, ...]
) -> set[str]:
    by_id = {str(row["event_id"]): row for row in rows}
    if any(event_id not in by_id for event_id in frontier_event_ids):
        raise FederationAuthorizationError("capability frontier is incomplete")
    included: set[str] = set()
    pending = list(frontier_event_ids)
    while pending:
        event_id = pending.pop()
        if event_id in included:
            continue
        included.add(event_id)
        pending.extend(json.loads(str(by_id[event_id]["parents_json"])))
    return included


def _capability_is_ancestor(
    ancestor: str,
    descendant: str,
    by_id: dict[str, sqlite3.Row],
) -> bool:
    pending = list(json.loads(str(by_id[descendant]["parents_json"])))
    visited: set[str] = set()
    while pending:
        current = str(pending.pop())
        if current == ancestor:
            return True
        if current not in visited and current in by_id:
            visited.add(current)
            pending.extend(json.loads(str(by_id[current]["parents_json"])))
    return False


def _layer_state(
    rows: list[sqlite3.Row],
    *,
    included: set[str],
    subject_peer_id: str,
    scope_id: str | None,
) -> tuple[str, set[str], tuple[str, ...]]:
    by_id = {str(row["event_id"]): row for row in rows}
    relevant = [
        row
        for row in rows
        if str(row["event_id"]) in included
        and str(row["subject_peer_id"]) == subject_peer_id
        and row["scope_id"] == scope_id
        and str(row["action"]) != "rotate"
    ]
    heads = [
        row
        for row in relevant
        if not any(
            _capability_is_ancestor(
                str(row["event_id"]), str(other["event_id"]), by_id
            )
            for other in relevant
            if str(other["event_id"]) != str(row["event_id"])
        )
    ]
    if len(heads) > 1:
        return "conflict", set(), tuple(sorted(str(row["event_id"]) for row in heads))
    if not heads:
        return "ungranted", set(), ()
    head = heads[0]
    action = str(head["action"])
    if action in {"grant", "readmit", "resolve_conflict"}:
        return "active", set(json.loads(str(head["capabilities_json"]))), ()
    if action == "suspend":
        return "suspended", set(), ()
    if action == "revoke":
        return "revoked", set(), ()
    return "ungranted", set(), ()


def authorize_operation(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str | None,
    peer_id: str,
    operation: str,
    frontier_event_ids: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    if operation not in ALL_CAPABILITIES:
        raise ValueError("federation operation is invalid")
    peer = conn.execute(
        "SELECT 1 FROM federation_peers WHERE project_id = ? AND space_id = ? AND peer_id = ?",
        (project_id, space_id, peer_id),
    ).fetchone()
    if peer is None:
        return {"allowed": False, "reason": "peer_unknown", "capabilities": []}
    rows = list(
        conn.execute(
            """
            SELECT scope_id, action, capabilities_json, event_id,
                   subject_peer_id, parents_json
            FROM federation_capability_events
            WHERE project_id = ? AND space_id = ?
            """,
            (project_id, space_id),
        )
    )
    selected_frontier = (
        tuple(frontier_event_ids)
        if frontier_event_ids is not None
        else _capability_heads(conn, project_id=project_id, space_id=space_id)
    )
    included = _capability_ancestors(rows, selected_frontier) if selected_frontier else set()
    global_state, global_capabilities, global_conflicts = _layer_state(
        rows,
        included=included,
        subject_peer_id=peer_id,
        scope_id=None,
    )
    scope_state, scope_capabilities, scope_conflicts = _layer_state(
        rows,
        included=included,
        subject_peer_id=peer_id,
        scope_id=scope_id,
    ) if scope_id is not None else ("ungranted", set(), ())
    conflicts = tuple(sorted(set(global_conflicts) | set(scope_conflicts)))
    if conflicts:
        return {
            "allowed": False,
            "reason": "governance_conflict",
            "capabilities": [],
            "conflicting_event_ids": list(conflicts),
        }
    if global_state == "revoked" or scope_state == "revoked":
        return {"allowed": False, "reason": "peer_revoked", "capabilities": []}
    if global_state == "suspended" or scope_state == "suspended":
        return {"allowed": False, "reason": "peer_suspended", "capabilities": []}
    effective = global_capabilities | scope_capabilities
    allowed = "admin" in effective or operation in effective
    return {
        "allowed": allowed,
        "reason": "allowed" if allowed else "capability_missing",
        "capabilities": sorted(effective),
    }


def resolve_capability_conflict(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str | None,
    author: FederationIdentity,
    subject_peer_id: str,
    capabilities: tuple[str, ...],
    commit: bool = True,
) -> dict[str, Any]:
    """Append an explicit administrator decision over all current control heads."""

    return _record_capability_event(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        author=author,
        subject_peer_id=subject_peer_id,
        action="resolve_conflict",
        capabilities=capabilities,
        commit=commit,
    )


def _required_operation(event_type: str) -> str:
    if event_type.startswith(("memory.", "evidence.", "truth.")):
        return "write"
    if event_type.startswith("comment."):
        return "review"
    if event_type in {"approval.proposed", "review.requested"}:
        return "review"
    if event_type.startswith(("approval.", "decision.")):
        return "admin"
    raise FederationAuthorizationError("federation event type is not authorized")


def _set_validation(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    event_id: str,
    state: str,
    reason: str | None,
    commit: bool = True,
) -> None:
    conn.execute(
        """
        UPDATE federation_event_validation
        SET validation_state = ?, reason_code = ?, validated_at = ?
        WHERE project_id = ? AND event_row_id = (
            SELECT id FROM federation_events WHERE project_id = ? AND event_id = ?
        )
        """,
        (state, reason, _now_iso(), project_id, project_id, event_id),
    )
    if state == "quarantined":
        row = conn.execute(
            "SELECT * FROM federation_events WHERE project_id = ? AND event_id = ?",
            (project_id, event_id),
        ).fetchone()
        if row is not None:
            stored_envelope = FederationEventEnvelope(
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
            conn.execute(
                "INSERT OR IGNORE INTO federation_quarantine(project_id, space_id, "
                "claimed_event_id, reason_code, envelope_sha256, encoded_bytes, state, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)",
                (
                    project_id,
                    stored_envelope.space_id,
                    stored_envelope.event_id,
                    reason or "validation_failed",
                    stored_envelope.envelope_sha256,
                    len(stored_envelope.encoded),
                    _now_iso(),
                ),
            )
    if commit:
        conn.commit()


def quarantine_stored_event(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    event_id: str,
    reason: str,
    commit: bool = True,
) -> None:
    """Quarantine one already stored opaque event without opening its payload."""

    _set_validation(
        conn,
        project_id=project_id,
        event_id=event_id,
        state="quarantined",
        reason=reason,
        commit=commit,
    )


def validate_and_accept_event(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    envelope: FederationEventEnvelope,
    author_signing_public_key: bytes,
    scope_key: bytes,
    allow_quarantine_recheck: bool = False,
    commit: bool = True,
) -> dict[str, Any]:
    stored = conn.execute(
        """
        SELECT e.*, v.validation_state
        FROM federation_events e
        JOIN federation_event_validation v ON v.event_row_id = e.id
        WHERE e.project_id = ? AND e.space_id = ? AND e.event_id = ?
        """,
        (project_id, envelope.space_id, envelope.event_id),
    ).fetchone()
    if stored is None:
        raise ValueError("federation event must be stored before validation")
    stored_identity = (
        str(stored["scope_id"]), int(stored["epoch"]), str(stored["author_peer_id"]),
        int(stored["author_sequence"]), str(stored["capability_event_id"]),
        str(stored["parents_json"]), bytes(stored["nonce"]), bytes(stored["ciphertext"]),
        str(stored["ciphertext_sha256"]), bytes(stored["signature"]),
    )
    supplied_identity = (
        envelope.scope_id, envelope.epoch, envelope.author_peer_id,
        envelope.author_sequence, envelope.capability_event_id,
        json.dumps(list(envelope.parents), separators=(",", ":")), envelope.nonce,
        envelope.ciphertext, envelope.ciphertext_sha256, envelope.signature,
    )
    if stored_identity != supplied_identity:
        raise ValueError("federation event validation does not match the stored envelope")
    if str(stored["validation_state"]) == "quarantined" and not allow_quarantine_recheck:
        raise FederationAuthorizationError("quarantined federation event requires operator review")
    if envelope.parents:
        placeholders = ",".join("?" for _ in envelope.parents)
        present = int(
            conn.execute(
                f"SELECT COUNT(*) FROM federation_events WHERE project_id = ? "  # nosec B608 - placeholder count only
                f"AND space_id = ? AND event_id IN ({placeholders})",
                (project_id, envelope.space_id, *envelope.parents),
            ).fetchone()[0]
        )
        if present != len(envelope.parents):
            return {
                "state": "pending_parent",
                "event_id": envelope.event_id,
                "missing_parent_count": len(envelope.parents) - present,
            }
    current = authorize_operation(
        conn,
        project_id=project_id,
        space_id=envelope.space_id,
        scope_id=envelope.scope_id,
        peer_id=envelope.author_peer_id,
        operation="read",
    )
    if current["reason"] in {"peer_unknown", "peer_revoked", "peer_suspended"}:
        _set_validation(
            conn,
            project_id=project_id,
            event_id=envelope.event_id,
            state="quarantined",
            reason=current["reason"],
            commit=commit,
        )
        raise FederationAuthorizationError(current["reason"].replace("_", " "))
    frontier = conn.execute(
        """
        SELECT action, subject_peer_id, scope_id, capabilities_json
        FROM federation_capability_events
        WHERE project_id = ? AND space_id = ? AND event_id = ?
        """,
        (project_id, envelope.space_id, envelope.capability_event_id),
    ).fetchone()
    if (
        frontier is None
        or str(frontier["subject_peer_id"]) != envelope.author_peer_id
        or frontier["action"] not in {"grant", "readmit"}
        or frontier["scope_id"] not in {None, envelope.scope_id}
    ):
        _set_validation(
            conn,
            project_id=project_id,
            event_id=envelope.event_id,
            state="quarantined",
            reason="authorization_frontier_invalid",
            commit=commit,
        )
        raise FederationAuthorizationError("authorization frontier is invalid")
    try:
        payload = decrypt_event(
            envelope,
            author_signing_public_key=author_signing_public_key,
            scope_key=scope_key,
        )
    except FederationCryptoError:
        _set_validation(
            conn,
            project_id=project_id,
            event_id=envelope.event_id,
            state="quarantined",
            reason="cryptographic_verification_failed",
            commit=commit,
        )
        raise
    event_type = str(payload.get("event_type") or "")
    required = _required_operation(event_type)
    authority = authorize_operation(
        conn,
        project_id=project_id,
        space_id=envelope.space_id,
        scope_id=envelope.scope_id,
        peer_id=envelope.author_peer_id,
        operation=required,
    )
    frontier_capabilities = set(json.loads(str(frontier["capabilities_json"])))
    if not authority["allowed"] or (
        "admin" not in frontier_capabilities and required not in frontier_capabilities
    ):
        reason = authority["reason"] if not authority["allowed"] else "frontier_capability_missing"
        _set_validation(
            conn,
            project_id=project_id,
            event_id=envelope.event_id,
            state="quarantined",
            reason=reason,
            commit=commit,
        )
        raise FederationAuthorizationError(reason.replace("_", " "))
    _set_validation(
        conn,
        project_id=project_id,
        event_id=envelope.event_id,
        state="accepted",
        reason=None,
        commit=commit,
    )
    return {"state": "accepted", "event_id": envelope.event_id, "event_type": event_type}
