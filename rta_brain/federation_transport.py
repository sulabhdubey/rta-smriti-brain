"""Opaque, bounded content-addressed transport for federation events."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
from pathlib import Path
from typing import Protocol

from .federation import deterministic_event_order, store_event
from .federation_crypto import FederationCryptoError, FederationIdentity
from .federation_governance import (
    FederationAuthorizationError,
    authorize_operation,
    open_scope_key_for_epoch,
    quarantine_stored_event,
    validate_and_accept_event,
)
from .federation_types import (
    FederationEventEnvelope,
    canonical_json_bytes,
    parse_event_envelope,
)

MAX_RELAY_OBJECTS = 10_000


class FederationTransportError(OSError):
    """A relay object failed an integrity, size, or atomicity check."""


class FederationRelay(Protocol):
    """Common opaque relay contract used by filesystem and HTTP transports."""

    def put_event(
        self, envelope: FederationEventEnvelope
    ) -> dict[str, str | int]: ...

    def inventory(
        self, space_id: str, *, scope_id: str | None = None
    ) -> list[str]: ...

    def missing(
        self, space_id: str, known_event_ids: tuple[str, ...]
    ) -> list[str]: ...

    def get_event(
        self, space_id: str, event_id: str
    ) -> FederationEventEnvelope: ...


def _identifier(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
        or set(value) == {"0"}
    ):
        raise ValueError(f"{name} must be a non-zero lower-case SHA-256 identifier")
    return value


class FilesystemFederationRelay:
    """A blind local/self-hosted relay storing only canonical encrypted envelopes."""

    def __init__(self, root: Path, *, max_blob_bytes: int = 2 * 1024 * 1024) -> None:
        self.root = Path(root).expanduser().absolute()
        self.max_blob_bytes = int(max_blob_bytes)
        if not 64 <= self.max_blob_bytes <= 16 * 1024 * 1024:
            raise ValueError("max_blob_bytes is outside the supported range")

    @staticmethod
    def _is_link_or_reparse(path: Path) -> bool:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return False
        attributes = int(getattr(metadata, "st_file_attributes", 0))
        reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)

    def _assert_unlinked_path(self, path: Path) -> None:
        selected = Path(path).absolute()
        try:
            selected.relative_to(self.root)
        except ValueError as exc:
            raise FederationTransportError("relay storage path escapes its root") from exc
        chain = [*reversed(self.root.parents), self.root]
        if selected != self.root:
            current = self.root
            for part in selected.relative_to(self.root).parts:
                current = current / part
                chain.append(current)
        for component in chain:
            if self._is_link_or_reparse(component):
                raise FederationTransportError(
                    "relay storage path contains a linked or reparse component"
                )

    def _space_root(self, space_id: str) -> Path:
        selected = _identifier("space_id", space_id)
        return self.root / "objects" / selected

    def _path(self, space_id: str, event_id: str) -> Path:
        selected = _identifier("event_id", event_id)
        return self._space_root(space_id) / selected[:2] / f"{selected}.event"

    def put_event(self, envelope: FederationEventEnvelope) -> dict[str, str | int]:
        encoded = envelope.encoded
        if len(encoded) > self.max_blob_bytes:
            raise FederationTransportError("relay event exceeds the configured size limit")
        target = self._path(envelope.space_id, envelope.event_id)
        self._assert_unlinked_path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        self._assert_unlinked_path(target)
        if target.exists():
            existing = target.read_bytes()
            if existing != encoded:
                raise FederationTransportError("existing relay event digest does not match")
            return {
                "state": "already_present",
                "event_id": envelope.event_id,
                "bytes": len(encoded),
            }
        temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, target)
            except FileExistsError:
                if target.read_bytes() != encoded:
                    raise FederationTransportError("concurrent relay event digest does not match")
            return {
                "state": "stored" if target.exists() else "error",
                "event_id": envelope.event_id,
                "bytes": len(encoded),
            }
        finally:
            temporary.unlink(missing_ok=True)

    def inventory(
        self, space_id: str, *, scope_id: str | None = None
    ) -> list[str]:
        root = self._space_root(space_id)
        self._assert_unlinked_path(root)
        if not root.exists():
            return []
        selected_scope = _identifier("scope_id", scope_id) if scope_id is not None else None
        result: list[str] = []
        for path in root.glob("??/*.event"):
            self._assert_unlinked_path(path)
            event_id = path.stem
            _identifier("event_id", event_id)
            if selected_scope is not None:
                envelope = self.get_event(space_id, event_id)
                if envelope.scope_id != selected_scope:
                    continue
            result.append(event_id)
            if len(result) > MAX_RELAY_OBJECTS:
                raise FederationTransportError("relay inventory exceeds the bounded object limit")
        return sorted(result)

    def missing(self, space_id: str, known_event_ids: tuple[str, ...]) -> list[str]:
        if not isinstance(known_event_ids, tuple) or len(known_event_ids) > MAX_RELAY_OBJECTS:
            raise ValueError("known_event_ids must be a bounded tuple")
        known = {_identifier("event_id", item) for item in known_event_ids}
        return sorted(set(self.inventory(space_id)) - known)

    def get_event(self, space_id: str, event_id: str) -> FederationEventEnvelope:
        target = self._path(space_id, event_id)
        self._assert_unlinked_path(target)
        try:
            size = target.stat().st_size
        except FileNotFoundError as exc:
            raise FederationTransportError("relay event does not exist") from exc
        if not 1 <= size <= self.max_blob_bytes:
            raise FederationTransportError("relay event exceeds the configured size limit")
        encoded = target.read_bytes()
        if len(encoded) != size:
            raise FederationTransportError("relay event changed during bounded read")
        try:
            envelope = parse_event_envelope(encoded)
        except (TypeError, ValueError) as exc:
            raise FederationTransportError("relay event digest or envelope is invalid") from exc
        if envelope.space_id != space_id or envelope.event_id != event_id:
            raise FederationTransportError("relay event digest or routing identity is invalid")
        if hashlib.sha256(envelope.ciphertext).hexdigest() != envelope.ciphertext_sha256:
            raise FederationTransportError("relay event ciphertext digest is invalid")
        return envelope


def _row_envelope(row: sqlite3.Row) -> FederationEventEnvelope:
    return FederationEventEnvelope(
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


def _require_sync(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    actor_peer_id: str,
) -> None:
    authority = authorize_operation(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        peer_id=actor_peer_id,
        operation="sync",
    )
    if not authority["allowed"]:
        raise FederationAuthorizationError(
            f"sync requires an active scope capability: {authority['reason']}"
        )


def push_to_relay(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    actor_peer_id: str,
    relay: FederationRelay,
    preview: bool = False,
) -> dict[str, object]:
    """Preview or publish accepted encrypted events from one authorized scope."""

    _require_sync(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        actor_peer_id=actor_peer_id,
    )
    rows = list(
        conn.execute(
            """
            SELECT e.* FROM federation_events e
            JOIN federation_event_validation v ON v.event_row_id = e.id
            WHERE e.project_id = ? AND e.space_id = ? AND e.scope_id = ?
              AND v.validation_state = 'accepted'
            ORDER BY e.event_id
            LIMIT ?
            """,
            (project_id, space_id, scope_id, MAX_RELAY_OBJECTS + 1),
        )
    )
    if len(rows) > MAX_RELAY_OBJECTS:
        raise FederationTransportError("outbound sync exceeds the bounded object limit")
    envelopes = [_row_envelope(row) for row in rows]
    if preview:
        return {
            "state": "preview",
            "event_count": len(envelopes),
            "event_ids": [item.event_id for item in envelopes],
            "bytes": sum(len(item.encoded) for item in envelopes),
        }
    receipts = [relay.put_event(envelope) for envelope in envelopes]
    return {
        "state": "complete",
        "event_count": len(receipts),
        "stored": sum(item["state"] == "stored" for item in receipts),
        "already_present": sum(item["state"] == "already_present" for item in receipts),
    }


def pull_from_relay(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    actor_peer_id: str,
    relay: FederationRelay,
    transport_id: str,
    limit: int = MAX_RELAY_OBJECTS,
    preview: bool = False,
) -> dict[str, object]:
    """Preview or pull missing opaque events with a resumable local cursor receipt."""

    _require_sync(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        actor_peer_id=actor_peer_id,
    )
    selected_transport = str(transport_id).strip()
    if not 1 <= len(selected_transport) <= 256 or "\0" in selected_transport:
        raise ValueError("transport_id must be a bounded string")
    selected_limit = int(limit)
    if not 1 <= selected_limit <= MAX_RELAY_OBJECTS:
        raise ValueError("limit is outside the bounded sync range")
    known = tuple(
        str(row[0])
        for row in conn.execute(
            "SELECT event_id FROM federation_events WHERE project_id = ? AND space_id = ?",
            (project_id, space_id),
        )
    )
    inventory = relay.inventory(space_id, scope_id=scope_id)
    missing_ids = sorted(set(inventory) - set(known))
    selected_ids = missing_ids[:selected_limit]
    selected = [relay.get_event(space_id, event_id) for event_id in selected_ids]
    inventory_digest = hashlib.sha256(
        canonical_json_bytes({"scope_id": scope_id, "event_ids": inventory})
    ).hexdigest()
    state = "partial" if len(missing_ids) > len(selected) else "complete"
    if preview:
        return {
            "state": "preview",
            "available": len(missing_ids),
            "selected": len(selected),
            "event_ids": [item.event_id for item in selected],
            "inventory_digest": inventory_digest,
        }
    savepoint = "federation_pull"
    conn.execute(f"SAVEPOINT {savepoint}")
    try:
        receipts = [
            store_event(conn, project_id=project_id, envelope=item, commit=False)
            for item in selected
        ]
        cursor = selected[-1].event_id if selected else inventory_digest
        conn.execute(
            """
            INSERT INTO federation_sync_cursors(
                project_id, space_id, transport_id, cursor,
                inventory_digest, state, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(project_id, space_id, transport_id) DO UPDATE SET
                cursor = excluded.cursor,
                inventory_digest = excluded.inventory_digest,
                state = excluded.state,
                updated_at = excluded.updated_at
            """,
            (project_id, space_id, selected_transport, cursor, inventory_digest, state),
        )
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise
    return {
        "state": state,
        "available": len(missing_ids),
        "received": len(receipts),
        "duplicates": sum(item["state"] == "duplicate" for item in receipts),
        "event_ids": [item.event_id for item in selected],
        "inventory_digest": inventory_digest,
    }


def pull_and_validate_from_relay(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    actor: FederationIdentity,
    relay: FederationRelay,
    transport_id: str,
    limit: int = MAX_RELAY_OBJECTS,
    preview: bool = False,
) -> dict[str, object]:
    """Pull and cryptographically accept events using the recipient's epoch keys."""

    if preview:
        return pull_from_relay(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            actor_peer_id=actor.identity_id,
            relay=relay,
            transport_id=transport_id,
            limit=limit,
            preview=True,
        )

    savepoint = "federation_pull_validate"
    conn.execute(f"SAVEPOINT {savepoint}")
    savepoint_active = True
    try:
        result = pull_from_relay(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            actor_peer_id=actor.identity_id,
            relay=relay,
            transport_id=transport_id,
            limit=limit,
        )
        candidates = {
            str(row["event_id"])
            for row in conn.execute(
                """
                SELECT e.event_id FROM federation_events e
                JOIN federation_event_validation v ON v.event_row_id = e.id
                WHERE e.project_id = ? AND e.space_id = ? AND e.scope_id = ?
                  AND v.validation_state IN ('received', 'pending_parent')
                """,
                (project_id, space_id, scope_id),
            )
        }
        ordered = [
            item["event_id"]
            for item in deterministic_event_order(
                conn,
                project_id=project_id,
                space_id=space_id,
            )
            if item["event_id"] in candidates and item["scope_id"] == scope_id
        ]
        accepted = 0
        quarantined = 0
        key_cache: dict[int, bytes] = {}
        for event_id in ordered:
            row = conn.execute(
                "SELECT * FROM federation_events WHERE project_id = ? AND space_id = ? AND event_id = ?",
                (project_id, space_id, event_id),
            ).fetchone()
            if row is None:
                raise FederationTransportError("received event is missing from local storage")
            envelope = _row_envelope(row)
            author = conn.execute(
                "SELECT signing_public_key FROM federation_peers "
                "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
                (project_id, space_id, envelope.author_peer_id),
            ).fetchone()
            if envelope.epoch not in key_cache:
                try:
                    key_cache[envelope.epoch] = open_scope_key_for_epoch(
                        conn,
                        project_id=project_id,
                        space_id=space_id,
                        scope_id=scope_id,
                        epoch=envelope.epoch,
                        recipient=actor,
                    )
                except FederationAuthorizationError:
                    quarantine_stored_event(
                        conn,
                        project_id=project_id,
                        event_id=event_id,
                        reason="key_epoch_unavailable",
                        commit=False,
                    )
                    quarantined += 1
                    continue
            try:
                validation = validate_and_accept_event(
                    conn,
                    project_id=project_id,
                    envelope=envelope,
                    author_signing_public_key=(
                        bytes(author["signing_public_key"]) if author is not None else b""
                    ),
                    scope_key=key_cache[envelope.epoch],
                    commit=False,
                )
            except (FederationAuthorizationError, FederationCryptoError):
                state = conn.execute(
                    "SELECT v.validation_state FROM federation_events e "
                    "JOIN federation_event_validation v ON v.event_row_id = e.id "
                    "WHERE e.project_id = ? AND e.space_id = ? AND e.event_id = ?",
                    (project_id, space_id, event_id),
                ).fetchone()
                if state is None or str(state["validation_state"]) != "quarantined":
                    raise
                quarantined += 1
                continue
            accepted += validation["state"] == "accepted"
        pending_parent = int(
            conn.execute(
                """
                SELECT COUNT(*) FROM federation_events e
                JOIN federation_event_validation v ON v.event_row_id = e.id
                WHERE e.project_id = ? AND e.space_id = ? AND e.scope_id = ?
                  AND v.validation_state = 'pending_parent'
                """,
                (project_id, space_id, scope_id),
            ).fetchone()[0]
        )
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        savepoint_active = False
        conn.commit()
    except Exception:
        if savepoint_active:
            conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        else:
            conn.rollback()
        raise
    return {
        **result,
        "state": "partial" if pending_parent else result["state"],
        "accepted": accepted,
        "quarantined": quarantined,
        "pending_parent": pending_parent,
    }


def verify_relay_sync(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    actor_peer_id: str,
    relay: FederationRelay,
) -> dict[str, object]:
    """Compare one authorized local scope with an opaque relay without writing."""

    _require_sync(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        actor_peer_id=actor_peer_id,
    )
    local_ids = {
        str(row[0])
        for row in conn.execute(
            """
            SELECT e.event_id FROM federation_events e
            JOIN federation_event_validation v ON v.event_row_id = e.id
            WHERE e.project_id = ? AND e.space_id = ? AND e.scope_id = ?
              AND v.validation_state = 'accepted'
            """,
            (project_id, space_id, scope_id),
        )
    }
    relay_inventory = relay.inventory(space_id)
    relay_ids: set[str] = set()
    for event_id in relay_inventory:
        envelope = relay.get_event(space_id, event_id)
        if envelope.scope_id == scope_id:
            relay_ids.add(envelope.event_id)
    local_only = local_ids - relay_ids
    relay_only = relay_ids - local_ids
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "local": sorted(local_ids),
                "relay": sorted(relay_ids),
                "scope_id": scope_id,
            }
        )
    ).hexdigest()
    return {
        "state": "healthy" if not local_only and not relay_only else "partial",
        "local_event_count": len(local_ids),
        "relay_event_count": len(relay_ids),
        "local_only_count": len(local_only),
        "relay_only_count": len(relay_only),
        "comparison_digest": digest,
        "writes_performed": False,
    }


def preview_sync_operation(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    actor: FederationIdentity,
    relay: FederationRelay,
    action: str,
    transport_id: str,
    limit: int = MAX_RELAY_OBJECTS,
) -> dict[str, object]:
    """Bind one path-free synchronization operation to current local and relay state."""

    selected_action = str(action).strip().casefold()
    if selected_action not in {"push", "pull", "repair"}:
        raise ValueError("federation sync action is unsupported")
    details: dict[str, object] = {}
    if selected_action in {"push", "repair"}:
        details["push"] = push_to_relay(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            actor_peer_id=actor.identity_id,
            relay=relay,
            preview=True,
        )
    if selected_action in {"pull", "repair"}:
        details["pull"] = pull_and_validate_from_relay(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            actor=actor,
            relay=relay,
            transport_id=transport_id,
            limit=limit,
            preview=True,
        )
    intent = {
        "action": selected_action,
        "actor_peer_id": actor.identity_id,
        "details": details,
        "limit": int(limit),
        "project_id": int(project_id),
        "scope_id": scope_id,
        "space_id": space_id,
        "transport_id": str(transport_id),
    }
    confirmation = hashlib.sha256(
        b"rta-smriti-federation-sync-preview-v1\0" + canonical_json_bytes(intent)
    ).hexdigest()
    primary = details.get(selected_action, {})
    return {
        **primary,
        "state": "preview",
        "action": selected_action,
        "details": details,
        "confirmation_digest": confirmation,
        "writes_performed": False,
    }


def apply_sync_operation(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    actor: FederationIdentity,
    relay: FederationRelay,
    action: str,
    transport_id: str,
    confirmation_digest: str,
    limit: int = MAX_RELAY_OBJECTS,
) -> dict[str, object]:
    """Apply only the exact local and relay synchronization state just previewed."""

    plan = preview_sync_operation(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        actor=actor,
        relay=relay,
        action=action,
        transport_id=transport_id,
        limit=limit,
    )
    if not hmac.compare_digest(
        str(confirmation_digest), str(plan["confirmation_digest"])
    ):
        raise FederationTransportError("federation sync changed after preview")
    selected_action = str(plan["action"])
    if selected_action == "push":
        return push_to_relay(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            actor_peer_id=actor.identity_id,
            relay=relay,
        )
    if selected_action == "pull":
        return pull_and_validate_from_relay(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            actor=actor,
            relay=relay,
            transport_id=transport_id,
            limit=limit,
        )
    pulled = pull_and_validate_from_relay(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        actor=actor,
        relay=relay,
        transport_id=transport_id,
        limit=limit,
    )
    pushed = push_to_relay(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        actor_peer_id=actor.identity_id,
        relay=relay,
    )
    verified = verify_relay_sync(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        actor_peer_id=actor.identity_id,
        relay=relay,
    )
    return {
        **verified,
        "action": "repair",
        "pulled": pulled["received"],
        "accepted": pulled["accepted"],
        "pushed": pushed["stored"],
        "already_present": pushed["already_present"],
    }
