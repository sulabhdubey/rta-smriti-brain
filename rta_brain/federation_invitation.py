"""Recipient-encrypted, owner-signed federation onboarding bundles."""

from __future__ import annotations

import base64
import hashlib
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .federation_crypto import (
    FederationIdentity,
    PublicFederationIdentity,
    export_public_identity,
    generate_scope_key,
    import_public_identity,
    open_scope_key,
    public_identity_from_keys,
    seal_scope_key,
)
from .federation_governance import (
    authorize_operation,
    export_capability_event,
    import_capability_event,
)
from .federation_types import canonical_json_bytes, parse_canonical_json

MAX_INVITATION_BYTES = 4 * 1024 * 1024
_SCHEMA = "rta-smriti.federation-invitation/v1"
_PAYLOAD_SCHEMA = "rta-smriti.federation-invitation-payload/v1"


class FederationInvitationError(ValueError):
    """An invitation failed audience, integrity, expiry, or import validation."""


def _now() -> datetime:
    return datetime.now(UTC)


def _now_iso() -> str:
    return _now().replace(microsecond=0).isoformat()


def _timestamp(value: Any, *, name: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise FederationInvitationError(f"invitation {name} is invalid")
    try:
        selected = datetime.fromisoformat(value)
    except ValueError as exc:
        raise FederationInvitationError(f"invitation {name} is invalid") from exc
    if selected.tzinfo is None:
        raise FederationInvitationError(f"invitation {name} must include a timezone")
    return selected.astimezone(UTC)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: Any, *, name: str, exact: int | None = None) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as exc:
        raise FederationInvitationError(f"invitation {name} is invalid") from exc
    if exact is not None and len(decoded) != exact:
        raise FederationInvitationError(f"invitation {name} is invalid")
    return decoded


def _invitation_scope_id(space_id: str, recipient_peer_id: str) -> str:
    return hashlib.sha256(
        f"rta-smriti-invitation\0{space_id}\0{recipient_peer_id}".encode("ascii")
    ).hexdigest()


def create_invitation_bundle(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    author: FederationIdentity,
    recipient: PublicFederationIdentity,
    scope_ids: tuple[str, ...],
    expires_at: str,
    commit: bool = True,
) -> bytes:
    """Create a selective onboarding package for an already-approved peer."""

    expiry = _timestamp(expires_at, name="expiry")
    issued = _now()
    if expiry <= issued or expiry - issued > timedelta(days=30):
        raise FederationInvitationError("invitation expiry must be within 30 days")
    selected_scopes = tuple(sorted(set(scope_ids)))
    if not selected_scopes or len(selected_scopes) != len(scope_ids) or len(selected_scopes) > 100:
        raise FederationInvitationError("invitation scopes must be a bounded unique tuple")
    space = conn.execute(
        "SELECT wire_schema, owner_peer_id, created_at FROM federation_spaces "
        "WHERE project_id = ? AND space_id = ?",
        (project_id, space_id),
    ).fetchone()
    if space is None or str(space["owner_peer_id"]) != author.identity_id:
        raise FederationInvitationError("invitation must be issued by the space owner")
    admin = authorize_operation(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=None,
        peer_id=author.identity_id,
        operation="admin",
    )
    if not admin["allowed"]:
        raise FederationInvitationError("invitation author is not an active administrator")
    recipient_row = conn.execute(
        "SELECT 1 FROM federation_peers WHERE project_id = ? AND space_id = ? AND peer_id = ?",
        (project_id, space_id, recipient.identity_id),
    ).fetchone()
    if recipient_row is None:
        raise FederationInvitationError("invitation recipient is not an approved peer")
    placeholders = ",".join("?" for _ in selected_scopes)
    scopes = list(
        conn.execute(
            f"SELECT scope_id, scope_kind, label, created_by_peer_id, created_at "  # nosec B608 - placeholder count only
            f"FROM federation_scopes WHERE project_id = ? AND space_id = ? "
            f"AND scope_id IN ({placeholders}) ORDER BY scope_id",
            (project_id, space_id, *selected_scopes),
        )
    )
    if len(scopes) != len(selected_scopes):
        raise FederationInvitationError("invitation contains an unknown scope")
    for scope_id in selected_scopes:
        access = authorize_operation(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=scope_id,
            peer_id=recipient.identity_id,
            operation="read",
        )
        if not access["allowed"]:
            raise FederationInvitationError("invitation recipient lacks scope access")

    peers = list(
        conn.execute(
            "SELECT peer_id, label, signing_public_key, envelope_public_key, added_at "
            "FROM federation_peers WHERE project_id = ? AND space_id = ? ORDER BY peer_id",
            (project_id, space_id),
        )
    )
    capability_rows = list(
        conn.execute(
            f"SELECT event_id FROM federation_capability_events "  # nosec B608 - placeholder count only
            f"WHERE project_id = ? AND space_id = ? "
            f"AND (scope_id IS NULL OR scope_id IN ({placeholders})) "
            f"ORDER BY id LIMIT 2001",
            (project_id, space_id, *selected_scopes),
        )
    )
    if len(peers) > 256 or len(capability_rows) > 2000:
        raise FederationInvitationError("invitation governance inventory exceeds its bound")
    epochs = list(
        conn.execute(
            f"SELECT scope_id, epoch, rotation_event_id, key_digest, created_at "  # nosec B608 - placeholder count only
            f"FROM federation_scope_epochs WHERE project_id = ? AND space_id = ? "
            f"AND scope_id IN ({placeholders}) ORDER BY scope_id, epoch",
            (project_id, space_id, *selected_scopes),
        )
    )
    envelopes = list(
        conn.execute(
            f"SELECT scope_id, epoch, envelope_id, recipient_peer_id, issuer_peer_id, "  # nosec B608 - placeholder count only
            f"hpke_ciphertext, envelope_digest, signature, created_at "
            f"FROM federation_key_envelopes WHERE project_id = ? AND space_id = ? "
            f"AND scope_id IN ({placeholders}) AND recipient_peer_id = ? "
            f"ORDER BY scope_id, epoch",
            (project_id, space_id, *selected_scopes, recipient.identity_id),
        )
    )
    latest_scopes = {str(row["scope_id"]) for row in envelopes}
    if latest_scopes != set(selected_scopes):
        raise FederationInvitationError("invitation scope key is unavailable for recipient")
    payload = {
        "capability_events": [
            parse_canonical_json(
                export_capability_event(
                    conn,
                    project_id=project_id,
                    space_id=space_id,
                    event_id=str(row["event_id"]),
                )
            )
            for row in capability_rows
        ],
        "epochs": [dict(row) for row in epochs],
        "key_envelopes": [
            {
                **{
                    key: row[key]
                    for key in row.keys()  # noqa: SIM118 - sqlite3.Row key API
                    if key not in {"hpke_ciphertext", "signature"}
                },
                "hpke_ciphertext": _b64(bytes(row["hpke_ciphertext"])),
                "signature": _b64(bytes(row["signature"])),
            }
            for row in envelopes
        ],
        "peers": [
            {
                "added_at": str(row["added_at"]),
                "envelope_public_key": _b64(bytes(row["envelope_public_key"])),
                "label": str(row["label"]),
                "peer_id": str(row["peer_id"]),
                "signing_public_key": _b64(bytes(row["signing_public_key"])),
            }
            for row in peers
        ],
        "schema": _PAYLOAD_SCHEMA,
        "scopes": [dict(row) for row in scopes],
        "space": dict(space),
    }
    plaintext = canonical_json_bytes(payload, max_bytes=MAX_INVITATION_BYTES // 2)
    issued_at = issued.replace(microsecond=0).isoformat()
    header = {
        "author_identity": _b64(export_public_identity(author)),
        "author_peer_id": author.identity_id,
        "expires_at": expiry.replace(microsecond=0).isoformat(),
        "issued_at": issued_at,
        "recipient_peer_id": recipient.identity_id,
        "schema": _SCHEMA,
        "space_id": space_id,
    }
    aad = canonical_json_bytes(header)
    bundle_key = generate_scope_key()
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(bundle_key).encrypt(nonce, plaintext, aad)
    sealed = seal_scope_key(
        bundle_key,
        recipient_public_key=recipient.envelope_public_bytes,
        space_id=space_id,
        scope_id=_invitation_scope_id(space_id, recipient.identity_id),
        epoch=1,
        recipient_peer_id=recipient.identity_id,
    )
    body = {
        **header,
        "ciphertext": _b64(ciphertext),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "hpke_key_envelope": _b64(sealed),
        "nonce": _b64(nonce),
    }
    invitation_id = hashlib.sha256(
        b"rta-smriti-invitation-v1\0" + canonical_json_bytes(body, max_bytes=MAX_INVITATION_BYTES)
    ).hexdigest()
    signature = author.signing_private_key.sign(
        canonical_json_bytes({**body, "invitation_id": invitation_id}, max_bytes=MAX_INVITATION_BYTES)
    )
    encoded = canonical_json_bytes(
        {**body, "invitation_id": invitation_id, "signature": _b64(signature)},
        max_bytes=MAX_INVITATION_BYTES,
    )
    conn.execute(
        "INSERT INTO federation_invitation_receipts(project_id, space_id, invitation_id, "
        "direction, action, peer_id, bundle_digest, recorded_at) "
        "VALUES (?, ?, ?, 'outbound', 'issued', ?, ?, ?)",
        (
            project_id,
            space_id,
            invitation_id,
            recipient.identity_id,
            hashlib.sha256(encoded).hexdigest(),
            _now_iso(),
        ),
    )
    if commit:
        conn.commit()
    return encoded


def _open_invitation(
    encoded: bytes,
    recipient: FederationIdentity,
    *,
    allow_expired: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], PublicFederationIdentity]:
    try:
        value = parse_canonical_json(encoded, max_bytes=MAX_INVITATION_BYTES)
        expected = {
            "author_identity", "author_peer_id", "ciphertext", "ciphertext_sha256",
            "expires_at", "hpke_key_envelope", "invitation_id", "issued_at", "nonce",
            "recipient_peer_id", "schema", "signature", "space_id",
        }
        if not isinstance(value, dict) or set(value) != expected or value["schema"] != _SCHEMA:
            raise FederationInvitationError("invitation fields are invalid")
        if value["recipient_peer_id"] != recipient.identity_id:
            raise FederationInvitationError("invitation recipient does not match this device")
        issued = _timestamp(value["issued_at"], name="issue time")
        expiry = _timestamp(value["expires_at"], name="expiry")
        if expiry <= issued or (not allow_expired and _now() >= expiry):
            raise FederationInvitationError("invitation has expired")
        author = import_public_identity(_unb64(value["author_identity"], name="author identity"))
        if value["author_peer_id"] != author.identity_id:
            raise FederationInvitationError("invitation author identity does not match")
        body = {key: item for key, item in value.items() if key not in {"invitation_id", "signature"}}
        invitation_id = hashlib.sha256(
            b"rta-smriti-invitation-v1\0" + canonical_json_bytes(body, max_bytes=MAX_INVITATION_BYTES)
        ).hexdigest()
        if value["invitation_id"] != invitation_id:
            raise FederationInvitationError("invitation identity is invalid")
        Ed25519PublicKey.from_public_bytes(author.signing_public_bytes).verify(
            _unb64(value["signature"], name="signature", exact=64),
            canonical_json_bytes({**body, "invitation_id": invitation_id}, max_bytes=MAX_INVITATION_BYTES),
        )
        ciphertext = _unb64(value["ciphertext"], name="ciphertext")
        if hashlib.sha256(ciphertext).hexdigest() != value["ciphertext_sha256"]:
            raise FederationInvitationError("invitation ciphertext digest is invalid")
        bundle_key = open_scope_key(
            _unb64(value["hpke_key_envelope"], name="key envelope"),
            recipient_private_key=recipient.envelope_private_key,
            space_id=str(value["space_id"]),
            scope_id=_invitation_scope_id(str(value["space_id"]), recipient.identity_id),
            epoch=1,
            recipient_peer_id=recipient.identity_id,
        )
        header = {key: value[key] for key in (
            "author_identity", "author_peer_id", "expires_at", "issued_at",
            "recipient_peer_id", "schema", "space_id",
        )}
        plaintext = ChaCha20Poly1305(bundle_key).decrypt(
            _unb64(value["nonce"], name="nonce", exact=12),
            ciphertext,
            canonical_json_bytes(header),
        )
        payload = parse_canonical_json(plaintext, max_bytes=MAX_INVITATION_BYTES // 2)
        if not isinstance(payload, dict) or set(payload) != {
            "capability_events", "epochs", "key_envelopes", "peers", "schema", "scopes", "space"
        } or payload["schema"] != _PAYLOAD_SCHEMA:
            raise FederationInvitationError("invitation payload is invalid")
        return value, payload, author
    except FederationInvitationError:
        raise
    except (TypeError, ValueError, InvalidSignature, InvalidTag) as exc:
        raise FederationInvitationError("invitation verification failed") from exc


def preview_invitation_bundle(encoded: bytes, *, recipient: FederationIdentity) -> dict[str, Any]:
    value, payload, author = _open_invitation(encoded, recipient)
    return {
        "state": "valid",
        "invitation_id": value["invitation_id"],
        "space_id": value["space_id"],
        "author_peer_id": author.identity_id,
        "recipient_peer_id": recipient.identity_id,
        "scope_count": len(payload["scopes"]),
        "peer_count": len(payload["peers"]),
        "expires_at": value["expires_at"],
        "requires_fingerprint_verification": True,
        "warning": "Public-key fingerprints identify devices, not verified people.",
    }


def _record_inbound_disposition(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    encoded: bytes,
    recipient: FederationIdentity,
    action: str,
) -> dict[str, Any]:
    if action not in {"rejected", "expired"}:
        raise ValueError("invitation disposition is invalid")
    value, _, _ = _open_invitation(
        encoded,
        recipient,
        allow_expired=action == "expired",
    )
    expired = _now() >= _timestamp(value["expires_at"], name="expiry")
    if action == "expired" and not expired:
        raise FederationInvitationError("invitation has not expired")
    digest = hashlib.sha256(encoded).hexdigest()
    conn.execute(
        "INSERT OR IGNORE INTO federation_invitation_receipts(project_id, space_id, "
        "invitation_id, direction, action, peer_id, bundle_digest, recorded_at) "
        "VALUES (?, ?, ?, 'inbound', ?, ?, ?, ?)",
        (
            project_id,
            value["space_id"],
            value["invitation_id"],
            action,
            recipient.identity_id,
            digest,
            _now_iso(),
        ),
    )
    conn.commit()
    return {
        "state": action,
        "invitation_id": value["invitation_id"],
        "space_id": value["space_id"],
        "bundle_digest": digest,
    }


def reject_invitation_bundle(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    encoded: bytes,
    recipient: FederationIdentity,
) -> dict[str, Any]:
    """Verify and record an explicit local rejection without enrolling the space."""

    return _record_inbound_disposition(
        conn,
        project_id=project_id,
        encoded=encoded,
        recipient=recipient,
        action="rejected",
    )


def expire_invitation_bundle(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    encoded: bytes,
    recipient: FederationIdentity,
) -> dict[str, Any]:
    """Verify and record a locally observed invitation expiry."""

    return _record_inbound_disposition(
        conn,
        project_id=project_id,
        encoded=encoded,
        recipient=recipient,
        action="expired",
    )


def accept_invitation_bundle(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    encoded: bytes,
    recipient: FederationIdentity,
    recipient_key_reference: str,
    _refresh_existing: bool = False,
) -> dict[str, Any]:
    value, payload, author = _open_invitation(encoded, recipient)
    space_id = str(value["space_id"])
    existing_space = conn.execute(
        "SELECT wire_schema, owner_peer_id FROM federation_spaces "
        "WHERE project_id = ? AND space_id = ?",
        (project_id, space_id),
    ).fetchone()
    if existing_space is not None and not _refresh_existing:
        raise FederationInvitationError("invitation space is already enrolled")
    peers = payload["peers"]
    scopes = payload["scopes"]
    events = payload["capability_events"]
    epochs = payload["epochs"]
    envelopes = payload["key_envelopes"]
    if not all(isinstance(items, list) for items in (peers, scopes, events, epochs, envelopes)):
        raise FederationInvitationError("invitation collections are invalid")
    if len(peers) > 256 or len(scopes) > 100 or len(events) > 2000 or len(epochs) > 1000 or len(envelopes) > 1000:
        raise FederationInvitationError("invitation collection exceeds its bound")
    space = payload["space"]
    if not isinstance(space, dict) or set(space) != {"wire_schema", "owner_peer_id", "created_at"}:
        raise FederationInvitationError("invitation space record is invalid")
    if space["owner_peer_id"] != author.identity_id or space["wire_schema"] != "rta-smriti.federation/v1":
        raise FederationInvitationError("invitation space authority is invalid")
    owns_transaction = not conn.in_transaction
    savepoint = "federation_invitation_accept"
    try:
        if owns_transaction:
            conn.execute("BEGIN IMMEDIATE")
        else:
            conn.execute(f"SAVEPOINT {savepoint}")
        for identity, key_reference in (
            (author, f"remote:{author.identity_id}"),
            (
                PublicFederationIdentity(
                    recipient.identity_id,
                    recipient.signing_public_bytes,
                    recipient.envelope_public_bytes,
                ),
                recipient_key_reference,
            ),
        ):
            conn.execute(
                "INSERT OR IGNORE INTO federation_identities(project_id, identity_id, "
                "signing_public_key, envelope_public_key, key_fingerprint, key_reference, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    project_id, identity.identity_id, identity.signing_public_bytes,
                    identity.envelope_public_bytes, identity.identity_id, key_reference, _now_iso(),
                ),
            )
        if existing_space is None:
            conn.execute(
                "INSERT INTO federation_spaces(project_id, space_id, wire_schema, owner_peer_id, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (project_id, space_id, space["wire_schema"], space["owner_peer_id"], space["created_at"]),
            )
        elif (
            str(existing_space["wire_schema"]) != str(space["wire_schema"])
            or str(existing_space["owner_peer_id"]) != str(space["owner_peer_id"])
        ):
            raise FederationInvitationError("invitation conflicts with the enrolled space")
        if _refresh_existing:
            current_authority = authorize_operation(
                conn,
                project_id=project_id,
                space_id=space_id,
                scope_id=None,
                peer_id=author.identity_id,
                operation="admin",
            )
            if not current_authority["allowed"]:
                raise FederationInvitationError(
                    "invitation owner is not currently authorized to refresh enrollment"
                )
        imported_peers: set[str] = set()
        for peer in peers:
            signing = _unb64(peer.get("signing_public_key"), name="peer signing key", exact=32)
            envelope = _unb64(peer.get("envelope_public_key"), name="peer envelope key", exact=32)
            public = public_identity_from_keys(signing, envelope)
            if peer.get("peer_id") != public.identity_id:
                raise FederationInvitationError("invitation peer fingerprint is invalid")
            existing_peer = conn.execute(
                "SELECT label, signing_public_key, envelope_public_key FROM federation_peers "
                "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
                (project_id, space_id, public.identity_id),
            ).fetchone()
            if existing_peer is None:
                conn.execute(
                    "INSERT INTO federation_peers(project_id, space_id, peer_id, label, "
                "signing_public_key, envelope_public_key, added_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        project_id, space_id, public.identity_id, str(peer.get("label")),
                        signing, envelope, str(peer.get("added_at")),
                    ),
                )
            elif (
                bytes(existing_peer["signing_public_key"]) != signing
                or bytes(existing_peer["envelope_public_key"]) != envelope
            ):
                raise FederationInvitationError("invitation peer conflicts with enrolled identity")
            imported_peers.add(public.identity_id)
        if {author.identity_id, recipient.identity_id} - imported_peers:
            raise FederationInvitationError("invitation omits a required peer")
        scope_ids: set[str] = set()
        for scope in scopes:
            scope_id = str(scope.get("scope_id"))
            existing_scope = conn.execute(
                "SELECT scope_kind, label, created_by_peer_id FROM federation_scopes "
                "WHERE project_id = ? AND space_id = ? AND scope_id = ?",
                (project_id, space_id, scope_id),
            ).fetchone()
            expected_scope = (
                str(scope.get("scope_kind")),
                str(scope.get("label")),
                str(scope.get("created_by_peer_id")),
            )
            if existing_scope is None:
                conn.execute(
                    "INSERT INTO federation_scopes(project_id, space_id, scope_id, scope_kind, label, "
                    "created_by_peer_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        project_id, space_id, scope_id, *expected_scope,
                        str(scope.get("created_at")),
                    ),
                )
            elif tuple(str(existing_scope[key]) for key in ("scope_kind", "label", "created_by_peer_id")) != expected_scope:
                raise FederationInvitationError("invitation scope conflicts with enrolled scope")
            scope_ids.add(scope_id)
        for event in events:
            import_capability_event(
                conn,
                project_id=project_id,
                space_id=space_id,
                encoded=canonical_json_bytes(event),
                commit=False,
            )
        epoch_digests: dict[tuple[str, int], str] = {}
        for epoch in epochs:
            scope_id = str(epoch.get("scope_id"))
            selected_epoch = int(epoch.get("epoch"))
            if scope_id not in scope_ids:
                raise FederationInvitationError("invitation epoch is outside selected scopes")
            rotation_event_id = str(epoch.get("rotation_event_id"))
            key_digest = str(epoch.get("key_digest"))
            rotation_event = conn.execute(
                "SELECT action, scope_id FROM federation_capability_events "
                "WHERE project_id = ? AND space_id = ? AND event_id = ?",
                (project_id, space_id, rotation_event_id),
            ).fetchone()
            if (
                rotation_event is None
                or str(rotation_event["action"]) != "rotate"
                or str(rotation_event["scope_id"]) != scope_id
            ):
                raise FederationInvitationError(
                    "invitation epoch is missing its authorized rotation event"
                )
            existing_epoch = conn.execute(
                "SELECT rotation_event_id, key_digest FROM federation_scope_epochs "
                "WHERE project_id = ? AND space_id = ? AND scope_id = ? AND epoch = ?",
                (project_id, space_id, scope_id, selected_epoch),
            ).fetchone()
            if existing_epoch is None:
                conn.execute(
                    "INSERT INTO federation_scope_epochs(project_id, space_id, scope_id, epoch, "
                    "rotation_event_id, key_digest, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        project_id, space_id, scope_id, selected_epoch,
                        rotation_event_id, key_digest, str(epoch.get("created_at")),
                    ),
                )
            elif (
                str(existing_epoch["rotation_event_id"]) != rotation_event_id
                or str(existing_epoch["key_digest"]) != key_digest
            ):
                raise FederationInvitationError("invitation epoch conflicts with enrolled history")
            epoch_digests[(scope_id, selected_epoch)] = str(epoch.get("key_digest"))
        for envelope in envelopes:
            scope_id = str(envelope.get("scope_id"))
            epoch = int(envelope.get("epoch"))
            recipient_peer_id = str(envelope.get("recipient_peer_id"))
            issuer_peer_id = str(envelope.get("issuer_peer_id"))
            if recipient_peer_id != recipient.identity_id or (scope_id, epoch) not in epoch_digests:
                raise FederationInvitationError("invitation key envelope audience is invalid")
            sealed = _unb64(envelope.get("hpke_ciphertext"), name="scope key envelope")
            envelope_body = {
                "epoch": epoch,
                "hpke_ciphertext": _b64(sealed),
                "issuer_peer_id": issuer_peer_id,
                "recipient_peer_id": recipient_peer_id,
                "schema": "rta-smriti.scope-key-envelope/v1",
                "scope_id": scope_id,
                "space_id": space_id,
            }
            canonical = canonical_json_bytes(envelope_body)
            envelope_id = hashlib.sha256(b"rta-smriti-scope-envelope-v1\0" + canonical).hexdigest()
            if envelope.get("envelope_id") != envelope_id or envelope.get("envelope_digest") != hashlib.sha256(canonical).hexdigest():
                raise FederationInvitationError("invitation key envelope digest is invalid")
            issuer = next((peer for peer in peers if peer.get("peer_id") == issuer_peer_id), None)
            if issuer is None:
                raise FederationInvitationError("invitation key issuer is unknown")
            Ed25519PublicKey.from_public_bytes(
                _unb64(issuer.get("signing_public_key"), name="issuer key", exact=32)
            ).verify(
                _unb64(envelope.get("signature"), name="key signature", exact=64),
                canonical_json_bytes({**envelope_body, "envelope_id": envelope_id}),
            )
            scope_key = open_scope_key(
                sealed,
                recipient_private_key=recipient.envelope_private_key,
                space_id=space_id,
                scope_id=scope_id,
                epoch=epoch,
                recipient_peer_id=recipient.identity_id,
            )
            if hashlib.sha256(scope_key).hexdigest() != epoch_digests[(scope_id, epoch)]:
                raise FederationInvitationError("invitation scope key digest is invalid")
            signature = _unb64(envelope.get("signature"), name="key signature", exact=64)
            existing_envelope = conn.execute(
                "SELECT hpke_ciphertext, envelope_digest, signature FROM federation_key_envelopes "
                "WHERE project_id = ? AND space_id = ? AND scope_id = ? AND epoch = ? "
                "AND recipient_peer_id = ?",
                (project_id, space_id, scope_id, epoch, recipient_peer_id),
            ).fetchone()
            if existing_envelope is None:
                conn.execute(
                    "INSERT INTO federation_key_envelopes(project_id, space_id, scope_id, epoch, "
                "envelope_id, recipient_peer_id, issuer_peer_id, hpke_ciphertext, envelope_digest, "
                "signature, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        project_id, space_id, scope_id, epoch, envelope_id, recipient_peer_id,
                        issuer_peer_id, sealed, str(envelope.get("envelope_digest")),
                        signature, str(envelope.get("created_at")),
                    ),
                )
            elif (
                bytes(existing_envelope["hpke_ciphertext"]) != sealed
                or str(existing_envelope["envelope_digest"]) != str(envelope.get("envelope_digest"))
                or bytes(existing_envelope["signature"]) != signature
            ):
                raise FederationInvitationError("invitation key envelope conflicts with enrolled history")
        conn.execute(
            "INSERT INTO federation_invitation_receipts(project_id, space_id, invitation_id, "
            "direction, action, peer_id, bundle_digest, recorded_at) "
            "VALUES (?, ?, ?, 'inbound', 'accepted', ?, ?, ?)",
            (
                project_id, space_id, value["invitation_id"], recipient.identity_id,
                hashlib.sha256(encoded).hexdigest(), _now_iso(),
            ),
        )
        if owns_transaction:
            conn.commit()
        else:
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
    except (sqlite3.Error, TypeError, ValueError, InvalidSignature) as exc:
        if owns_transaction:
            conn.rollback()
        else:
            conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        if isinstance(exc, FederationInvitationError):
            raise
        raise FederationInvitationError("invitation import failed") from exc
    return {
        "state": "refreshed" if existing_space is not None else "accepted",
        "invitation_id": value["invitation_id"],
        "space_id": space_id,
        "scope_count": len(scope_ids),
        "peer_count": len(imported_peers),
        "requires_fingerprint_verification": True,
    }


def refresh_enrollment_bundle(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    encoded: bytes,
    recipient: FederationIdentity,
    recipient_key_reference: str,
) -> dict[str, Any]:
    """Apply an owner-signed encrypted control-plane refresh to an enrolled space."""

    return accept_invitation_bundle(
        conn,
        project_id=project_id,
        encoded=encoded,
        recipient=recipient,
        recipient_key_reference=recipient_key_reference,
        _refresh_existing=True,
    )
