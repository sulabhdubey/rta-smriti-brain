"""Signed, recipient-encrypted federation review bundles."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .federation import store_event
from .federation_crypto import (
    FederationIdentity,
    decrypt_event,
    generate_scope_key,
    open_scope_key,
    seal_scope_key,
)
from .federation_governance import (
    authorize_operation,
    open_scope_key_for_epoch,
    validate_and_accept_event,
)
from .federation_operator import _state_digest
from .federation_types import (
    FederationEventEnvelope,
    canonical_json_bytes,
    parse_canonical_json,
    parse_event_envelope,
)

MAX_FEDERATION_BUNDLE_BYTES = 8 * 1024 * 1024
_PRIVACY = frozenset({"public", "internal", "sensitive", "restricted"})
_PRIVACY_RANK = {"public": 0, "internal": 1, "sensitive": 2, "restricted": 3}


class FederationBundleError(ValueError):
    """A federation review bundle failed audience, integrity, or decryption checks."""


def _stored_envelope(row: sqlite3.Row) -> FederationEventEnvelope:
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


def _review_export_selection(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    scope_id: str,
    actor: FederationIdentity,
    recipient_peer_id: str,
    event_ids: tuple[str, ...],
    privacy_ceiling: str,
) -> dict[str, Any]:
    selected_space = _hex_id("space_id", space_id)
    selected_scope = _hex_id("scope_id", scope_id)
    selected_recipient = _hex_id("recipient_peer_id", recipient_peer_id)
    ceiling = str(privacy_ceiling).strip().casefold()
    if ceiling not in _PRIVACY:
        raise ValueError("privacy ceiling is invalid")
    if (
        not isinstance(event_ids, tuple)
        or not event_ids
        or len(event_ids) > 10_000
        or len(set(event_ids)) != len(event_ids)
    ):
        raise ValueError("event_ids must be a bounded unique non-empty tuple")
    authority = authorize_operation(
        conn,
        project_id=project_id,
        space_id=selected_space,
        scope_id=selected_scope,
        peer_id=actor.identity_id,
        operation="export",
    )
    if not authority["allowed"]:
        raise FederationBundleError(
            f"review export requires an active scope capability: {authority['reason']}"
        )
    recipient_authority = authorize_operation(
        conn,
        project_id=project_id,
        space_id=selected_space,
        scope_id=selected_scope,
        peer_id=selected_recipient,
        operation="read",
    )
    if not recipient_authority["allowed"]:
        raise FederationBundleError(
            "review bundle recipient requires current scope read access"
        )
    recipient = conn.execute(
        "SELECT envelope_public_key FROM federation_peers "
        "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
        (project_id, selected_space, selected_recipient),
    ).fetchone()
    if recipient is None:
        raise FederationBundleError("review bundle recipient is not an approved peer")

    included: list[FederationEventEnvelope] = []
    excluded: list[dict[str, str]] = []
    key_cache: dict[int, bytes] = {}
    for event_id in event_ids:
        selected_event = _hex_id("event_id", event_id)
        row = conn.execute(
            "SELECT e.* FROM federation_events e "
            "JOIN federation_event_validation v ON v.event_row_id = e.id "
            "WHERE e.project_id = ? AND e.space_id = ? AND e.scope_id = ? "
            "AND e.event_id = ? AND v.validation_state = 'accepted'",
            (project_id, selected_space, selected_scope, selected_event),
        ).fetchone()
        if row is None:
            raise FederationBundleError("review export event is unavailable or unaccepted")
        envelope = _stored_envelope(row)
        author = conn.execute(
            "SELECT signing_public_key FROM federation_peers "
            "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
            (project_id, selected_space, envelope.author_peer_id),
        ).fetchone()
        if author is None:
            raise FederationBundleError("review export event author is unknown")
        if envelope.epoch not in key_cache:
            key_cache[envelope.epoch] = open_scope_key_for_epoch(
                conn,
                project_id=project_id,
                space_id=selected_space,
                scope_id=selected_scope,
                epoch=envelope.epoch,
                recipient=actor,
            )
        payload = decrypt_event(
            envelope,
            author_signing_public_key=bytes(author["signing_public_key"]),
            scope_key=key_cache[envelope.epoch],
        )
        privacy = str(payload.get("privacy_class") or "restricted").casefold()
        if privacy not in _PRIVACY:
            privacy = "restricted"
        if _PRIVACY_RANK[privacy] <= _PRIVACY_RANK[ceiling]:
            included.append(envelope)
        else:
            excluded.append(
                {"reference": envelope.event_id, "digest": envelope.envelope_sha256}
            )
    epoch_row = conn.execute(
        "SELECT MAX(epoch) FROM federation_scope_epochs "
        "WHERE project_id = ? AND space_id = ? AND scope_id = ?",
        (project_id, selected_space, selected_scope),
    ).fetchone()
    epoch = int(epoch_row[0] or 0)
    if epoch < 1:
        raise FederationBundleError("review export scope has no active key epoch")
    evidence = [
        {"evidence_id": envelope.event_id, "digest": envelope.envelope_sha256}
        for envelope in included
    ]
    return {
        "events": tuple(included),
        "evidence_manifest": tuple(evidence),
        "excluded_manifest": tuple(excluded),
        "recipient_envelope_public_key": bytes(recipient["envelope_public_key"]),
        "epoch": epoch,
        "privacy_ceiling": ceiling,
        "space_id": selected_space,
        "scope_id": selected_scope,
        "recipient_peer_id": selected_recipient,
    }


def preview_review_bundle_export(
    conn: sqlite3.Connection,
    **request: Any,
) -> dict[str, Any]:
    """Preview exact privacy-filtered review content without writing a bundle."""

    selected = _review_export_selection(conn, **request)
    intent = {
        "included_event_ids": [event.event_id for event in selected["events"]],
        "excluded_content_proof": hashlib.sha256(
            canonical_json_bytes(list(selected["excluded_manifest"]))
        ).hexdigest(),
        "privacy_ceiling": selected["privacy_ceiling"],
        "recipient_peer_id": selected["recipient_peer_id"],
        "scope_id": selected["scope_id"],
        "space_id": selected["space_id"],
    }
    confirmation = hashlib.sha256(
        b"rta-smriti-review-export-preview-v1\0" + canonical_json_bytes(intent)
    ).hexdigest()
    return {
        "state": "preview",
        "included_event_count": len(selected["events"]),
        "excluded_event_count": len(selected["excluded_manifest"]),
        "privacy_ceiling": selected["privacy_ceiling"],
        "recipient_peer_id": selected["recipient_peer_id"],
        "scope_id": selected["scope_id"],
        "space_id": selected["space_id"],
        "excluded_content_proof": intent["excluded_content_proof"],
        "confirmation_digest": confirmation,
        "writes_performed": False,
    }


def export_review_bundle_from_store(
    conn: sqlite3.Connection,
    *,
    confirmation_digest: str,
    **request: Any,
) -> bytes:
    """Create the exact current review export previously approved by digest."""

    preview = preview_review_bundle_export(conn, **request)
    if not hmac.compare_digest(
        str(confirmation_digest), str(preview["confirmation_digest"])
    ):
        raise FederationBundleError("review export changed after preview")
    selected = _review_export_selection(conn, **request)
    return create_encrypted_review_bundle(
        events=selected["events"],
        author=request["actor"],
        recipient_peer_id=selected["recipient_peer_id"],
        recipient_envelope_public_key=selected["recipient_envelope_public_key"],
        space_id=selected["space_id"],
        scope_id=selected["scope_id"],
        epoch=selected["epoch"],
        privacy_ceiling=selected["privacy_ceiling"],
        evidence_manifest=selected["evidence_manifest"],
        excluded_manifest=selected["excluded_manifest"],
    )


def _review_import_selection(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    encoded: bytes,
    recipient: FederationIdentity,
) -> dict[str, Any]:
    try:
        header = parse_canonical_json(encoded, max_bytes=MAX_FEDERATION_BUNDLE_BYTES)
    except (TypeError, ValueError) as exc:
        raise FederationBundleError("review bundle encoding is invalid") from exc
    if not isinstance(header, dict):
        raise FederationBundleError("review bundle must be an object")
    if header.get("recipient_peer_id") != recipient.identity_id:
        raise FederationBundleError("review bundle recipient does not match this identity")
    space_id = _hex_id("space_id", header.get("space_id"))
    scope_id = _hex_id("scope_id", header.get("scope_id"))
    authority = authorize_operation(
        conn,
        project_id=project_id,
        space_id=space_id,
        scope_id=scope_id,
        peer_id=recipient.identity_id,
        operation="read",
    )
    if not authority["allowed"]:
        raise FederationBundleError(
            f"review import requires an active scope capability: {authority['reason']}"
        )
    author_peer_id = _hex_id("author_peer_id", header.get("author_peer_id"))
    author = conn.execute(
        "SELECT signing_public_key FROM federation_peers "
        "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
        (project_id, space_id, author_peer_id),
    ).fetchone()
    if author is None:
        raise FederationBundleError("review bundle author is unknown")
    opened = open_encrypted_review_bundle(
        encoded,
        recipient=recipient,
        author_signing_public_key=bytes(author["signing_public_key"]),
    )
    events: list[FederationEventEnvelope] = []
    for value in opened["events"]:
        if not isinstance(value, dict):
            raise FederationBundleError("review bundle event is invalid")
        try:
            envelope = parse_event_envelope(canonical_json_bytes(value))
        except (TypeError, ValueError) as exc:
            raise FederationBundleError("review bundle event is invalid") from exc
        if envelope.space_id != space_id or envelope.scope_id != scope_id:
            raise FederationBundleError("review bundle event is outside the selected scope")
        events.append(envelope)
    manifest = opened["evidence_manifest"]
    expected_manifest = sorted(
        (
            {"evidence_id": event.event_id, "digest": event.envelope_sha256}
            for event in events
        ),
        key=lambda item: (item["evidence_id"], item["digest"]),
    )
    if manifest != expected_manifest:
        raise FederationBundleError("review bundle evidence manifest does not match its events")
    return {
        "bundle_id": opened["bundle_id"],
        "events": tuple(events),
        "excluded_content_proof": opened["excluded_content_proof"],
        "privacy_ceiling": opened["privacy_ceiling"],
        "recipient_peer_id": recipient.identity_id,
        "scope_id": scope_id,
        "space_id": space_id,
    }


def _trial_review_bundle_import(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    selected: Mapping[str, Any],
    recipient: FederationIdentity,
) -> dict[str, int]:
    inserted = 0
    duplicates = 0
    for envelope in selected["events"]:
        stored = store_event(
            conn, project_id=project_id, envelope=envelope, commit=False
        )
        inserted += stored["state"] == "inserted"
        duplicates += stored["state"] == "duplicate"
    accepted = 0
    key_cache: dict[int, bytes] = {}
    for envelope in selected["events"]:
        author = conn.execute(
            "SELECT signing_public_key FROM federation_peers "
            "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
            (project_id, selected["space_id"], envelope.author_peer_id),
        ).fetchone()
        if author is None:
            raise FederationBundleError("review bundle event author is unknown")
        if envelope.epoch not in key_cache:
            key_cache[envelope.epoch] = open_scope_key_for_epoch(
                conn,
                project_id=project_id,
                space_id=selected["space_id"],
                scope_id=selected["scope_id"],
                epoch=envelope.epoch,
                recipient=recipient,
            )
        validation = validate_and_accept_event(
            conn,
            project_id=project_id,
            envelope=envelope,
            author_signing_public_key=bytes(author["signing_public_key"]),
            scope_key=key_cache[envelope.epoch],
            commit=False,
        )
        if validation["state"] != "accepted":
            raise FederationBundleError("review bundle contains unresolved event dependencies")
        accepted += 1
    return {
        "accepted_event_count": accepted,
        "duplicate_event_count": duplicates,
        "new_event_count": inserted,
    }


def preview_review_bundle_import(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    encoded: bytes,
    recipient: FederationIdentity,
) -> dict[str, Any]:
    """Verify and simulate a review import without committing federation state."""

    selected = _review_import_selection(
        conn,
        project_id=project_id,
        encoded=encoded,
        recipient=recipient,
    )
    state_before = _state_digest(conn, project_id)
    savepoint = "federation_review_import_preview"
    conn.execute(f"SAVEPOINT {savepoint}")
    try:
        counts = _trial_review_bundle_import(
            conn,
            project_id=project_id,
            selected=selected,
            recipient=recipient,
        )
    finally:
        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
    intent = {
        "bundle_id": selected["bundle_id"],
        "event_count": len(selected["events"]),
        "recipient_peer_id": selected["recipient_peer_id"],
        "scope_id": selected["scope_id"],
        "space_id": selected["space_id"],
        "state_before_digest": state_before,
    }
    confirmation = hashlib.sha256(
        b"rta-smriti-review-import-preview-v1\0" + canonical_json_bytes(intent)
    ).hexdigest()
    return {
        "state": "verified",
        **counts,
        "bundle_id": selected["bundle_id"],
        "confirmation_digest": confirmation,
        "event_count": len(selected["events"]),
        "excluded_content_proof": selected["excluded_content_proof"],
        "privacy_ceiling": selected["privacy_ceiling"],
        "recipient_peer_id": selected["recipient_peer_id"],
        "scope_id": selected["scope_id"],
        "space_id": selected["space_id"],
        "writes_performed": False,
    }


def import_review_bundle_to_store(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    encoded: bytes,
    recipient: FederationIdentity,
    confirmation_digest: str,
) -> dict[str, Any]:
    """Atomically accept the exact review bundle and local state previously verified."""

    preview = preview_review_bundle_import(
        conn,
        project_id=project_id,
        encoded=encoded,
        recipient=recipient,
    )
    if not hmac.compare_digest(
        str(confirmation_digest), str(preview["confirmation_digest"])
    ):
        raise FederationBundleError("review import changed after verification")
    selected = _review_import_selection(
        conn,
        project_id=project_id,
        encoded=encoded,
        recipient=recipient,
    )
    savepoint = "federation_review_import_apply"
    conn.execute(f"SAVEPOINT {savepoint}")
    try:
        counts = _trial_review_bundle_import(
            conn,
            project_id=project_id,
            selected=selected,
            recipient=recipient,
        )
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
    except Exception:
        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise
    return {
        "state": "imported",
        **counts,
        "bundle_id": selected["bundle_id"],
        "recipient_peer_id": selected["recipient_peer_id"],
        "scope_id": selected["scope_id"],
        "space_id": selected["space_id"],
    }


def _hex_id(name: str, value: Any) -> str:
    selected = str(value)
    if (
        len(selected) != 64
        or any(char not in "0123456789abcdef" for char in selected)
        or set(selected) == {"0"}
    ):
        raise ValueError(f"{name} is invalid")
    return selected


def _manifest(
    entries: Sequence[Mapping[str, Any]],
    *,
    id_name: str,
) -> list[dict[str, str]]:
    if len(entries) > 4096:
        raise ValueError("bundle manifest exceeds the item limit")
    normalized = []
    for item in entries:
        if not isinstance(item, Mapping):
            raise TypeError("bundle manifest entries must be mappings")
        identity = str(item.get(id_name) or "").strip()
        digest = str(item.get("digest") or "").strip().casefold()
        if not identity or len(identity) > 4096 or "\0" in identity:
            raise ValueError("bundle manifest identity is invalid")
        _hex_id("bundle manifest digest", digest)
        normalized.append({id_name: identity, "digest": digest})
    return sorted(normalized, key=lambda item: (item[id_name], item["digest"]))


def create_encrypted_review_bundle(
    *,
    events: tuple[FederationEventEnvelope, ...],
    author: FederationIdentity,
    recipient_peer_id: str,
    recipient_envelope_public_key: bytes,
    space_id: str,
    scope_id: str,
    epoch: int,
    privacy_ceiling: str,
    evidence_manifest: Sequence[Mapping[str, Any]],
    excluded_manifest: Sequence[Mapping[str, Any]],
) -> bytes:
    """Create a digest-bound export whose excluded entries are represented only by proof."""

    selected_recipient = _hex_id("recipient_peer_id", recipient_peer_id)
    selected_space = _hex_id("space_id", space_id)
    selected_scope = _hex_id("scope_id", scope_id)
    selected_epoch = int(epoch)
    if selected_epoch < 1:
        raise ValueError("epoch must be positive")
    selected_privacy = str(privacy_ceiling).strip().casefold()
    if selected_privacy not in _PRIVACY:
        raise ValueError("privacy ceiling is invalid")
    if not isinstance(events, tuple) or len(events) > 10_000:
        raise ValueError("events must be a bounded tuple")
    for event in events:
        if event.space_id != selected_space or event.scope_id != selected_scope:
            raise ValueError("bundle event is outside the selected scope")
    included = _manifest(evidence_manifest, id_name="evidence_id")
    excluded = _manifest(excluded_manifest, id_name="reference")
    excluded_proof = hashlib.sha256(canonical_json_bytes(excluded)).hexdigest()
    payload = {
        "events": [event.as_wire_dict() for event in events],
        "schema": "rta-smriti.federation-review-payload/v1",
    }
    plaintext = canonical_json_bytes(payload, max_bytes=MAX_FEDERATION_BUNDLE_BYTES // 2)
    header = {
        "author_peer_id": author.identity_id,
        "epoch": selected_epoch,
        "evidence_manifest": included,
        "event_count": len(events),
        "excluded_content_proof": excluded_proof,
        "privacy_ceiling": selected_privacy,
        "recipient_peer_id": selected_recipient,
        "schema": "rta-smriti.federation-review-bundle/v1",
        "scope_id": selected_scope,
        "space_id": selected_space,
    }
    aad = canonical_json_bytes(header, max_bytes=MAX_FEDERATION_BUNDLE_BYTES)
    bundle_key = generate_scope_key()
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(bundle_key).encrypt(nonce, plaintext, aad)
    sealed_key = seal_scope_key(
        bundle_key,
        recipient_public_key=recipient_envelope_public_key,
        space_id=selected_space,
        scope_id=selected_scope,
        epoch=selected_epoch,
        recipient_peer_id=selected_recipient,
    )
    body = {
        **header,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "hpke_key_envelope": base64.b64encode(sealed_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
    }
    bundle_id = hashlib.sha256(
        b"rta-smriti-federation-review-v1\0"
        + canonical_json_bytes(body, max_bytes=MAX_FEDERATION_BUNDLE_BYTES)
    ).hexdigest()
    signature = author.signing_private_key.sign(
        canonical_json_bytes(
            {**body, "bundle_id": bundle_id},
            max_bytes=MAX_FEDERATION_BUNDLE_BYTES,
        )
    )
    encoded = canonical_json_bytes(
        {
            **body,
            "bundle_id": bundle_id,
            "signature": base64.b64encode(signature).decode("ascii"),
        },
        max_bytes=MAX_FEDERATION_BUNDLE_BYTES,
    )
    return encoded


def open_encrypted_review_bundle(
    encoded: bytes,
    *,
    recipient: FederationIdentity,
    author_signing_public_key: bytes,
) -> dict[str, Any]:
    """Verify authorship and exact audience before decrypting a review bundle."""

    try:
        value = parse_canonical_json(encoded, max_bytes=MAX_FEDERATION_BUNDLE_BYTES)
    except (TypeError, ValueError) as exc:
        raise FederationBundleError("review bundle encoding is invalid") from exc
    if not isinstance(value, dict):
        raise FederationBundleError("review bundle must be an object")
    expected = {
        "author_peer_id", "bundle_id", "ciphertext", "ciphertext_sha256", "epoch",
        "evidence_manifest", "event_count", "excluded_content_proof", "hpke_key_envelope",
        "nonce", "privacy_ceiling", "recipient_peer_id", "schema", "scope_id",
        "signature", "space_id",
    }
    if set(value) != expected or value.get("schema") != "rta-smriti.federation-review-bundle/v1":
        raise FederationBundleError("review bundle fields are invalid")
    if value.get("recipient_peer_id") != recipient.identity_id:
        raise FederationBundleError("review bundle recipient does not match this identity")
    body = {key: item for key, item in value.items() if key not in {"bundle_id", "signature"}}
    bundle_id = str(value["bundle_id"])
    expected_id = hashlib.sha256(
        b"rta-smriti-federation-review-v1\0"
        + canonical_json_bytes(body, max_bytes=MAX_FEDERATION_BUNDLE_BYTES)
    ).hexdigest()
    if bundle_id != expected_id:
        raise FederationBundleError("review bundle signature identity is invalid")
    try:
        signature = base64.b64decode(value["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(author_signing_public_key).verify(
            signature,
            canonical_json_bytes(
                {**body, "bundle_id": bundle_id},
                max_bytes=MAX_FEDERATION_BUNDLE_BYTES,
            ),
        )
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise FederationBundleError("review bundle signature is invalid") from exc
    header_keys = {
        "author_peer_id", "epoch", "evidence_manifest", "event_count",
        "excluded_content_proof", "privacy_ceiling", "recipient_peer_id", "schema",
        "scope_id", "space_id",
    }
    header = {key: value[key] for key in header_keys}
    try:
        bundle_key = open_scope_key(
            base64.b64decode(value["hpke_key_envelope"], validate=True),
            recipient_private_key=recipient.envelope_private_key,
            space_id=_hex_id("space_id", value["space_id"]),
            scope_id=_hex_id("scope_id", value["scope_id"]),
            epoch=int(value["epoch"]),
            recipient_peer_id=recipient.identity_id,
        )
        nonce = base64.b64decode(value["nonce"], validate=True)
        ciphertext = base64.b64decode(value["ciphertext"], validate=True)
        if hashlib.sha256(ciphertext).hexdigest() != value["ciphertext_sha256"]:
            raise FederationBundleError("review bundle ciphertext digest is invalid")
        plaintext = ChaCha20Poly1305(bundle_key).decrypt(
            nonce,
            ciphertext,
            canonical_json_bytes(header, max_bytes=MAX_FEDERATION_BUNDLE_BYTES),
        )
        payload = parse_canonical_json(
            plaintext, max_bytes=MAX_FEDERATION_BUNDLE_BYTES // 2
        )
    except FederationBundleError:
        raise
    except (TypeError, ValueError, InvalidTag) as exc:
        raise FederationBundleError("review bundle cannot be decrypted") from exc
    if not isinstance(payload, dict) or payload.get("schema") != "rta-smriti.federation-review-payload/v1":
        raise FederationBundleError("review bundle payload is invalid")
    events = payload.get("events")
    if not isinstance(events, list) or len(events) != int(value["event_count"]):
        raise FederationBundleError("review bundle event count is invalid")
    return {
        "bundle_id": bundle_id,
        "author_peer_id": value["author_peer_id"],
        "recipient_peer_id": value["recipient_peer_id"],
        "space_id": value["space_id"],
        "scope_id": value["scope_id"],
        "epoch": int(value["epoch"]),
        "privacy_ceiling": value["privacy_ceiling"],
        "event_count": len(events),
        "events": events,
        "evidence_manifest": value["evidence_manifest"],
        "excluded_content_proof": value["excluded_content_proof"],
        "non_authoritative_summary": True,
    }
