"""Cryptographic identity and envelope primitives for governed federation."""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

from .federation_types import (
    FederationEventEnvelope,
    canonical_json_bytes,
    parse_canonical_json,
)
from .runtime_control import (
    create_secret,
    is_safe_regular_file,
    prepare_control_dir,
    read_json,
    read_secret,
)

_HPKE = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)
_HEX = frozenset("0123456789abcdef")
_IDENTITY_SCHEMA = "rta-smriti.federation-identity/v1"
_PUBLIC_IDENTITY_SCHEMA = "rta-smriti.federation-public-identity/v1"
_EVENT_SCHEMA = "rta-smriti.federation-event/v1"
_IDENTITY_BACKUP_SCHEMA = "rta-smriti.federation-identity-backup/v1"
_MAX_IDENTITY_BACKUP_BYTES = 256 * 1024


class FederationCryptoError(ValueError):
    """Cryptographic material or verification is invalid."""


@dataclass(frozen=True)
class FederationIdentity:
    identity_id: str
    signing_private_key: Ed25519PrivateKey  # gitleaks:allow - typed key handle, not key material
    envelope_private_key: X25519PrivateKey  # gitleaks:allow - typed key handle, not key material

    @property
    def signing_public_bytes(self) -> bytes:
        return self.signing_private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    @property
    def envelope_public_bytes(self) -> bytes:
        return self.envelope_private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )


@dataclass(frozen=True)
class PublicFederationIdentity:
    identity_id: str
    signing_public_bytes: bytes
    envelope_public_bytes: bytes


def _validate_passphrase(passphrase: bytes) -> bytes:
    if not isinstance(passphrase, bytes) or not 16 <= len(passphrase) <= 1024:
        raise ValueError("identity passphrase must contain 16 to 1,024 bytes")
    return passphrase


def _hex_identifier(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or set(value) - _HEX
        or set(value) == {"0"}
    ):
        raise ValueError(f"{name} must be a non-zero 64-character lower-case hex value")
    return value


def _identity_id(signing_public: bytes, envelope_public: bytes) -> str:
    payload = canonical_json_bytes(
        {
            "envelope_public_key": base64.b64encode(envelope_public).decode("ascii"),
            "schema": _IDENTITY_SCHEMA,
            "signing_public_key": base64.b64encode(signing_public).decode("ascii"),
        }
    )
    return hashlib.sha256(b"rta-smriti-identity-v1\0" + payload).hexdigest()


def public_identity_from_keys(
    signing_public: bytes, envelope_public: bytes
) -> PublicFederationIdentity:
    if (
        not isinstance(signing_public, bytes)
        or not isinstance(envelope_public, bytes)
        or len(signing_public) != 32
        or len(envelope_public) != 32
    ):
        raise FederationCryptoError("public identity key length is invalid")
    return PublicFederationIdentity(
        identity_id=_identity_id(signing_public, envelope_public),
        signing_public_bytes=signing_public,
        envelope_public_bytes=envelope_public,
    )


def export_public_identity(identity: FederationIdentity) -> bytes:
    """Return a bounded self-signed public device manifest."""

    body = {
        "envelope_public_key": base64.b64encode(
            identity.envelope_public_bytes
        ).decode("ascii"),
        "identity_id": identity.identity_id,
        "schema": _PUBLIC_IDENTITY_SCHEMA,
        "signing_public_key": base64.b64encode(
            identity.signing_public_bytes
        ).decode("ascii"),
    }
    signature = identity.signing_private_key.sign(canonical_json_bytes(body))
    return canonical_json_bytes(
        {**body, "signature": base64.b64encode(signature).decode("ascii")}
    )


def import_public_identity(encoded: bytes) -> PublicFederationIdentity:
    """Validate key possession and return public-only peer material."""

    try:
        value = parse_canonical_json(encoded)
        if not isinstance(value, dict) or set(value) != {
            "envelope_public_key",
            "identity_id",
            "schema",
            "signature",
            "signing_public_key",
        }:
            raise ValueError("public identity fields are invalid")
        if value["schema"] != _PUBLIC_IDENTITY_SCHEMA:
            raise ValueError("public identity schema is invalid")
        signing_public = base64.b64decode(
            value["signing_public_key"], validate=True
        )
        envelope_public = base64.b64decode(
            value["envelope_public_key"], validate=True
        )
        if len(signing_public) != 32 or len(envelope_public) != 32:
            raise ValueError("public identity key length is invalid")
        identity_id = _identity_id(signing_public, envelope_public)
        if value["identity_id"] != identity_id:
            raise ValueError("public identity fingerprint is invalid")
        body = {key: item for key, item in value.items() if key != "signature"}
        signature = base64.b64decode(value["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(signing_public).verify(
            signature, canonical_json_bytes(body)
        )
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise FederationCryptoError("public identity manifest is invalid") from exc
    return public_identity_from_keys(signing_public, envelope_public)


def _public_manifest(identity: FederationIdentity) -> dict[str, str]:
    return {
        "envelope_private_key_file": "envelope.pem",
        "envelope_public_key": base64.b64encode(identity.envelope_public_bytes).decode("ascii"),
        "identity_id": identity.identity_id,
        "schema": _IDENTITY_SCHEMA,
        "signing_private_key_file": "signing.pem",
        "signing_public_key": base64.b64encode(identity.signing_public_bytes).decode("ascii"),
    }


def create_identity(root: Path, *, passphrase: bytes) -> FederationIdentity:
    selected_passphrase = _validate_passphrase(passphrase)
    target = Path(root).expanduser()
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"federation identity already exists: {target}")
    target.mkdir(parents=True)
    try:
        prepare_control_dir(target, label="federation identity")
        signing = Ed25519PrivateKey.generate()
        envelope = X25519PrivateKey.generate()
        signing_public = signing.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        envelope_public = envelope.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        identity = FederationIdentity(
            identity_id=_identity_id(signing_public, envelope_public),
            signing_private_key=signing,
            envelope_private_key=envelope,
        )
        encryption = serialization.BestAvailableEncryption(selected_passphrase)
        signing_pem = signing.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        ).decode("ascii")
        envelope_pem = envelope.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        ).decode("ascii")
        create_secret(target / "signing.pem", signing_pem.rstrip(), label="federation signing key")
        create_secret(target / "envelope.pem", envelope_pem.rstrip(), label="federation envelope key")
        manifest = canonical_json_bytes(_public_manifest(identity)).decode("ascii")
        create_secret(target / "identity.json", manifest, label="federation identity manifest")
        return identity
    except BaseException:
        for name in ("identity.json", "envelope.pem", "signing.pem"):
            (target / name).unlink(missing_ok=True)
        try:
            target.rmdir()
        except OSError:
            pass
        raise


def load_identity(root: Path, *, passphrase: bytes) -> FederationIdentity:
    selected_passphrase = _validate_passphrase(passphrase)
    target = Path(root).expanduser()
    manifest_path = target / "identity.json"
    signing_path = target / "signing.pem"
    envelope_path = target / "envelope.pem"
    if not all(is_safe_regular_file(path) for path in (manifest_path, signing_path, envelope_path)):
        raise FederationCryptoError("federation identity is missing or unsafe")
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("schema") != _IDENTITY_SCHEMA:
        raise FederationCryptoError("federation identity manifest is invalid")
    try:
        signing = serialization.load_pem_private_key(
            read_secret(signing_path, label="federation signing key").encode("ascii"),
            password=selected_passphrase,
        )
        envelope = serialization.load_pem_private_key(
            read_secret(envelope_path, label="federation envelope key").encode("ascii"),
            password=selected_passphrase,
        )
    except (TypeError, ValueError) as exc:
        raise FederationCryptoError("cannot decrypt identity with the supplied passphrase") from exc
    if not isinstance(signing, Ed25519PrivateKey) or not isinstance(envelope, X25519PrivateKey):
        raise FederationCryptoError("federation identity key types are invalid")
    identity = FederationIdentity(
        identity_id=_identity_id(
            signing.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            envelope.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        ),
        signing_private_key=signing,
        envelope_private_key=envelope,
    )
    expected = _public_manifest(identity)
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise FederationCryptoError("federation identity manifest does not match its keys")
    return identity


def create_identity_backup(root: Path, *, passphrase: bytes) -> bytes:
    """Export a signed bounded backup whose private keys remain passphrase-encrypted."""

    identity = load_identity(root, passphrase=passphrase)
    target = Path(root).expanduser()
    files = {
        name: read_secret(target / name, label=f"federation identity {name}").encode("ascii")
        for name in ("identity.json", "signing.pem", "envelope.pem")
    }
    body = {
        "files": {
            name: {
                "content": base64.b64encode(content).decode("ascii"),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
            for name, content in sorted(files.items())
        },
        "identity_id": identity.identity_id,
        "schema": _IDENTITY_BACKUP_SCHEMA,
    }
    signature = identity.signing_private_key.sign(
        canonical_json_bytes(body, max_bytes=_MAX_IDENTITY_BACKUP_BYTES)
    )
    return canonical_json_bytes(
        {**body, "signature": base64.b64encode(signature).decode("ascii")},
        max_bytes=_MAX_IDENTITY_BACKUP_BYTES,
    )


def restore_identity_backup(
    encoded: bytes,
    target: Path,
    *,
    passphrase: bytes,
) -> FederationIdentity:
    """Verify and restore an encrypted identity backup without overwriting a target."""

    _validate_passphrase(passphrase)
    destination = Path(target).expanduser()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"federation identity already exists: {destination}")
    try:
        value = parse_canonical_json(encoded, max_bytes=_MAX_IDENTITY_BACKUP_BYTES)
        if not isinstance(value, dict) or set(value) != {
            "files", "identity_id", "schema", "signature"
        }:
            raise ValueError("identity backup fields are invalid")
        if value["schema"] != _IDENTITY_BACKUP_SCHEMA:
            raise ValueError("identity backup schema is invalid")
        files = value["files"]
        if not isinstance(files, dict) or set(files) != {
            "identity.json", "signing.pem", "envelope.pem"
        }:
            raise ValueError("identity backup file inventory is invalid")
        decoded: dict[str, bytes] = {}
        for name, item in files.items():
            if not isinstance(item, dict) or set(item) != {"content", "sha256"}:
                raise ValueError("identity backup file record is invalid")
            content = base64.b64decode(item["content"], validate=True)
            if not content or len(content) > 64 * 1024:
                raise ValueError("identity backup file exceeds its bound")
            if hashlib.sha256(content).hexdigest() != item["sha256"]:
                raise ValueError("identity backup file digest is invalid")
            decoded[name] = content
        manifest = parse_canonical_json(decoded["identity.json"])
        if not isinstance(manifest, dict) or manifest.get("identity_id") != value["identity_id"]:
            raise ValueError("identity backup manifest is invalid")
        signing_public = base64.b64decode(manifest["signing_public_key"], validate=True)
        body = {key: item for key, item in value.items() if key != "signature"}
        Ed25519PublicKey.from_public_bytes(signing_public).verify(
            base64.b64decode(value["signature"], validate=True),
            canonical_json_bytes(body, max_bytes=_MAX_IDENTITY_BACKUP_BYTES),
        )
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise FederationCryptoError("federation identity backup is invalid") from exc

    destination.mkdir(parents=True)
    try:
        prepare_control_dir(destination, label="federation identity")
        for name in ("identity.json", "signing.pem", "envelope.pem"):
            create_secret(
                destination / name,
                decoded[name].decode("ascii").rstrip(),
                label=f"federation identity {name}",
            )
        restored = load_identity(destination, passphrase=passphrase)
        if restored.identity_id != value["identity_id"]:
            raise FederationCryptoError("restored federation identity does not match the backup")
        return restored
    except BaseException:
        for name in ("identity.json", "envelope.pem", "signing.pem"):
            (destination / name).unlink(missing_ok=True)
        try:
            destination.rmdir()
        except OSError:
            pass
        raise


def generate_scope_key() -> bytes:
    return os.urandom(32)


def _scope_key_info(
    *,
    space_id: str,
    scope_id: str,
    epoch: int,
    recipient_peer_id: str,
) -> bytes:
    _hex_identifier("space_id", space_id)
    _hex_identifier("scope_id", scope_id)
    _hex_identifier("recipient_peer_id", recipient_peer_id)
    if type(epoch) is not int or epoch < 1:
        raise ValueError("epoch must be a positive integer")
    return canonical_json_bytes(
        {
            "epoch": epoch,
            "recipient_peer_id": recipient_peer_id,
            "schema": "rta-smriti.scope-key-envelope/v1",
            "scope_id": scope_id,
            "space_id": space_id,
        }
    )


def seal_scope_key(
    scope_key: bytes,
    *,
    recipient_public_key: bytes,
    space_id: str,
    scope_id: str,
    epoch: int,
    recipient_peer_id: str,
) -> bytes:
    if not isinstance(scope_key, bytes) or len(scope_key) != 32:
        raise ValueError("scope key must contain exactly 32 bytes")
    if not isinstance(recipient_public_key, bytes) or len(recipient_public_key) != 32:
        raise ValueError("recipient public key must contain exactly 32 bytes")
    public_key = X25519PublicKey.from_public_bytes(recipient_public_key)
    return _HPKE.encrypt(
        scope_key,
        public_key,
        info=_scope_key_info(
            space_id=space_id,
            scope_id=scope_id,
            epoch=epoch,
            recipient_peer_id=recipient_peer_id,
        ),
    )


def open_scope_key(
    sealed: bytes,
    *,
    recipient_private_key: X25519PrivateKey,
    space_id: str,
    scope_id: str,
    epoch: int,
    recipient_peer_id: str,
) -> bytes:
    if not isinstance(sealed, bytes) or not 1 <= len(sealed) <= 65_536:
        raise ValueError("sealed scope key exceeds the configured byte limit")
    if not isinstance(recipient_private_key, X25519PrivateKey):
        raise TypeError("recipient private key must be X25519")
    try:
        opened = _HPKE.decrypt(
            sealed,
            recipient_private_key,
            info=_scope_key_info(
                space_id=space_id,
                scope_id=scope_id,
                epoch=epoch,
                recipient_peer_id=recipient_peer_id,
            ),
        )
    except (InvalidTag, ValueError) as exc:
        raise FederationCryptoError("cannot open scope key for this recipient and context") from exc
    if len(opened) != 32:
        raise FederationCryptoError("opened scope key has an invalid length")
    return opened


def _event_aad(
    *,
    space_id: str,
    scope_id: str,
    epoch: int,
    author_peer_id: str,
    author_sequence: int,
    capability_event_id: str,
    parents: tuple[str, ...],
    nonce: bytes,
) -> bytes:
    _hex_identifier("space_id", space_id)
    _hex_identifier("scope_id", scope_id)
    _hex_identifier("author_peer_id", author_peer_id)
    _hex_identifier("capability_event_id", capability_event_id)
    if type(epoch) is not int or epoch < 1:
        raise ValueError("epoch must be a positive integer")
    if type(author_sequence) is not int or author_sequence < 1:
        raise ValueError("author_sequence must be a positive integer")
    normalized_parents = tuple(sorted({_hex_identifier("parent", item) for item in parents}))
    if len(normalized_parents) != len(parents) or len(parents) > 256:
        raise ValueError("parents must be unique and bounded")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("nonce must contain exactly 12 bytes")
    return canonical_json_bytes(
        {
            "author_peer_id": author_peer_id,
            "author_sequence": author_sequence,
            "capability_event_id": capability_event_id,
            "epoch": epoch,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "parents": list(normalized_parents),
            "schema": _EVENT_SCHEMA,
            "scope_id": scope_id,
            "space_id": space_id,
        }
    )


def _event_id(aad: bytes, ciphertext: bytes) -> str:
    return hashlib.sha256(b"rta-smriti-event-id-v1\0" + aad + ciphertext).hexdigest()


def _signature_input(
    *,
    aad: bytes,
    event_id: str,
    ciphertext: bytes,
    ciphertext_sha256: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "aad": base64.b64encode(aad).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "ciphertext_sha256": ciphertext_sha256,
            "event_id": event_id,
            "schema": "rta-smriti.federation-signature/v1",
        },
        max_bytes=2 * 1024 * 1024,
    )


def create_encrypted_event(
    payload: Mapping[str, Any],
    *,
    identity: FederationIdentity,
    scope_key: bytes,
    space_id: str,
    scope_id: str,
    epoch: int,
    author_sequence: int,
    capability_event_id: str,
    parents: tuple[str, ...],
    received_at: str,
) -> FederationEventEnvelope:
    if not isinstance(payload, Mapping):
        raise TypeError("federation event payload must be a mapping")
    if not isinstance(scope_key, bytes) or len(scope_key) != 32:
        raise ValueError("scope key must contain exactly 32 bytes")
    if not isinstance(identity, FederationIdentity):
        raise TypeError("identity must be a loaded federation identity")
    nonce = os.urandom(12)
    normalized_parents = tuple(sorted(parents))
    aad = _event_aad(
        space_id=space_id,
        scope_id=scope_id,
        epoch=epoch,
        author_peer_id=identity.identity_id,
        author_sequence=author_sequence,
        capability_event_id=capability_event_id,
        parents=normalized_parents,
        nonce=nonce,
    )
    plaintext = canonical_json_bytes(dict(payload))
    ciphertext = ChaCha20Poly1305(scope_key).encrypt(nonce, plaintext, aad)
    ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
    event_id = _event_id(aad, ciphertext)
    signature = identity.signing_private_key.sign(
        _signature_input(
            aad=aad,
            event_id=event_id,
            ciphertext=ciphertext,
            ciphertext_sha256=ciphertext_sha256,
        )
    )
    return FederationEventEnvelope(
        space_id=space_id,
        scope_id=scope_id,
        epoch=epoch,
        event_id=event_id,
        author_peer_id=identity.identity_id,
        author_sequence=author_sequence,
        capability_event_id=capability_event_id,
        parents=normalized_parents,
        nonce=nonce,
        ciphertext=ciphertext,
        ciphertext_sha256=ciphertext_sha256,
        signature=signature,
        received_at=received_at,
    )


def decrypt_event(
    envelope: FederationEventEnvelope,
    *,
    author_signing_public_key: bytes,
    scope_key: bytes,
) -> dict[str, Any]:
    if not isinstance(author_signing_public_key, bytes) or len(author_signing_public_key) != 32:
        raise ValueError("author signing public key must contain exactly 32 bytes")
    if not isinstance(scope_key, bytes) or len(scope_key) != 32:
        raise ValueError("scope key must contain exactly 32 bytes")
    aad = _event_aad(
        space_id=envelope.space_id,
        scope_id=envelope.scope_id,
        epoch=envelope.epoch,
        author_peer_id=envelope.author_peer_id,
        author_sequence=envelope.author_sequence,
        capability_event_id=envelope.capability_event_id,
        parents=envelope.parents,
        nonce=envelope.nonce,
    )
    signing_input = _signature_input(
        aad=aad,
        event_id=envelope.event_id,
        ciphertext=envelope.ciphertext,
        ciphertext_sha256=envelope.ciphertext_sha256,
    )
    try:
        Ed25519PublicKey.from_public_bytes(author_signing_public_key).verify(
            envelope.signature, signing_input
        )
    except (InvalidSignature, ValueError) as exc:
        raise FederationCryptoError("federation event signature is invalid") from exc
    if _event_id(aad, envelope.ciphertext) != envelope.event_id:
        raise FederationCryptoError("federation event id is invalid")
    try:
        plaintext = ChaCha20Poly1305(scope_key).decrypt(
            envelope.nonce, envelope.ciphertext, aad
        )
    except InvalidTag as exc:
        raise FederationCryptoError("federation event cannot be decrypted in this scope") from exc
    try:
        payload = parse_canonical_json(plaintext)
    except (TypeError, ValueError) as exc:
        raise FederationCryptoError("federation event plaintext is invalid") from exc
    if not isinstance(payload, dict):
        raise FederationCryptoError("federation event payload must be an object")
    return payload
