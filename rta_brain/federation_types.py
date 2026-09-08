"""Bounded public wire types for governed federation."""

from __future__ import annotations

import base64
import hashlib
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

MAX_CANONICAL_JSON_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 4096
MAX_JSON_STRING_CHARS = 256_000
MAX_EVENT_CIPHERTEXT_BYTES = 1024 * 1024
_HEX = frozenset("0123456789abcdef")


def _validate_json_value(value: Any, *, depth: int, max_depth: int) -> int:
    if depth > max_depth:
        raise ValueError("JSON nesting exceeds the configured limit")
    if value is None or isinstance(value, bool):
        return 1
    if isinstance(value, int):
        return 1
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return 1
    if isinstance(value, str):
        if len(value) > MAX_JSON_STRING_CHARS or "\0" in value:
            raise ValueError("JSON string exceeds the configured limit")
        return 1
    if isinstance(value, list):
        if len(value) > MAX_JSON_ITEMS:
            raise ValueError("JSON collection exceeds the configured limit")
        total = 1
        for item in value:
            total += _validate_json_value(item, depth=depth + 1, max_depth=max_depth)
            if total > MAX_JSON_ITEMS:
                raise ValueError("JSON item count exceeds the configured limit")
        return total
    if isinstance(value, dict):
        if len(value) > MAX_JSON_ITEMS:
            raise ValueError("JSON collection exceeds the configured limit")
        total = 1
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 256 or "\0" in key:
                raise ValueError("JSON object keys must be bounded strings")
            total += _validate_json_value(item, depth=depth + 1, max_depth=max_depth)
            if total > MAX_JSON_ITEMS:
                raise ValueError("JSON item count exceeds the configured limit")
        return total
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def canonical_json_bytes(
    value: Any,
    *,
    max_bytes: int = MAX_CANONICAL_JSON_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
) -> bytes:
    _validate_json_value(value, depth=0, max_depth=max_depth)
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    if len(encoded) > max_bytes:
        raise ValueError("canonical JSON exceeds the configured byte limit")
    return encoded


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_canonical_json(
    encoded: bytes,
    *,
    max_bytes: int = MAX_CANONICAL_JSON_BYTES,
    max_depth: int = MAX_JSON_DEPTH,
) -> Any:
    if not isinstance(encoded, bytes):
        raise TypeError("canonical JSON input must be bytes")
    if not encoded or len(encoded) > max_bytes:
        raise ValueError("canonical JSON input exceeds the configured byte limit")
    try:
        text = encoded.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except UnicodeDecodeError as exc:
        raise ValueError("canonical JSON must be valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("canonical JSON is invalid") from exc
    canonical = canonical_json_bytes(value, max_bytes=max_bytes, max_depth=max_depth)
    if encoded != canonical:
        raise ValueError("JSON input is not in canonical form")
    return value


def _hex_identifier(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or set(value) - _HEX
        or set(value) == {"0"}
    ):
        raise ValueError(f"{name} must be a non-zero 64-character lower-case hex value")
    return value


@dataclass(frozen=True)
class FederationEventEnvelope:
    space_id: str
    scope_id: str
    epoch: int
    event_id: str
    author_peer_id: str
    author_sequence: int
    capability_event_id: str
    parents: tuple[str, ...]
    nonce: bytes
    ciphertext: bytes
    ciphertext_sha256: str
    signature: bytes
    received_at: str

    def __post_init__(self) -> None:
        _hex_identifier("space_id", self.space_id)
        _hex_identifier("scope_id", self.scope_id)
        _hex_identifier("event_id", self.event_id)
        _hex_identifier("author_peer_id", self.author_peer_id)
        _hex_identifier("capability_event_id", self.capability_event_id)
        _hex_identifier("ciphertext_sha256", self.ciphertext_sha256)
        if type(self.epoch) is not int or self.epoch < 1:
            raise ValueError("epoch must be a positive integer")
        if type(self.author_sequence) is not int or self.author_sequence < 1:
            raise ValueError("author_sequence must be a positive integer")
        if not isinstance(self.parents, tuple) or len(self.parents) > 256:
            raise ValueError("parents must be a bounded tuple")
        normalized_parents = tuple(sorted({_hex_identifier("parent", item) for item in self.parents}))
        if len(normalized_parents) != len(self.parents):
            raise ValueError("parents must not contain duplicates")
        if self.event_id in normalized_parents:
            raise ValueError("an event must not reference itself as a parent")
        object.__setattr__(self, "parents", normalized_parents)
        if not isinstance(self.nonce, bytes) or len(self.nonce) != 12:
            raise ValueError("nonce must contain exactly 12 bytes")
        if (
            not isinstance(self.ciphertext, bytes)
            or not 1 <= len(self.ciphertext) <= MAX_EVENT_CIPHERTEXT_BYTES
        ):
            raise ValueError("ciphertext exceeds the configured byte limit")
        if hashlib.sha256(self.ciphertext).hexdigest() != self.ciphertext_sha256:
            raise ValueError("ciphertext digest does not match the ciphertext")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValueError("signature must contain exactly 64 bytes")
        if (
            not isinstance(self.received_at, str)
            or not 1 <= len(self.received_at) <= 64
            or "\0" in self.received_at
        ):
            raise ValueError("received_at must be a bounded timestamp string")

    def as_wire_dict(self) -> dict[str, Any]:
        return {
            "author_peer_id": self.author_peer_id,
            "author_sequence": self.author_sequence,
            "capability_event_id": self.capability_event_id,
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "ciphertext_sha256": self.ciphertext_sha256,
            "epoch": self.epoch,
            "event_id": self.event_id,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "parents": list(self.parents),
            "schema": "rta-smriti.federation-event/v1",
            "scope_id": self.scope_id,
            "signature": base64.b64encode(self.signature).decode("ascii"),
            "space_id": self.space_id,
        }

    @property
    def encoded(self) -> bytes:
        return canonical_json_bytes(self.as_wire_dict(), max_bytes=2 * MAX_CANONICAL_JSON_BYTES)

    @property
    def envelope_sha256(self) -> str:
        return hashlib.sha256(self.encoded).hexdigest()


def parse_event_envelope(
    encoded: bytes,
    *,
    received_at: str | None = None,
) -> FederationEventEnvelope:
    """Parse one canonical relay blob and attach local receipt metadata."""

    value = parse_canonical_json(encoded, max_bytes=2 * MAX_CANONICAL_JSON_BYTES)
    if not isinstance(value, dict):
        raise ValueError(  # noqa: TRY004 - untrusted envelope validation
            "federation event envelope must be a JSON object"
        )
    expected = {
        "author_peer_id", "author_sequence", "capability_event_id", "ciphertext",
        "ciphertext_sha256", "epoch", "event_id", "nonce", "parents", "schema",
        "scope_id", "signature", "space_id",
    }
    if set(value) != expected or value.get("schema") != "rta-smriti.federation-event/v1":
        raise ValueError("federation event envelope fields are invalid")
    try:
        ciphertext = base64.b64decode(value["ciphertext"], validate=True)
        nonce = base64.b64decode(value["nonce"], validate=True)
        signature = base64.b64decode(value["signature"], validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("federation event envelope contains invalid base64") from exc
    parents = value["parents"]
    if not isinstance(parents, list) or not all(isinstance(item, str) for item in parents):
        raise ValueError("federation event parents must be a list of identifiers")
    return FederationEventEnvelope(
        space_id=value["space_id"],
        scope_id=value["scope_id"],
        epoch=value["epoch"],
        event_id=value["event_id"],
        author_peer_id=value["author_peer_id"],
        author_sequence=value["author_sequence"],
        capability_event_id=value["capability_event_id"],
        parents=tuple(parents),
        nonce=nonce,
        ciphertext=ciphertext,
        ciphertext_sha256=value["ciphertext_sha256"],
        signature=signature,
        received_at=received_at or datetime.now(UTC).replace(microsecond=0).isoformat(),
    )
