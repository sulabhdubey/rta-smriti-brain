"""Bounded sensitive-text detection shared by exports and release scans."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

MAX_SENSITIVE_TEXT_CHARS = 100_000
MAX_SENSITIVE_COLLECTION_ITEMS = 10_000
MAX_SENSITIVE_DEPTH = 12
MAX_LOCAL_PAYLOAD_BYTES = 1_048_576


@dataclass(frozen=True)
class SensitiveFinding:
    label: str
    start: int
    end: int


SECRET_TEXT_PATTERNS = {
    "aws-access-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "openai-style-token": re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{20,}\b"),
    "stripe-secret-key": re.compile(
        r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"
    ),
    "stripe-webhook-secret": re.compile(r"\bwhsec_[0-9A-Za-z]{16,}\b"),
    "private-key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        r"[\s\S]{0,100000}?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|\Z)"
    ),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "assigned-secret": re.compile(
        r"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|password|access[_-]?token|"
        r"auth(?:orization)?[_-]?token|bearer[_-]?token|client[_-]?secret)"
        r"\s*[:=]\s*(?:['\"][^'\"\r\n]{1,4096}['\"]|[^\s,;]{1,4096})"
    ),
    "authorization-bearer": re.compile(
        r"(?i)\b(?:authorization\s*:\s*)?bearer\s+[A-Za-z0-9._~+/=-]{12,4096}"
    ),
    "cookie-header": re.compile(
        r"(?i)\b(?:cookie|set-cookie)\s*:\s*[^\r\n]{1,4096}"
    ),
    "url-credentials": re.compile(
        r"(?i)\b[a-z][a-z0-9+.-]{1,15}://"
        r"[^\s/:@]{1,256}:[^\s/@]{1,4096}@"
    ),
}

PATH_TEXT_PATTERNS = {
    "windows-user-path": re.compile(
        r"(?i)\b[A-Z]:[\\/]Users[\\/][^\\/\x00\r\n]{1,100}"
        r"(?:[\\/][^\\/\x00\r\n\"'<>|]{1,255}){0,31}"
        r"[\\/][^\s\\/\x00\r\n\"'<>|]{1,255}"
    ),
    "posix-user-path": re.compile(
        r"/(?:Users|home)/[^/\x00\r\n]{1,100}"
        r"(?:/[^/\x00\r\n\"'<>]{1,255}){0,31}"
        r"/[^\s/\x00\r\n\"'<>]{1,255}"
    ),
    "unc-path": re.compile(
        r"\\\\(?:\?\\UNC\\)?[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?"
        r"\\[A-Za-z0-9$][^\\\x00-\x1f]{0,99}(?=\\|$)"
        r"(?:\\[^\x00\r\n]{1,4096})?"
    ),
    "windows-absolute-path": re.compile(
        r"(?i)(?<![A-Za-z0-9_])[A-Z]:[\\/]"
        r"(?:[^<>:\"/\\|?*\x00-\x1f]{1,255}[\\/]){0,32}"
        r"[^\s<>:\"/\\|?*\x00-\x1f]{1,255}"
    ),
    "posix-absolute-path": re.compile(
        r"(?<![:/A-Za-z0-9_])/(?!/)"
        r"(?:[^/\x00-\x1f\x7f\"']{1,255}/){0,32}"
        r"[^\s/\x00-\x1f\x7f\"']{1,255}"
    ),
}

SENSITIVE_TEXT_PATTERNS = {**SECRET_TEXT_PATTERNS, **PATH_TEXT_PATTERNS}

# Every detector above requires a path separator or one of these case-folded
# fragments. This conservative prefilter avoids repeated regex passes over
# ordinary event labels while preserving the fail-closed detector surface.
_SENSITIVE_TEXT_MARKERS = (
    "akia", "asia", "aiza", "gh", "sk-", "rk-", "sk_", "rk_", "whsec_",
    "-----begin", "eyj", "api",
    "secret", "password", "access", "client", "token", "bearer", "cookie",
)

SENSITIVE_FIELD_NAME = re.compile(
    r"(?ix)(?:"
    r"(?:^|[_-])(?:api[_-]?key|secret(?:[_-]?access)?[_-]?key|"
    r"password|passwd|pwd|access[_-]?token|refresh[_-]?token|"
    r"client[_-]?secret|authorization|cookie|set[_-]?cookie|"
    r"private[_-]?key|database[_-]?url|connection[_-]?string|"
    r"credential(?:s)?)$"
    r"|(?:^|[_-])(?:token|secret)$"
    r")"
)

_SENSITIVE_COMPACT_FIELD_NAMES = frozenset(
    {
        "apikey",
        "authorization",
        "clientsecret",
        "clipboard",
        "connectionstring",
        "cookies",
        "credential",
        "credentials",
        "databaseurl",
        "passcode",
        "passwd",
        "password",
        "privatekey",
        "pwd",
        "setcookie",
    }
)
_SENSITIVE_COMPACT_CONTAINER_NAMES = frozenset({"environment", "headers"})
_SENSITIVE_COMPACT_FIELD_SUFFIXES = (
    "apikey",
    "cookie",
    "credential",
    "credentials",
    "password",
    "passwd",
    "privatekey",
    "pwd",
    "secret",
    "token",
)
_SENSITIVE_COMPACT_VALUE_ROOTS = (
    "accesstoken",
    "apikey",
    "authorization",
    "authtoken",
    "bearertoken",
    "clientsecret",
    "connectionstring",
    "cookie",
    "credential",
    "credentials",
    "databaseurl",
    "password",
    "passwd",
    "privatekey",
    "pwd",
    "refreshtoken",
    "secret",
    "secretaccesskey",
    "setcookie",
    "token",
)
_SENSITIVE_COMPACT_VALUE_QUALIFIERS = (
    "bytes",
    "content",
    "data",
    "material",
    "raw",
    "text",
    "value",
)


def is_sensitive_field_name(
    value: str, *, include_containers: bool = False
) -> bool:
    """Recognize credential-bearing keys across snake, kebab, and camel case."""

    key = str(value).strip()
    if not key:
        return False
    if SENSITIVE_FIELD_NAME.search(key):
        return True
    compact = re.sub(r"[^a-z0-9]+", "", key.lower())
    qualified_sensitive_value = any(
        compact.endswith(root + qualifier)
        for root in _SENSITIVE_COMPACT_VALUE_ROOTS
        for qualifier in _SENSITIVE_COMPACT_VALUE_QUALIFIERS
    )
    return (
        compact in _SENSITIVE_COMPACT_FIELD_NAMES
        or (
            include_containers
            and compact in _SENSITIVE_COMPACT_CONTAINER_NAMES
        )
        or compact.endswith(_SENSITIVE_COMPACT_FIELD_SUFFIXES)
        or qualified_sensitive_value
    )


def _byte_patterns(patterns: dict[str, re.Pattern[str]]) -> dict[str, re.Pattern[bytes]]:
    return {
        label: re.compile(pattern.pattern.encode("ascii"), re.IGNORECASE if pattern.flags & re.IGNORECASE else 0)
        for label, pattern in patterns.items()
    }


SECRET_BYTE_PATTERNS = _byte_patterns(SECRET_TEXT_PATTERNS)
PATH_BYTE_PATTERNS = _byte_patterns(PATH_TEXT_PATTERNS)

# Release scanning deliberately limits path checks to private-machine locations.
# Source trees legitimately contain URL routes and portable POSIX paths; bundle
# values do not have that ambiguity and use the full detector above.
RELEASE_SECRET_BYTE_PATTERNS = {
    "aws-access-key": re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    "google-api-key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "github-token": re.compile(rb"gh[pousr]_[A-Za-z0-9_]{30,}"),
    "stripe-secret-key": re.compile(
        rb"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"
    ),
    "stripe-webhook-secret": re.compile(rb"whsec_[0-9A-Za-z]{16,}"),
    "private-key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "assigned-secret": re.compile(
        rb"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)"
        rb"\s*[:=]\s*['\"][^'\"\r\n]{12,}['\"]"
    ),
}
RELEASE_PATH_BYTE_PATTERNS = {
    label: PATH_BYTE_PATTERNS[label]
    for label in ("windows-user-path", "posix-user-path", "unc-path")
}


def find_sensitive_text(value: str, *, max_chars: int = MAX_SENSITIVE_TEXT_CHARS) -> list[SensitiveFinding]:
    text = str(value)
    if len(text) > max_chars:
        raise ValueError(f"sensitive-text scan exceeds the {max_chars:,} character limit")
    lowered = text.lower()
    if (
        "/" not in text
        and "\\" not in text
        and not any(marker in lowered for marker in _SENSITIVE_TEXT_MARKERS)
    ):
        return []
    findings = []
    for label, pattern in SENSITIVE_TEXT_PATTERNS.items():
        findings.extend(
            SensitiveFinding(label, match.start(), match.end())
            for match in pattern.finditer(text)
        )
    return sorted(findings, key=lambda item: (item.start, item.end, item.label))


def redact_sensitive_text(
    value: str,
    replacement: str = "[REDACTED]",
    *,
    max_chars: int = MAX_SENSITIVE_TEXT_CHARS,
) -> tuple[str, int]:
    text = str(value)
    if type(max_chars) is not int or max_chars < 1:
        raise ValueError("max_chars must be a positive integer")
    if len(text) > max_chars:
        raise ValueError(
            f"sensitive-text redaction exceeds the {max_chars:,} character limit"
        )
    lowered = text.lower()
    if (
        "/" not in text
        and "\\" not in text
        and not any(marker in lowered for marker in _SENSITIVE_TEXT_MARKERS)
    ):
        return text, 0
    redactions = 0
    for pattern in SENSITIVE_TEXT_PATTERNS.values():
        text, count = pattern.subn(replacement, text)
        redactions += count
    return text, redactions


def redact_sensitive_data(
    value: Any,
    replacement: str = "[REDACTED]",
    *,
    max_chars: int = MAX_SENSITIVE_TEXT_CHARS,
    max_items: int = MAX_SENSITIVE_COLLECTION_ITEMS,
    max_depth: int = MAX_SENSITIVE_DEPTH,
) -> tuple[Any, int]:
    """Return a bounded deep copy with sensitive string values redacted."""

    if type(max_chars) is not int or max_chars < 1:
        raise ValueError("max_chars must be a positive integer")
    if type(max_items) is not int or max_items < 1:
        raise ValueError("max_items must be a positive integer")
    if type(max_depth) is not int or max_depth < 1:
        raise ValueError("max_depth must be a positive integer")

    item_count = 0
    character_count = 0

    def visit(current: Any, depth: int, *, sensitive_key: bool = False) -> tuple[Any, int]:
        nonlocal item_count, character_count
        if depth > max_depth:
            raise ValueError("sensitive-data redaction exceeds the depth limit")
        if sensitive_key and current is not None:
            return replacement, 1
        if isinstance(current, str):
            character_count += len(current)
            if character_count > max_chars:
                raise ValueError("sensitive-data redaction exceeds the character limit")
            redacted, count = redact_sensitive_text(
                current, replacement, max_chars=max_chars
            )
            return redacted, count
        if current is None or type(current) in {bool, int, float}:
            return current, 0
        if isinstance(current, Mapping):
            item_count += len(current)
            if item_count > max_items:
                raise ValueError("sensitive-data redaction exceeds the collection limit")
            result: dict[str, Any] = {}
            redactions = 0
            for key, child in current.items():
                if not isinstance(key, str):
                    raise TypeError("sensitive-data object keys must be strings")
                character_count += len(key)
                if character_count > max_chars:
                    raise ValueError("sensitive-data redaction exceeds the character limit")
                sanitized_key, key_redactions = redact_sensitive_text(
                    key, replacement, max_chars=max_chars
                )
                if sanitized_key in result:
                    raise ValueError(
                        "sensitive-data key collision after redaction"
                    )
                sanitized, count = visit(
                    child,
                    depth + 1,
                    sensitive_key=is_sensitive_field_name(
                        key, include_containers=True
                    ),
                )
                result[sanitized_key] = sanitized
                redactions += key_redactions + count
            return result, redactions
        if isinstance(current, (list, tuple)):
            item_count += len(current)
            if item_count > max_items:
                raise ValueError("sensitive-data redaction exceeds the collection limit")
            result = []
            redactions = 0
            for child in current:
                sanitized, count = visit(child, depth + 1)
                result.append(sanitized)
                redactions += count
            return result, redactions
        raise TypeError("sensitive-data redaction accepts only canonical JSON values")

    return visit(value, 1)


def encrypt_local_payload(
    payload: bytes,
    *,
    key: bytes,
    associated_data: bytes,
) -> dict[str, Any]:
    """Encrypt one bounded local payload using AES-256-GCM."""

    if not isinstance(payload, bytes):
        raise TypeError("local payload must be bytes")
    if len(payload) > MAX_LOCAL_PAYLOAD_BYTES:
        raise ValueError("local payload exceeds the 1 MiB limit")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("local payload key must contain exactly 32 bytes")
    if not isinstance(associated_data, bytes) or not associated_data:
        raise ValueError("local payload associated data must be non-empty bytes")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - required dependency in packaged builds
        raise ValueError("encrypted capture payloads require the cryptography package") from exc
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, payload, associated_data)
    return {
        "ciphertext": ciphertext,
        "nonce": nonce.hex(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "content_encoding": "binary",
        "encryption": "AES-256-GCM",
    }


def decrypt_local_payload(
    ciphertext: bytes,
    *,
    key: bytes,
    nonce_hex: str,
    associated_data: bytes,
) -> bytes:
    """Decrypt one bounded local payload and authenticate its event binding."""

    if not isinstance(ciphertext, bytes) or len(ciphertext) > MAX_LOCAL_PAYLOAD_BYTES + 16:
        raise ValueError("encrypted local payload exceeds the bounded ciphertext limit")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("local payload key must contain exactly 32 bytes")
    if not isinstance(associated_data, bytes) or not associated_data:
        raise ValueError("local payload associated data must be non-empty bytes")
    try:
        nonce = bytes.fromhex(nonce_hex)
    except (TypeError, ValueError) as exc:
        raise ValueError("encrypted local payload nonce is invalid") from exc
    if len(nonce) != 12:
        raise ValueError("encrypted local payload nonce is invalid")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - required dependency in packaged builds
        raise ValueError("encrypted capture payloads require the cryptography package") from exc
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
