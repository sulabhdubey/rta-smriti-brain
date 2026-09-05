"""Bounded, atomic lifecycle review-bundle exports."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .runtime_control import is_safe_regular_file, prepare_control_dir

MAX_REVIEW_BUNDLE_BYTES = 4 * 1024 * 1024
_FORMATS = frozenset({"json", "markdown"})
_PRIVACY_CEILINGS = frozenset({"public", "internal", "sensitive", "restricted"})
_SAFE_TOKEN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,255}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_TRANSACTION_SCHEMA = "rta-smriti.review-bundle-transaction/v1"
_TRANSACTION_AUTH_ALGORITHM = "hmac-sha256"
_TRANSACTION_AUTHORITY_FILE = "authority.key"


def _digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def normalize_audience(value: str) -> str:
    selected = str(value or "").strip().casefold()
    if not _SAFE_TOKEN.fullmatch(selected):
        raise ValueError("audience must be a bounded path-safe token")
    return selected


def normalize_privacy_ceiling(value: str) -> str:
    selected = str(value or "").strip().casefold()
    if selected not in _PRIVACY_CEILINGS:
        raise ValueError("privacy ceiling is invalid")
    return selected


def normalize_evidence_references(
    references: Sequence[Mapping[str, Any]] | None,
) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for item in references or ():
        if not isinstance(item, Mapping):
            raise TypeError("evidence references must be mappings")
        kind = str(item.get("kind") or "").strip().casefold()
        reference = str(item.get("reference") or "").strip()
        digest = str(item.get("digest") or "").strip().casefold()
        if (
            not _SAFE_TOKEN.fullmatch(kind)
            or not _SAFE_TOKEN.fullmatch(reference)
            or not _SHA256.fullmatch(digest)
            or Path(reference).is_absolute()
            or "/" in reference
            or "\\" in reference
            or reference in {".", ".."}
        ):
            raise ValueError("evidence reference must be path-safe and digest-bound")
        normalized.append(
            {"kind": kind, "reference": reference, "digest": digest}
        )
    by_identity: dict[tuple[str, str, str], dict[str, str]] = {}
    digest_by_reference: dict[tuple[str, str], str] = {}
    for item in normalized:
        reference_identity = (item["kind"], item["reference"])
        previous_digest = digest_by_reference.get(reference_identity)
        if previous_digest is not None and previous_digest != item["digest"]:
            raise ValueError("evidence reference has conflicting digest bindings")
        digest_by_reference[reference_identity] = item["digest"]
        by_identity[(item["kind"], item["reference"], item["digest"])] = item
    return sorted(
        by_identity.values(),
        key=lambda item: (item["kind"], item["reference"], item["digest"]),
    )


def normalize_redaction_manifest(
    entries: Sequence[Mapping[str, Any]] | None,
) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for item in entries or ():
        if not isinstance(item, Mapping):
            raise TypeError("redaction entries must be mappings")
        field = str(item.get("field") or "").strip().casefold()
        action = str(item.get("action") or "").strip().casefold()
        if not _SAFE_TOKEN.fullmatch(field) or not _SAFE_TOKEN.fullmatch(action):
            raise ValueError("redaction manifest entries must be path-safe tokens")
        normalized.append({"field": field, "action": action})
    return sorted(
        {(item["field"], item["action"]): item for item in normalized}.values(),
        key=lambda item: (item["field"], item["action"]),
    )


def _markdown(bundle: Mapping[str, Any]) -> str:
    lines = [
        "# Rta-Smriti Trusted Lifecycle Review",
        "",
        "**Non-authoritative operational summary.** Verify the cited evidence before making a release or recovery decision.",
        "",
        f"- Schema: `{bundle.get('schema', 'unknown')}`",
        f"- Audience: `{bundle.get('audience', 'unknown')}`",
        f"- Privacy ceiling: `{bundle.get('privacy_ceiling', 'unknown')}`",
        f"- Status: `{bundle.get('status', 'unknown')}`",
        f"- Enrollment: `{bundle.get('enrollment_state', 'unknown')}`",
        f"- Bundle digest: `{bundle.get('bundle_digest', 'unsealed')}`",
        "",
        "## Health Axes",
        "",
    ]
    axes = bundle.get("health_axes")
    if isinstance(axes, Mapping):
        for name, payload in sorted(axes.items()):
            state = payload.get("state", "unknown") if isinstance(payload, Mapping) else "unknown"
            lines.append(f"- `{name}`: `{state}`")
    lines.extend(["", "## Evidence References", ""])
    references = bundle.get("evidence_reference_manifest")
    if isinstance(references, list) and references:
        for item in references:
            if isinstance(item, Mapping):
                lines.append(
                    f"- `{item.get('kind')}` `{item.get('reference')}` "
                    f"SHA-256 `{item.get('digest')}`"
                )
    else:
        lines.append("- None recorded.")
    lines.extend(["", "## Redaction Manifest", ""])
    redactions = bundle.get("redaction_manifest")
    if isinstance(redactions, list) and redactions:
        for item in redactions:
            if isinstance(item, Mapping):
                lines.append(f"- `{item.get('field')}`: `{item.get('action')}`")
    else:
        lines.append("- None recorded.")
    lines.extend(["", "## Lifecycle Receipts", ""])
    receipts = bundle.get("receipts")
    if isinstance(receipts, list) and receipts:
        for receipt in receipts:
            if isinstance(receipt, Mapping):
                lines.append(
                    f"- `{receipt.get('operation_id')}`: `{receipt.get('state')}` "
                    f"({receipt.get('execution_kind') or 'operation'})"
                )
    else:
        lines.append("- None recorded.")
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not is_safe_regular_file(path):
        raise PermissionError("review-bundle destination is linked or unsafe")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.stem}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _stage_bytes(parent: Path, prefix: str, suffix: str, content: bytes) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=parent,
        prefix=prefix,
        suffix=suffix,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _stage_backup(path: Path, *, prefix: str, parent: Path | None = None) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=parent or path.parent,
        prefix=prefix,
        suffix=".bak",
    )
    backup = Path(temporary_name)
    try:
        with path.open("rb") as source, os.fdopen(descriptor, "wb") as destination:
            shutil.copyfileobj(source, destination)
            destination.flush()
            os.fsync(destination.fileno())
        return backup
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        backup.unlink(missing_ok=True)
        raise


def _transaction_path(base: Path) -> Path:
    return base.with_name(f".{base.name}.review-bundle-transaction.json")


def _transaction_directory(base: Path) -> Path:
    return base.with_name(f".{base.name}.review-bundle-transaction")


def _transaction_authority_path(base: Path) -> Path:
    return _transaction_directory(base) / _TRANSACTION_AUTHORITY_FILE


def _safe_transaction_directory(base: Path, *, create: bool) -> Path:
    directory = _transaction_directory(base)
    if create:
        try:
            prepare_control_dir(directory, label="review-bundle transaction")
        except (OSError, ValueError) as exc:
            raise PermissionError(
                "review-bundle recovery journal is invalid"
            ) from exc
    try:
        info = directory.lstat()
    except OSError as exc:
        raise PermissionError(
            "review-bundle recovery journal is invalid"
        ) from exc
    reparse = bool(int(getattr(info, "st_file_attributes", 0)) & 0x400)
    if directory.is_symlink() or reparse or not stat.S_ISDIR(info.st_mode):
        raise PermissionError("review-bundle recovery journal is invalid")
    if not create:
        try:
            prepare_control_dir(directory, label="review-bundle transaction")
            refreshed = directory.lstat()
        except (OSError, ValueError) as exc:
            raise PermissionError(
                "review-bundle recovery journal is invalid"
            ) from exc
        refreshed_reparse = bool(
            int(getattr(refreshed, "st_file_attributes", 0)) & 0x400
        )
        if (
            directory.is_symlink()
            or refreshed_reparse
            or not stat.S_ISDIR(refreshed.st_mode)
            or (int(refreshed.st_dev), int(refreshed.st_ino))
            != (int(info.st_dev), int(info.st_ino))
        ):
            raise PermissionError("review-bundle recovery journal is invalid")
    return directory


def _create_transaction_authority(base: Path) -> bytes:
    directory = _safe_transaction_directory(base, create=False)
    authority = _transaction_authority_path(base)
    key = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    descriptor = os.open(authority, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        authority.unlink(missing_ok=True)
        raise
    if authority.parent != directory or not is_safe_regular_file(authority):
        authority.unlink(missing_ok=True)
        raise PermissionError("review-bundle recovery journal is invalid")
    return key


def _load_transaction_authority(base: Path) -> bytes:
    directory = _safe_transaction_directory(base, create=False)
    authority = _transaction_authority_path(base)
    if authority.parent != directory or not is_safe_regular_file(authority):
        raise PermissionError("review-bundle recovery journal is invalid")
    try:
        key = authority.read_bytes()
    except OSError as exc:
        raise PermissionError("review-bundle recovery journal is invalid") from exc
    if len(key) != 32:
        raise PermissionError("review-bundle recovery journal is invalid")
    return key


def _transaction_body(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(name): value
        for name, value in payload.items()
        if name != "authentication"
    }


def _authenticated_transaction_payload(
    payload: Mapping[str, Any], key: bytes
) -> dict[str, Any]:
    body = _transaction_body(payload)
    signature = hmac.digest(key, _stable_transaction_json(body), "sha256").hex()
    return {
        **body,
        "authentication": {
            "algorithm": _TRANSACTION_AUTH_ALGORITHM,
            "key_id": hashlib.sha256(key).hexdigest(),
            "signature": signature,
        },
    }


def _verify_transaction_authentication(base: Path, payload: Mapping[str, Any]) -> None:
    authentication = payload.get("authentication")
    if not isinstance(authentication, Mapping):
        raise PermissionError("review-bundle recovery journal is invalid")
    key = _load_transaction_authority(base)
    if (
        authentication.get("algorithm") != _TRANSACTION_AUTH_ALGORITHM
        or not hmac.compare_digest(
            str(authentication.get("key_id") or ""),
            hashlib.sha256(key).hexdigest(),
        )
    ):
        raise PermissionError("review-bundle recovery journal is invalid")
    supplied = str(authentication.get("signature") or "")
    expected = hmac.digest(
        key,
        _stable_transaction_json(_transaction_body(payload)),
        "sha256",
    ).hex()
    if not _SHA256.fullmatch(supplied) or not hmac.compare_digest(
        supplied, expected
    ):
        raise PermissionError("review-bundle recovery journal is invalid")


def _file_digest(path: Path) -> str:
    if not is_safe_regular_file(path):
        raise PermissionError("review-bundle transaction artifact is invalid")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise PermissionError(
            "review-bundle transaction artifact is invalid"
        ) from exc
    if not is_safe_regular_file(path):
        raise PermissionError("review-bundle transaction artifact is invalid")
    return digest.hexdigest()


def _transaction_artifact(
    directory: Path,
    base: Path,
    selected: str,
    name: str,
    suffix: str,
) -> Path:
    prefix = f"{selected}."
    if (
        not name.startswith(prefix)
        or not name.endswith(suffix)
        or not _SAFE_TOKEN.fullmatch(name)
    ):
        raise PermissionError("review-bundle recovery journal is invalid")
    middle = name[len(prefix) : -len(suffix)]
    if not middle or "." in middle:
        raise PermissionError("review-bundle recovery journal is invalid")
    candidate = directory / name
    if candidate.parent != directory or candidate == base:
        raise PermissionError("review-bundle recovery journal is invalid")
    return candidate


def _transaction_entries(base: Path, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    if payload.get("schema") != _TRANSACTION_SCHEMA:
        raise PermissionError("review-bundle recovery journal is invalid")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise PermissionError("review-bundle recovery journal is invalid")
    allowed_targets = {
        base.with_suffix(".json").name,
        base.with_suffix(".md").name,
    }
    seen_targets: set[str] = set()
    validated: list[dict[str, Any]] = []
    directory = _safe_transaction_directory(base, create=False)
    for item in entries:
        if not isinstance(item, Mapping):
            raise PermissionError("review-bundle recovery journal is invalid")
        target_name = str(item.get("target") or "")
        staged_name = str(item.get("staged") or "")
        backup_name = str(item.get("backup") or "")
        staged_digest = str(item.get("staged_digest") or "")
        backup_digest = str(item.get("backup_digest") or "")
        existed = item.get("existed")
        if (
            target_name not in allowed_targets
            or not staged_name
            or existed not in {True, False}
            or (bool(backup_name) != bool(existed))
            or not _SHA256.fullmatch(staged_digest)
            or (bool(backup_digest) != bool(existed))
            or (backup_digest and not _SHA256.fullmatch(backup_digest))
            or target_name in seen_targets
        ):
            raise PermissionError("review-bundle recovery journal is invalid")
        selected = "json" if target_name == base.with_suffix(".json").name else "markdown"
        staged = _transaction_artifact(
            directory, base, selected, staged_name, ".new"
        )
        backup = (
            _transaction_artifact(
                directory, base, selected, backup_name, ".bak"
            )
            if backup_name
            else None
        )
        seen_targets.add(target_name)
        validated.append(
            {
                "target": base.parent / target_name,
                "staged": staged,
                "backup": backup,
                "existed": bool(existed),
                "staged_digest": staged_digest,
                "backup_digest": backup_digest or None,
            }
        )
    return validated


def _validate_transaction_inventory(
    base: Path,
    entries: Sequence[Mapping[str, Any]],
    *,
    require_authority: bool = True,
) -> Path:
    directory = _safe_transaction_directory(base, create=False)
    expected = {
        Path(path)
        for item in entries
        for path in (item.get("staged"), item.get("backup"))
        if path is not None
    }
    authority = _transaction_authority_path(base)
    if require_authority:
        if not is_safe_regular_file(authority):
            raise PermissionError("review-bundle transaction inventory is invalid")
        expected.add(authority)
    try:
        for index, child in enumerate(directory.iterdir()):
            if (
                index >= len(expected)
                or child not in expected
                or not is_safe_regular_file(child)
            ):
                raise PermissionError(
                    "review-bundle transaction inventory is invalid"
                )
    except OSError as exc:
        raise PermissionError(
            "review-bundle transaction inventory is invalid"
        ) from exc
    return directory


def _cleanup_transaction(
    journal: Path, entries: Sequence[Mapping[str, Any]]
) -> None:
    base = journal.with_name(
        journal.name.removeprefix(".").removesuffix(
            ".review-bundle-transaction.json"
        )
    )
    directory = _validate_transaction_inventory(base, entries)
    for item in entries:
        staged = Path(item["staged"])
        if staged.exists():
            if not is_safe_regular_file(staged):
                raise PermissionError("review-bundle transaction artifact is unsafe")
            staged.unlink()
        backup = item.get("backup")
        if backup is not None and Path(backup).exists():
            if not is_safe_regular_file(Path(backup)):
                raise PermissionError("review-bundle transaction artifact is unsafe")
            Path(backup).unlink()
    if journal.exists():
        if not is_safe_regular_file(journal):
            raise PermissionError("review-bundle recovery journal is invalid")
        journal.unlink()
    authority = _transaction_authority_path(base)
    if not is_safe_regular_file(authority):
        raise PermissionError("review-bundle recovery journal is invalid")
    authority.unlink()
    directory.rmdir()


def _validate_recovery_artifacts(
    entries: Sequence[Mapping[str, Any]], *, phase: str
) -> None:
    for item in entries:
        staged = Path(item["staged"])
        if staged.exists() and not hmac.compare_digest(
            _file_digest(staged), str(item["staged_digest"])
        ):
            raise PermissionError("review-bundle transaction artifact is invalid")
        backup = item.get("backup")
        if backup is not None:
            backup_path = Path(backup)
            if not backup_path.exists() or not hmac.compare_digest(
                _file_digest(backup_path), str(item["backup_digest"])
            ):
                raise PermissionError(
                    "review-bundle transaction artifact is invalid"
                )
        target = Path(item["target"])
        if not target.exists():
            if phase == "committed":
                raise PermissionError(
                    "review-bundle transaction artifact is invalid"
                )
            continue
        target_digest = _file_digest(target)
        allowed = {str(item["staged_digest"])}
        if item.get("backup_digest"):
            allowed.add(str(item["backup_digest"]))
        if target_digest not in allowed:
            raise PermissionError("review-bundle transaction artifact is invalid")
        if phase == "committed" and target_digest != item["staged_digest"]:
            raise PermissionError("review-bundle transaction artifact is invalid")


def _recover_transaction(base: Path) -> None:
    journal = _transaction_path(base)
    if not journal.exists() and not journal.is_symlink():
        return
    if not is_safe_regular_file(journal):
        raise PermissionError("review-bundle recovery journal is invalid")
    try:
        raw = journal.read_bytes()
        if len(raw) > 64 * 1024:
            raise PermissionError("review-bundle recovery journal exceeds its bound")
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PermissionError("review-bundle recovery journal is invalid") from exc
    if not isinstance(payload, Mapping):
        raise PermissionError("review-bundle recovery journal is invalid")
    _verify_transaction_authentication(base, payload)
    entries = _transaction_entries(base, payload)
    if payload.get("phase") == "committed":
        _validate_recovery_artifacts(entries, phase="committed")
        _cleanup_transaction(journal, entries)
        return
    if payload.get("phase") != "prepared":
        raise PermissionError("review-bundle recovery journal is invalid")
    _validate_recovery_artifacts(entries, phase="prepared")
    for item in reversed(entries):
        target = Path(item["target"])
        if item["existed"]:
            backup = Path(item["backup"])
            if not is_safe_regular_file(backup):
                raise PermissionError("review-bundle rollback backup is unavailable")
            restore = _stage_backup(
                backup,
                prefix=f".{base.name}.restore.",
            )
            try:
                os.replace(restore, target)
            except BaseException:
                restore.unlink(missing_ok=True)
                raise
        else:
            if target.exists():
                if not is_safe_regular_file(target):
                    raise PermissionError("review-bundle rollback target is unsafe")
                target.unlink()
    _cleanup_transaction(journal, entries)


def _publish_transaction(
    base: Path,
    outputs: Sequence[tuple[str, Path, bytes]],
) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    _recover_transaction(base)
    journal = _transaction_path(base)
    directory = _safe_transaction_directory(base, create=True)
    _validate_transaction_inventory(base, (), require_authority=False)
    authority_key = _create_transaction_authority(base)
    _validate_transaction_inventory(base, ())
    entries: list[dict[str, Any]] = []
    try:
        for selected, target, content in outputs:
            if target.exists() and not is_safe_regular_file(target):
                raise PermissionError("review-bundle target must be a safe regular file")
            staged = _stage_bytes(
                directory,
                f"{selected}.",
                ".new",
                content,
            )
            existed = target.exists()
            backup = (
                _stage_backup(target, prefix=f"{selected}.", parent=directory)
                if existed
                else None
            )
            entries.append(
                {
                    "target": target,
                    "staged": staged,
                    "backup": backup,
                    "existed": existed,
                    "staged_digest": _file_digest(staged),
                    "backup_digest": _file_digest(backup) if backup else None,
                }
            )
        journal_payload = {
            "schema": _TRANSACTION_SCHEMA,
            "phase": "prepared",
            "entries": [
                {
                    "target": Path(item["target"]).name,
                    "staged": Path(item["staged"]).name,
                    "backup": (
                        Path(item["backup"]).name
                        if item["backup"] is not None
                        else None
                    ),
                    "existed": item["existed"],
                    "staged_digest": item["staged_digest"],
                    "backup_digest": item["backup_digest"],
                }
                for item in entries
            ],
        }
        _atomic_write(
            journal,
            _stable_transaction_json(
                _authenticated_transaction_payload(journal_payload, authority_key)
            ),
        )
    except BaseException:
        _cleanup_transaction(journal, entries)
        raise
    try:
        for item in entries:
            os.replace(item["staged"], item["target"])
        journal_payload["phase"] = "committed"
        _atomic_write(
            journal,
            _stable_transaction_json(
                _authenticated_transaction_payload(journal_payload, authority_key)
            ),
        )
        _cleanup_transaction(journal, entries)
    except Exception as publish_error:
        try:
            _recover_transaction(base)
        except OSError:
            raise RuntimeError(
                "review-bundle publication failed and requires recovery"
            ) from publish_error
        raise


def _stable_transaction_json(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def write_review_bundle(
    bundle: Mapping[str, Any],
    destination: str | Path,
    *,
    formats: Sequence[str] = ("json", "markdown"),
    max_output_bytes: int = 1_048_576,
) -> dict[str, Any]:
    """Write a versioned review bundle in the selected portable formats."""

    selected_formats = tuple(dict.fromkeys(str(item).strip().casefold() for item in formats))
    if not selected_formats or any(item not in _FORMATS for item in selected_formats):
        raise ValueError("formats must contain json and/or markdown")
    limit = int(max_output_bytes)
    if limit < 1 or limit > MAX_REVIEW_BUNDLE_BYTES:
        raise ValueError("review-bundle size limit is invalid")
    body = dict(bundle)
    supplied_digest = str(body.pop("bundle_digest", ""))
    if not _SHA256.fullmatch(supplied_digest) or _digest(body) != supplied_digest:
        raise ValueError("review-bundle digest is invalid")
    sealed = {**body, "bundle_digest": supplied_digest}
    rendered = {
        "json": (
            json.dumps(sealed, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode("utf-8"),
        "markdown": _markdown(sealed).encode("utf-8"),
    }
    for selected in selected_formats:
        if len(rendered[selected]) > limit:
            raise ValueError("review-bundle output exceeds the size limit")

    base = Path(destination).expanduser().resolve()
    suffixes = {"json": ".json", "markdown": ".md"}
    outputs: list[tuple[str, Path, bytes]] = []
    files: dict[str, str] = {}
    for selected in selected_formats:
        path = base.with_suffix(suffixes[selected])
        outputs.append((selected, path, rendered[selected]))
        files[selected] = str(path)
    _publish_transaction(base, outputs)
    return {
        "status": "ok",
        "schema": str(sealed.get("schema") or "unknown"),
        "bundle_digest": supplied_digest,
        "files": files,
    }
