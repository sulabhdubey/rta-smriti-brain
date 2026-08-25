from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import db
from .repository import canonical_root, same_root
from .temporal import VALID_PRIVACY_CLASSES


DEFAULT_MAX_MEDIA_BYTES = 32 * 1024 * 1024
HARD_MAX_MEDIA_BYTES = 256 * 1024 * 1024
MAX_DERIVATION_BYTES = 64 * 1024
VALID_VERIFICATION_STATES = {"unverified", "verified", "failed", "stale"}
MEDIA_BY_SUFFIX = {
    ".pdf": "pdf",
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".webp": "image",
    ".svg": "diagram",
    ".wav": "audio",
    ".mp3": "audio",
    ".m4a": "audio",
    ".flac": "audio",
    ".ogg": "audio",
    ".mp4": "video",
    ".mov": "video",
    ".webm": "video",
    ".mkv": "video",
    ".docx": "document",
    ".pptx": "document",
}


def _bounded_text(name: str, value: Any, maximum: int, *, required: bool = True) -> str:
    selected = str(value or "").strip()
    if required and not selected:
        raise ValueError(f"{name} is required")
    if len(selected) > maximum:
        raise ValueError(f"{name} must be at most {maximum} characters")
    return selected


def _json_object(value: dict[str, Any] | None, *, maximum_bytes: int = 32 * 1024) -> str:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise TypeError("metadata must be an object")
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > maximum_bytes:
        raise ValueError("metadata exceeds its bounded size")
    return encoded


def _is_reparse_point(info: os.stat_result) -> bool:
    return bool(int(getattr(info, "st_file_attributes", 0)) & 0x400)


def _project(conn, project: str) -> tuple[int, Path]:
    row = conn.execute(
        "SELECT id, root_path FROM projects WHERE name = ?", (project,)
    ).fetchone()
    if row is None or not row["root_path"]:
        raise ValueError(f"project has no canonical root: {project}")
    return int(row["id"]), Path(str(row["root_path"])).resolve()


def _stable_media_read(path: Path, *, maximum_bytes: int) -> tuple[bytes, os.stat_result]:
    expected = path.lstat()
    if (
        not stat.S_ISREG(expected.st_mode) or path.is_symlink()
        or _is_reparse_point(expected) or expected.st_nlink != 1
    ):
        raise PermissionError("media source must be an unlinked regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (expected.st_dev, expected.st_ino):
            raise PermissionError(
                "media source identity changed before it was opened"
            )
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or _is_reparse_point(before):
            raise PermissionError("media source must be an unlinked regular file")
        if before.st_size > maximum_bytes:
            raise ValueError(f"media source exceeds {maximum_bytes} bytes")
        chunks: list[bytes] = []
        remaining = int(before.st_size) + 1
        while remaining > 0:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise RuntimeError("media source changed while it was being read")
        if len(payload) != before.st_size:
            raise RuntimeError("media source read was incomplete")
        return payload, before
    finally:
        os.close(descriptor)


def _validate_media_signature(payload: bytes, suffix: str, media_kind: str) -> None:
    head = payload[:4096]
    accepted = False
    if suffix == ".pdf":
        accepted = head.startswith(b"%PDF-")
    elif suffix == ".png":
        accepted = head.startswith(b"\x89PNG\r\n\x1a\n")
    elif suffix in {".jpg", ".jpeg"}:
        accepted = head.startswith(b"\xff\xd8\xff")
    elif suffix == ".gif":
        accepted = head.startswith((b"GIF87a", b"GIF89a"))
    elif suffix == ".webp":
        accepted = len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    elif suffix == ".svg":
        accepted = bool(re.search(rb"<svg(?:\s|>)", head, flags=re.IGNORECASE))
    elif suffix == ".wav":
        accepted = len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WAVE"
    elif suffix == ".mp3":
        accepted = head.startswith(b"ID3") or (
            len(head) >= 2 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0
        )
    elif suffix == ".flac":
        accepted = head.startswith(b"fLaC")
    elif suffix == ".ogg":
        accepted = head.startswith(b"OggS")
    elif suffix in {".mp4", ".mov", ".m4a"}:
        accepted = len(head) >= 12 and head[4:8] == b"ftyp"
    elif suffix in {".webm", ".mkv"}:
        accepted = head.startswith(b"\x1aE\xdf\xa3")
    elif suffix in {".docx", ".pptx"}:
        accepted = head.startswith(b"PK\x03\x04")
    if media_kind == "unknown":
        raise ValueError(f"unsupported multimodal source extension: {suffix or '<none>'}")
    if not accepted:
        raise ValueError(f"media source signature does not match {suffix}")


def _bound_project(
    conn, project: str, active_root: str | Path
) -> tuple[int, Path]:
    project_id, bound_root = _project(conn, project)
    requested_root = Path(canonical_root(active_root))
    if not same_root(bound_root, requested_root):
        raise ValueError("active root does not match the canonical project binding")
    return project_id, requested_root


def _require_operator(actor_type: str, actor_id: str) -> str:
    if str(actor_type or "").strip().casefold() != "operator":
        raise PermissionError("multimodal lifecycle changes require operator authority")
    return _bounded_text("actor_id", actor_id, 300)


def _instant(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _metadata(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _safe_source_path(root: Path, source_identifier: str) -> Path:
    candidate = root / source_identifier
    if candidate.is_symlink():
        raise PermissionError("linked media sources are not allowed")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PermissionError("media source must remain inside the canonical root") from exc
    return resolved


def ingest_media(
    conn,
    *,
    project: str,
    active_root: str | Path,
    path: str | Path,
    privacy_class: str = "internal",
    sharing_policy: str = "local-only",
    metadata: dict[str, Any] | None = None,
    maximum_bytes: int = DEFAULT_MAX_MEDIA_BYTES,
) -> dict[str, Any]:
    """Register one bounded local media source without interpreting its content."""

    db.init_schema(conn)
    project_id, requested_root = _bound_project(conn, project, active_root)
    requested = Path(path).expanduser()
    candidate = requested if requested.is_absolute() else requested_root / requested
    if candidate.is_symlink():
        raise PermissionError("linked media sources are not allowed")
    resolved = candidate.resolve(strict=True)
    try:
        relative = resolved.relative_to(requested_root).as_posix()
    except ValueError as exc:
        raise PermissionError("media source must remain inside the canonical root") from exc
    selected_limit = int(maximum_bytes)
    if selected_limit <= 0 or selected_limit > HARD_MAX_MEDIA_BYTES:
        raise ValueError(f"maximum_bytes must be between 1 and {HARD_MAX_MEDIA_BYTES}")
    selected_privacy = str(privacy_class).strip().lower()
    if selected_privacy not in VALID_PRIVACY_CLASSES:
        raise ValueError(f"unsupported privacy class: {privacy_class}")
    payload, info = _stable_media_read(resolved, maximum_bytes=selected_limit)
    suffix = resolved.suffix.casefold()
    media_kind = MEDIA_BY_SUFFIX.get(suffix, "unknown")
    _validate_media_signature(payload, suffix, media_kind)
    content_hash = hashlib.sha256(payload).hexdigest()
    mime_type = mimetypes.guess_type(resolved.name)[0] or "application/octet-stream"
    source_id = hashlib.sha256(
        f"{project_id}\0{relative}\0{content_hash}".encode("utf-8")
    ).hexdigest()[:32]
    now = db.now_iso()
    metadata_json = _json_object(
        {
            **(metadata or {}),
            "extension": suffix,
            "mtime_ns": int(info.st_mtime_ns),
        }
    )
    conn.execute(
        """
        INSERT INTO multimodal_sources(
            project_id, source_id, source_identifier, media_kind, mime_type,
            content_sha256, byte_size, metadata_json, privacy_class,
            sharing_policy, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(project_id, source_id) DO UPDATE SET
            metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at
        """,
        (
            project_id,
            source_id,
            relative,
            media_kind,
            mime_type,
            content_hash,
            int(info.st_size),
            metadata_json,
            selected_privacy,
            _bounded_text("sharing_policy", sharing_policy, 128),
            now,
            now,
        ),
    )
    conn.commit()
    return {
        "status": "ok",
        "source_id": source_id,
        "source_identifier": relative,
        "media_kind": media_kind,
        "mime_type": mime_type,
        "content_sha256": content_hash,
        "byte_size": int(info.st_size),
        "privacy_class": selected_privacy,
        "sharing_policy": str(sharing_policy),
    }


def add_derivation(
    conn,
    *,
    project: str,
    source_id: str,
    method: str,
    text: str,
    confidence: float,
    verification_status: str,
    tool_identity: str,
    model_identity: str | None = None,
    derivation_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    actor_type: str | None = None,
    actor_id: str | None = None,
) -> dict[str, Any]:
    """Store a bounded interpretation while preserving its unverified boundary."""

    db.init_schema(conn)
    project_id, _root = _project(conn, project)
    selected_source_id = _bounded_text("source_id", source_id, 128)
    source = conn.execute(
        """
        SELECT content_sha256, privacy_class, sharing_policy
        FROM multimodal_sources WHERE project_id = ? AND source_id = ?
        """,
        (project_id, selected_source_id),
    ).fetchone()
    if source is None:
        raise ValueError(f"multimodal source does not exist: {selected_source_id}")
    selected_text = _bounded_text("text", text, MAX_DERIVATION_BYTES)
    if len(selected_text.encode("utf-8")) > MAX_DERIVATION_BYTES:
        raise ValueError("derived text exceeds 64 KiB")
    selected_tool = _bounded_text("tool_identity", tool_identity, 256)
    selected_verification = str(verification_status).strip().lower()
    if selected_verification not in VALID_VERIFICATION_STATES:
        raise ValueError(f"unsupported verification status: {verification_status}")
    if selected_verification == "verified" and (
        selected_tool.casefold().startswith("model:") or model_identity
    ):
        raise PermissionError("model-derived observations cannot self-promote to verified truth")
    selected_metadata = dict(metadata or {})
    if selected_verification == "verified":
        selected_actor = _require_operator(str(actor_type or ""), str(actor_id or ""))
        selected_metadata.update({
            "verified_by_sha256": hashlib.sha256(
                selected_actor.encode("utf-8")
            ).hexdigest(),
            "verified_at": db.now_iso(),
        })
    selected_confidence = float(confidence)
    if not 0.0 <= selected_confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")
    selected_derivation_id = _bounded_text(
        "derivation_id", derivation_id or uuid.uuid4().hex, 128
    )
    output_hash = hashlib.sha256(selected_text.encode("utf-8")).hexdigest()
    now = db.now_iso()
    conn.execute(
        """
        INSERT INTO multimodal_derivations(
            project_id, derivation_id, source_id, method, tool_identity,
            model_identity, source_sha256, output_sha256, text, confidence,
            verification_status, metadata_json, privacy_class, sharing_policy,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            selected_derivation_id,
            selected_source_id,
            _bounded_text("method", method, 256),
            selected_tool,
            _bounded_text("model_identity", model_identity, 256, required=False) or None,
            str(source["content_sha256"]),
            output_hash,
            selected_text,
            selected_confidence,
            selected_verification,
            _json_object(selected_metadata),
            str(source["privacy_class"]),
            str(source["sharing_policy"]),
            now,
        ),
    )
    conn.commit()
    return {
        "status": "ok",
        "derivation_id": selected_derivation_id,
        "source_id": selected_source_id,
        "source_sha256": str(source["content_sha256"]),
        "output_sha256": output_hash,
        "method": str(method),
        "verification_status": selected_verification,
        "confidence": selected_confidence,
    }


def list_multimodal_evidence(conn, *, project: str, limit: int = 100) -> dict[str, Any]:
    db.init_schema(conn)
    project_id, _root = _project(conn, project)
    selected_limit = max(1, min(250, int(limit)))
    total = int(conn.execute(
        "SELECT COUNT(*) AS count FROM multimodal_sources WHERE project_id = ?",
        (project_id,),
    ).fetchone()["count"])
    rows = conn.execute(
        """
        SELECT s.source_id, s.source_identifier, s.media_kind, s.mime_type,
               s.content_sha256, s.byte_size, s.privacy_class, s.sharing_policy,
               s.updated_at, COUNT(d.id) AS derivation_count,
               SUM(CASE WHEN d.verification_status = 'verified' THEN 1 ELSE 0 END)
                   AS verified_derivations
        FROM multimodal_sources s
        LEFT JOIN multimodal_derivations d
          ON d.project_id = s.project_id AND d.source_id = s.source_id
        WHERE s.project_id = ?
        GROUP BY s.id
        ORDER BY s.updated_at DESC, s.source_id
        LIMIT ?
        """,
        (project_id, selected_limit),
    ).fetchall()
    return {
        "status": "ok",
        "project": project,
        "count": total,
        "truncated": total > len(rows),
        "items": [
            {
                "source_id": str(row["source_id"]),
                "source_identifier": str(row["source_identifier"]),
                "media_kind": str(row["media_kind"]),
                "mime_type": str(row["mime_type"]),
                "content_sha256": str(row["content_sha256"]),
                "byte_size": int(row["byte_size"]),
                "privacy_class": str(row["privacy_class"]),
                "sharing_policy": str(row["sharing_policy"]),
                "derivation_count": int(row["derivation_count"] or 0),
                "verified_derivations": int(row["verified_derivations"] or 0),
                "updated_at": str(row["updated_at"]),
            }
            for row in rows
        ],
    }


def list_multimodal_derivations(
    conn,
    *,
    project: str,
    source_id: str,
    include_text: bool = False,
    limit: int = 100,
) -> dict[str, Any]:
    db.init_schema(conn)
    project_id, _root = _project(conn, project)
    selected_source = _bounded_text("source_id", source_id, 128)
    selected_limit = max(1, min(250, int(limit)))
    rows = conn.execute(
        """
        SELECT derivation_id, source_id, method, tool_identity, model_identity,
               source_sha256, output_sha256, text, confidence, verification_status,
               metadata_json, privacy_class, sharing_policy, created_at
        FROM multimodal_derivations
        WHERE project_id = ? AND source_id = ?
        ORDER BY created_at DESC, derivation_id LIMIT ?
        """,
        (project_id, selected_source, selected_limit),
    ).fetchall()
    items = []
    for row in rows:
        item = {
            "derivation_id": str(row["derivation_id"]),
            "source_id": str(row["source_id"]),
            "method": str(row["method"]),
            "tool_identity": str(row["tool_identity"]),
            "model_identity": row["model_identity"],
            "source_sha256": str(row["source_sha256"]),
            "output_sha256": str(row["output_sha256"]),
            "confidence": float(row["confidence"]),
            "verification_status": str(row["verification_status"]),
            "privacy_class": str(row["privacy_class"]),
            "sharing_policy": str(row["sharing_policy"]),
            "created_at": str(row["created_at"]),
            "redacted": bool(_metadata(row["metadata_json"]).get("redacted")),
        }
        if include_text:
            item["text"] = str(row["text"])
        items.append(item)
    return {"status": "ok", "project": project, "source_id": selected_source, "items": items}


def verify_multimodal_source(
    conn,
    *,
    project: str,
    active_root: str | Path,
    source_id: str,
    maximum_bytes: int = HARD_MAX_MEDIA_BYTES,
) -> dict[str, Any]:
    """Compare one registered source with disk without updating stored evidence."""
    db.init_schema(conn)
    project_id, root = _bound_project(conn, project, active_root)
    selected_source = _bounded_text("source_id", source_id, 128)
    row = conn.execute(
        """
        SELECT source_identifier, content_sha256, byte_size FROM multimodal_sources
        WHERE project_id = ? AND source_id = ?
        """,
        (project_id, selected_source),
    ).fetchone()
    if row is None:
        raise ValueError("multimodal source does not exist")
    try:
        path = _safe_source_path(root, str(row["source_identifier"]))
    except FileNotFoundError:
        return {"status": "ok", "source_id": selected_source, "state": "missing"}
    payload, info = _stable_media_read(path, maximum_bytes=int(maximum_bytes))
    observed_hash = hashlib.sha256(payload).hexdigest()
    state = "current" if (
        observed_hash == str(row["content_sha256"])
        and int(info.st_size) == int(row["byte_size"])
    ) else "changed"
    return {
        "status": "ok",
        "source_id": selected_source,
        "state": state,
        "expected_sha256": str(row["content_sha256"]),
        "observed_sha256": observed_hash,
        "expected_bytes": int(row["byte_size"]),
        "observed_bytes": int(info.st_size),
    }


def redact_derivation(
    conn,
    *,
    project: str,
    active_root: str | Path,
    derivation_id: str,
    reason: str,
    actor_type: str,
    actor_id: str,
) -> dict[str, Any]:
    db.init_schema(conn)
    project_id, _root = _bound_project(conn, project, active_root)
    selected_actor = _require_operator(actor_type, actor_id)
    selected_derivation = _bounded_text("derivation_id", derivation_id, 128)
    selected_reason = _bounded_text("reason", reason, 4096)
    row = conn.execute(
        """
        SELECT metadata_json, text FROM multimodal_derivations
        WHERE project_id = ? AND derivation_id = ?
        """,
        (project_id, selected_derivation),
    ).fetchone()
    if row is None:
        raise ValueError("multimodal derivation does not exist")
    metadata = _metadata(row["metadata_json"])
    if metadata.get("redacted") and str(row["text"]) == "[redacted]":
        return {"status": "ok", "derivation_id": selected_derivation, "redacted": True, "idempotent_replay": True}
    metadata.update({
        "redacted": True,
        "redaction_reason": selected_reason,
        "redacted_by_sha256": hashlib.sha256(selected_actor.encode("utf-8")).hexdigest(),
        "redacted_at": db.now_iso(),
    })
    replacement = "[redacted]"
    with conn:
        conn.execute(
            """
            UPDATE multimodal_derivations
            SET text = ?, output_sha256 = ?, verification_status = 'stale', metadata_json = ?
            WHERE project_id = ? AND derivation_id = ?
            """,
            (
                replacement, hashlib.sha256(replacement.encode("utf-8")).hexdigest(),
                _json_object(metadata), project_id, selected_derivation,
            ),
        )
    return {"status": "ok", "derivation_id": selected_derivation, "redacted": True, "idempotent_replay": False}


def set_media_retention(
    conn,
    *,
    project: str,
    active_root: str | Path,
    source_id: str,
    retain_until: str,
    actor_type: str,
    actor_id: str,
) -> dict[str, Any]:
    db.init_schema(conn)
    project_id, _root = _bound_project(conn, project, active_root)
    selected_actor = _require_operator(actor_type, actor_id)
    selected_source = _bounded_text("source_id", source_id, 128)
    selected_until = _instant(retain_until, "retain_until").isoformat()
    row = conn.execute(
        "SELECT metadata_json FROM multimodal_sources WHERE project_id = ? AND source_id = ?",
        (project_id, selected_source),
    ).fetchone()
    if row is None:
        raise ValueError("multimodal source does not exist")
    metadata = _metadata(row["metadata_json"])
    metadata.update({
        "retain_until": selected_until,
        "retention_set_by_sha256": hashlib.sha256(selected_actor.encode("utf-8")).hexdigest(),
    })
    now = db.now_iso()
    with conn:
        conn.execute(
            """
            UPDATE multimodal_sources SET metadata_json = ?, updated_at = ?
            WHERE project_id = ? AND source_id = ?
            """,
            (_json_object(metadata), now, project_id, selected_source),
        )
    return {"status": "ok", "source_id": selected_source, "retain_until": selected_until}


def purge_expired_media(
    conn,
    *,
    project: str,
    active_root: str | Path,
    actor_type: str,
    actor_id: str,
    now: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    db.init_schema(conn)
    project_id, _root = _bound_project(conn, project, active_root)
    _require_operator(actor_type, actor_id)
    boundary = _instant(now, "now") if now else datetime.now(timezone.utc)
    eligible = []
    rows = conn.execute(
        """
        SELECT source_id, metadata_json FROM multimodal_sources
        WHERE project_id = ? ORDER BY source_id LIMIT 10000
        """,
        (project_id,),
    ).fetchall()
    for row in rows:
        retain_until = _metadata(row["metadata_json"]).get("retain_until")
        if retain_until and _instant(str(retain_until), "retain_until") <= boundary:
            eligible.append(str(row["source_id"]))
    deleted = []
    if not dry_run and eligible:
        with conn:
            for source_id in eligible:
                conn.execute(
                    "DELETE FROM multimodal_sources WHERE project_id = ? AND source_id = ?",
                    (project_id, source_id),
                )
                deleted.append(source_id)
    return {
        "status": "ok", "project": project, "dry_run": bool(dry_run),
        "eligible": eligible, "deleted": deleted, "truncated": len(rows) >= 10000,
    }


def delete_media(
    conn,
    *,
    project: str,
    active_root: str | Path,
    source_id: str,
    reason: str,
    actor_type: str,
    actor_id: str,
) -> dict[str, Any]:
    db.init_schema(conn)
    project_id, _root = _bound_project(conn, project, active_root)
    _require_operator(actor_type, actor_id)
    selected_source = _bounded_text("source_id", source_id, 128)
    _bounded_text("reason", reason, 4096)
    row = conn.execute(
        "SELECT content_sha256 FROM multimodal_sources WHERE project_id = ? AND source_id = ?",
        (project_id, selected_source),
    ).fetchone()
    if row is None:
        return {"status": "ok", "source_id": selected_source, "deleted": False, "idempotent_replay": True}
    with conn:
        conn.execute(
            "DELETE FROM multimodal_sources WHERE project_id = ? AND source_id = ?",
            (project_id, selected_source),
        )
    return {
        "status": "ok", "source_id": selected_source,
        "content_sha256": str(row["content_sha256"]),
        "deleted": True, "idempotent_replay": False,
    }


def export_multimodal_manifest(
    conn, *, project: str, audience: str = "local", limit: int = 1000
) -> dict[str, Any]:
    """Export evidence metadata only; never export media bytes or derived text."""
    db.init_schema(conn)
    project_id, _root = _project(conn, project)
    selected_audience = str(audience or "").strip().casefold()
    if selected_audience not in {"local", "public"}:
        raise ValueError("audience must be local or public")
    selected_limit = max(1, min(1000, int(limit)))
    rows = conn.execute(
        """
        SELECT source_id, source_identifier, media_kind, mime_type, content_sha256,
               byte_size, privacy_class, sharing_policy, updated_at
        FROM multimodal_sources WHERE project_id = ?
        ORDER BY source_id LIMIT ?
        """,
        (project_id, selected_limit),
    ).fetchall()
    items = []
    redacted = 0
    for row in rows:
        exportable = (
            str(row["privacy_class"]) == "public"
            and str(row["sharing_policy"]).casefold() in {"public", "exportable"}
        )
        if selected_audience == "public" and not exportable:
            redacted += 1
            continue
        items.append({
            "source_id": str(row["source_id"]),
            "source_identifier": str(row["source_identifier"]),
            "media_kind": str(row["media_kind"]),
            "mime_type": str(row["mime_type"]),
            "content_sha256": str(row["content_sha256"]),
            "byte_size": int(row["byte_size"]),
            "privacy_class": str(row["privacy_class"]),
            "sharing_policy": str(row["sharing_policy"]),
            "updated_at": str(row["updated_at"]),
        })
    return {
        "status": "ok", "project": project, "audience": selected_audience,
        "included": len(items), "redacted": redacted, "items": items,
        "truncated": len(rows) >= selected_limit,
        "limitations": ["Manifest export excludes media bytes and derived text."],
    }
