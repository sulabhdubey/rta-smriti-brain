"""Append-only operational continuity for project brains."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from .capture_adapters import (
    _capture_ancestor_guard,
    _stable_adapter_parent,
    _validate_ancestor_guard,
    normalize_capture_event,
)
from .db import ensure_project, integrity_diagnostics, latest_checkpoint, now_iso
from .repository import RepositoryInspection
from .temporal import temporal_readiness

MAX_EVENT_BYTES = 256_000
MAX_CODEX_EVENTS_PER_RUN = 5_000
VALID_VERIFICATION = {"unverified", "verified", "failed", "stale"}
SENSITIVE_EVENT_KEYS = {
    "api_key", "apikey", "authorization", "cookie", "password", "passwd", "secret",
    "set_cookie", "token", "access_token", "accesstoken", "refresh_token", "refreshtoken",
    "client_secret", "clientsecret", "x_api_key", "openai_api_key",
}
SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|token)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)([#?&](?:token|access[_-]?token|api[_-]?key)=)[^&#\s]+"),
    re.compile(r"(?im)^(\s*(?:cookie|set-cookie|authorization)\s*:\s*).+$"),
)
MAX_EVENT_STRING_CHARS = 16_000
MAX_EVENT_LIST_ITEMS = 100
MAX_CODEX_LINE_BYTES = 1_000_000
MAX_SESSION_META_BYTES = 256_000
MAX_SESSION_ID_CHARS = 512
MAX_CURSOR_CHARS = 1_024
MAX_EVENT_TYPE_CHARS = 128
MAX_EVENT_SOURCE_CHARS = 128
MAX_EVENT_NESTING = 64


def reject_windows_network_path(value: str | os.PathLike[str]) -> None:
    """Reject Windows network/device paths lexically before filesystem access."""
    if os.name != "nt":
        return
    raw = os.fspath(value).strip().replace("/", "\\")
    if raw.startswith("\\\\") or raw.casefold().startswith("\\??\\"):
        raise ValueError("Windows network paths are not permitted for session ingestion")


def json_nesting_exceeds(frame: bytes, maximum: int = MAX_EVENT_NESTING) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for byte in frame:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x5B, 0x7B}:
            depth += 1
            if depth > maximum:
                return True
        elif byte in {0x5D, 0x7D}:
            depth = max(0, depth - 1)
    return False


def _validate_event_nesting(value: Any) -> None:
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > MAX_EVENT_NESTING:
            raise ValueError(f"event payload nesting exceeds {MAX_EVENT_NESTING} levels")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)


def _bounded_identifier(name: str, value: Any, maximum: int) -> str:
    selected = str(value).strip()
    if not selected:
        raise ValueError(f"{name} is required")
    if len(selected) > maximum:
        raise ValueError(f"{name} must be at most {maximum} characters")
    return selected


def init_continuity_schema(conn) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS session_events (
            id INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            session_id TEXT NOT NULL,
            cursor TEXT NOT NULL,
            event_type TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            source TEXT NOT NULL,
            source_hash TEXT,
            verification_status TEXT NOT NULL DEFAULT 'unverified',
            occurred_at TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            UNIQUE(project_id, session_id, cursor)
        );
        CREATE TABLE IF NOT EXISTS adapter_cursors (
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            adapter TEXT NOT NULL,
            stream_id TEXT NOT NULL,
            cursor INTEGER NOT NULL,
            source_path TEXT,
            source_hash TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(project_id, adapter, stream_id)
        );
        CREATE TABLE IF NOT EXISTS work_items (
            id INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            item_type TEXT NOT NULL,
            external_id TEXT NOT NULL,
            local_path TEXT,
            qa_state TEXT NOT NULL DEFAULT 'unknown',
            decision TEXT NOT NULL DEFAULT 'pending',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            fallback TEXT NOT NULL DEFAULT '',
            next_action TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            UNIQUE(project_id, item_type, external_id)
        );
        CREATE TABLE IF NOT EXISTS continuity_checkpoint_marks (
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            session_id TEXT NOT NULL,
            event_id INTEGER NOT NULL REFERENCES session_events(id) ON DELETE CASCADE,
            checkpoint_id INTEGER NOT NULL REFERENCES checkpoints(id) ON DELETE CASCADE,
            trigger TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(project_id, session_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_session_events_project_id ON session_events(project_id, id);
        CREATE INDEX IF NOT EXISTS idx_work_items_project_state ON work_items(project_id, decision, qa_state);
        """
    )
    conn.commit()


def _json_text(payload: Any) -> str:
    text = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(text.encode("utf-8")) > MAX_EVENT_BYTES:
        raise ValueError("event payload exceeds the 256 KB limit")
    return text


def _redact_event_value(value: Any, key: str | None = None) -> Any:
    normalized_key = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_") if key else ""
    if normalized_key in SENSITIVE_EVENT_KEYS:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(item_key): _redact_event_value(item_value, str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact_event_value(item) for item in value]
    if isinstance(value, str):
        redacted = value
        for pattern in SECRET_PATTERNS:
            redacted = pattern.sub(
                (lambda match: f"{match.group(1)}[REDACTED]") if pattern.groups else "[REDACTED]",
                redacted,
            )
        return redacted
    return value


def _bound_event_value(value: Any) -> Any:
    if isinstance(value, str):
        if len(value) <= MAX_EVENT_STRING_CHARS:
            return value
        omitted = len(value) - MAX_EVENT_STRING_CHARS
        return value[:MAX_EVENT_STRING_CHARS] + f"\n[TRUNCATED {omitted} CHARACTERS]"
    if isinstance(value, list):
        bounded = [_bound_event_value(item) for item in value[:MAX_EVENT_LIST_ITEMS]]
        if len(value) > MAX_EVENT_LIST_ITEMS:
            bounded.append(f"[TRUNCATED {len(value) - MAX_EVENT_LIST_ITEMS} ITEMS]")
        return bounded
    if isinstance(value, dict):
        return {str(key): _bound_event_value(item) for key, item in value.items()}
    return value


def append_event(
    conn,
    project: str,
    session_id: str,
    cursor: str,
    event_type: str,
    payload: dict[str, Any],
    *,
    source: str = "operator",
    source_hash: str | None = None,
    verification_status: str = "unverified",
    occurred_at: str | None = None,
    _commit: bool = True,
    _project_id: int | None = None,
) -> dict:
    if _commit:
        init_continuity_schema(conn)
    project_id = int(_project_id) if _project_id is not None else ensure_project(conn, project)
    session_id = _bounded_identifier(
        "session_id", session_id, MAX_SESSION_ID_CHARS
    )
    cursor = _bounded_identifier("cursor", cursor, MAX_CURSOR_CHARS)
    event_type = _bounded_identifier(
        "event_type", event_type, MAX_EVENT_TYPE_CHARS
    ).lower().replace(" ", "_")
    source = _bounded_identifier("source", source, MAX_EVENT_SOURCE_CHARS)
    verification_status = str(verification_status).strip().lower()
    if verification_status not in VALID_VERIFICATION:
        raise ValueError(f"invalid verification status: {verification_status}")
    _validate_event_nesting(payload)
    payload_text = _json_text(_bound_event_value(_redact_event_value(payload)))
    timestamp = occurred_at or now_iso()
    recorded_at = now_iso()
    cursor_row = conn.execute(
        """
        INSERT OR IGNORE INTO session_events(
            project_id, session_id, cursor, event_type, payload_json, source,
            source_hash, verification_status, occurred_at, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id, session_id, cursor, event_type, payload_text, source,
            source_hash, verification_status, timestamp, recorded_at,
        ),
    )
    if _commit:
        conn.commit()
    inserted = cursor_row.rowcount == 1
    row = conn.execute(
        "SELECT id FROM session_events WHERE project_id = ? AND session_id = ? AND cursor = ?",
        (project_id, session_id, cursor),
    ).fetchone()
    return {"status": "ok", "project": project, "event_id": int(row["id"]), "inserted": inserted}


def list_events(conn, project: str, session_id: str | None = None, limit: int = 100) -> dict:
    init_continuity_schema(conn)
    project_id = ensure_project(conn, project)
    limit = max(1, min(500, int(limit)))
    params: list[Any] = [project_id]
    where = "project_id = ? AND payload_json <> 'null'"
    if session_id:
        where += " AND session_id = ?"
        params.append(
            _bounded_identifier("session_id", session_id, MAX_SESSION_ID_CHARS)
        )
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM session_events WHERE {where} ORDER BY id DESC LIMIT ?", params
    ).fetchall()
    events = []
    for row in reversed(rows):
        item = dict(row)
        item["payload"] = json.loads(item.pop("payload_json"))
        events.append(item)
    return {"status": "ok", "project": project, "events": events}


def _codex_event(payload: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    kind = str(payload.get("type") or "event")
    body = payload.get("payload") if isinstance(payload.get("payload"), dict) else payload
    normalized = normalize_capture_event(
        "codex-jsonl",
        payload,
        source_cursor="legacy",
        observed_at=str(payload.get("timestamp") or "1970-01-01T00:00:00Z"),
        session_id=str(body.get("id") or "legacy-codex-session"),
    )
    if normalized is None:
        return None
    attributes = dict(normalized.attributes)
    if kind == "session_meta":
        return "session_started", attributes
    if kind == "turn_context":
        return "turn_context", attributes
    if kind == "response_item":
        role = body.get("role")
        item_type = body.get("type")
        if role in {"user", "assistant"}:
            if "text" in attributes and "content" not in attributes:
                attributes["content"] = attributes.pop("text")
            return "message", attributes
        if item_type in {"function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output"}:
            return "tool_event", attributes
    if kind == "event_msg":
        event_kind = attributes.pop("event_kind", normalized.event_name)
        return "agent_event", {"type": event_kind, **attributes}
    return None


def _open_stable_codex_session(
    path: Path,
    expected_sessions_root: Path | None,
):
    reject_windows_network_path(path)
    if expected_sessions_root is None:
        return path.open("rb")
    reject_windows_network_path(expected_sessions_root)
    root = expected_sessions_root.expanduser().resolve()
    guard = _capture_ancestor_guard(path, root)
    with _stable_adapter_parent(path, root, guard):
        _validate_ancestor_guard(path, root, guard)
        handle = path.open("rb")
        try:
            opened = os.fstat(handle.fileno())
            current = path.stat()
            if (
                opened.st_dev != current.st_dev
                or opened.st_ino != current.st_ino
                or opened.st_nlink > 1
            ):
                raise ValueError(
                    "Codex session changed identity while it was being opened"
                )
            _validate_ancestor_guard(path, root, guard)
        except BaseException:
            handle.close()
            raise
    return handle


def ingest_codex_session(
    conn, path: Path, project: str, session_id: str | None = None,
    max_events: int = MAX_CODEX_EVENTS_PER_RUN,
    backlog_tail_bytes: int | None = None,
    expected_project_root: Path | None = None,
    expected_sessions_root: Path | None = None,
    binding_start_offset: int = 0,
) -> dict:
    init_continuity_schema(conn)
    reject_windows_network_path(path)
    candidate = path.expanduser()
    if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_nlink > 1:
        raise ValueError("Codex session must be an existing unlinked JSONL file")
    path = candidate.resolve()
    if not path.is_file() or path.suffix.lower() != ".jsonl":
        raise ValueError("Codex session must be an existing JSONL file")
    session_handle = _open_stable_codex_session(path, expected_sessions_root)
    try:
        max_events = max(1, min(MAX_CODEX_EVENTS_PER_RUN, int(max_events)))
        project_id = ensure_project(conn, project)
        if expected_project_root is None:
            project_row = conn.execute(
                "SELECT root_path FROM projects WHERE id = ?",
                (project_id,),
            ).fetchone()
            if project_row is None or not project_row["root_path"]:
                raise ValueError(
                    "Codex session ingestion requires a canonical project root"
                )
            expected_project_root = Path(str(project_row["root_path"]))
        stream_id = session_id or path.stem
        prior = conn.execute(
            "SELECT cursor FROM adapter_cursors WHERE project_id = ? AND adapter = 'codex-jsonl' AND stream_id = ?",
            (project_id, stream_id),
        ).fetchone()
        start = int(prior["cursor"]) if prior else 0
        file_size = path.stat().st_size
    except BaseException:
        session_handle.close()
        raise
    inserted = 0
    ignored = 0
    processed = 0
    conn.execute("SAVEPOINT codex_jsonl_ingest")
    with session_handle as handle:
        try:
            opened = os.fstat(handle.fileno())
            current = path.stat()
            if opened.st_dev != current.st_dev or opened.st_ino != current.st_ino or opened.st_nlink > 1:
                raise ValueError("Codex session changed identity while it was being opened")
            file_size = opened.st_size
            if start < 0 or start > file_size:
                start = 0
            if expected_sessions_root is not None:
                try:
                    path.relative_to(expected_sessions_root.expanduser().resolve())
                except ValueError as exc:
                    raise ValueError("Codex session is outside the configured session directory") from exc
            bound_to_project = False
            if expected_project_root is not None:
                declared_session = None
                declared_cwd = None
                consumed = 0
                handle.seek(0)
                while consumed < MAX_SESSION_META_BYTES:
                    raw_meta = handle.readline(min(MAX_CODEX_LINE_BYTES + 1, MAX_SESSION_META_BYTES - consumed + 1))
                    if not raw_meta or len(raw_meta) > MAX_CODEX_LINE_BYTES:
                        break
                    consumed += len(raw_meta)
                    if json_nesting_exceeds(raw_meta):
                        continue
                    try:
                        meta = json.loads(raw_meta)
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if meta.get("type") == "session_meta" and isinstance(meta.get("payload"), dict):
                        declared_session = str(meta["payload"].get("id") or "").strip()
                        declared_cwd = meta["payload"].get("cwd")
                        break
                if not declared_session or not declared_cwd:
                    raise ValueError("Codex session has no valid session metadata")
                reject_windows_network_path(expected_project_root)
                expected_root = expected_project_root.expanduser().resolve()
                try:
                    reject_windows_network_path(str(declared_cwd))
                    Path(str(declared_cwd)).expanduser().resolve().relative_to(expected_root)
                except ValueError:
                    if int(binding_start_offset) <= 0:
                        raise ValueError("Codex session is not bound to the canonical project root")
                    handle.seek(int(binding_start_offset))
                    raw_binding = handle.readline(MAX_CODEX_LINE_BYTES + 1)
                    try:
                        if json_nesting_exceeds(raw_binding):
                            raise ValueError
                        binding_row = json.loads(raw_binding)
                        binding_cwd = binding_row.get("payload", {}).get("cwd")
                        if binding_row.get("type") != "turn_context" or not binding_cwd:
                            raise ValueError
                        reject_windows_network_path(str(binding_cwd))
                        Path(str(binding_cwd)).expanduser().resolve().relative_to(expected_root)
                    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                        raise ValueError("Codex session rebind marker is not bound to the canonical project root") from exc
                    bound_to_project = True
                else:
                    bound_to_project = True
                if session_id and declared_session != stream_id:
                    raise ValueError("Codex session identity changed after discovery")
                start = max(start, max(0, int(binding_start_offset)))
            if backlog_tail_bytes is not None and file_size - start > max(1, int(backlog_tail_bytes)):
                previous_cursor = start
                handle.seek(file_size - max(1, int(backlog_tail_bytes)))
                handle.readline()
                start = handle.tell()
                marker = append_event(
                    conn, project, stream_id, f"truncated:{previous_cursor}:{start}", "history_truncated",
                    {"from_cursor": previous_cursor, "to_cursor": start, "skipped_bytes": start - previous_cursor, "retained_tail_bytes": file_size - start},
                source="continuity-daemon", verification_status="unverified",
                _commit=False, _project_id=project_id,
            )
                inserted += int(marker["inserted"])
            handle.seek(start)
            while processed < max_events:
                offset = handle.tell()
                raw_line = handle.readline(MAX_CODEX_LINE_BYTES + 1)
                if not raw_line:
                    break
                if len(raw_line) > MAX_CODEX_LINE_BYTES and not raw_line.endswith(b"\n"):
                    digest = hashlib.sha256(raw_line)
                    total = len(raw_line)
                    complete_record = False
                    while True:
                        chunk = handle.readline(65_536)
                        if not chunk:
                            break
                        digest.update(chunk)
                        total += len(chunk)
                        if chunk.endswith(b"\n"):
                            complete_record = True
                            break
                    if not complete_record:
                        handle.seek(offset)
                        break
                    processed += 1
                    result = append_event(
                        conn, project, stream_id, str(offset), "oversized_record",
                        {"source_bytes": total, "stored": False}, source="codex-jsonl",
                        source_hash=digest.hexdigest(), verification_status="unverified",
                        _commit=False, _project_id=project_id,
                    )
                    inserted += int(result["inserted"])
                    bound_to_project = False
                    continue
                if not raw_line.endswith(b"\n"):
                    handle.seek(offset)
                    break
                processed += 1
                line = raw_line.decode("utf-8", errors="replace")
                if json_nesting_exceeds(raw_line):
                    ignored += 1
                    bound_to_project = False
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    ignored += 1
                    bound_to_project = False
                    continue
                if expected_project_root is not None and payload.get("type") == "turn_context":
                    body = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
                    cwd = body.get("cwd")
                    if cwd:
                        try:
                            reject_windows_network_path(str(cwd))
                            Path(str(cwd)).expanduser().resolve().relative_to(expected_root)
                        except ValueError:
                            bound_to_project = False
                        else:
                            bound_to_project = True
                    ignored += 1
                    continue
                if not bound_to_project:
                    ignored += 1
                    continue
                mapped = _codex_event(payload)
                if mapped is None:
                    ignored += 1
                    continue
                event_type, event_payload = mapped
                event_payload = _bound_event_value(_redact_event_value(event_payload))
                digest = hashlib.sha256(raw_line).hexdigest()
                result = append_event(
                    conn, project, stream_id, str(offset), event_type, event_payload,
                    source="codex-jsonl", source_hash=digest,
                    verification_status="unverified", occurred_at=payload.get("timestamp"),
                    _commit=False, _project_id=project_id,
                )
                inserted += int(result["inserted"])
            end = handle.tell()
            final_opened = os.fstat(handle.fileno())
            final_path = path.stat()
            if (
                final_opened.st_dev != opened.st_dev
                or final_opened.st_ino != opened.st_ino
                or final_opened.st_nlink > 1
                or final_path.st_dev != final_opened.st_dev
                or final_path.st_ino != final_opened.st_ino
            ):
                raise ValueError("Codex session changed identity while it was being ingested")
            file_size = final_opened.st_size
            file_mtime_ns = final_opened.st_mtime_ns
        except Exception:
            conn.execute("ROLLBACK TO SAVEPOINT codex_jsonl_ingest")
            conn.execute("RELEASE SAVEPOINT codex_jsonl_ingest")
            raise
    source_hash = hashlib.sha256(f"{file_size}:{file_mtime_ns}".encode("ascii")).hexdigest()
    conn.execute(
        """
        INSERT INTO adapter_cursors(project_id, adapter, stream_id, cursor, source_path, source_hash, updated_at)
        VALUES (?, 'codex-jsonl', ?, ?, ?, ?, ?)
        ON CONFLICT(project_id, adapter, stream_id) DO UPDATE SET
            cursor=excluded.cursor, source_path=excluded.source_path,
            source_hash=excluded.source_hash, updated_at=excluded.updated_at
        """,
        (project_id, stream_id, end, str(path), source_hash, now_iso()),
    )
    conn.execute("RELEASE SAVEPOINT codex_jsonl_ingest")
    conn.commit()
    return {
        "status": "ok", "project": project, "session_id": stream_id,
        "cursor": end, "source_bytes": file_size, "complete": end >= file_size,
        "processed": processed, "inserted": inserted, "ignored": ignored,
    }


def upsert_work_item(
    conn, project: str, item_type: str, external_id: str, *, local_path: str | None = None,
    qa_state: str = "unknown", decision: str = "pending", attempt_count: int = 0,
    fallback: str = "", next_action: str = "", metadata: dict[str, Any] | None = None,
) -> dict:
    init_continuity_schema(conn)
    project_id = ensure_project(conn, project)
    if local_path:
        root_row = conn.execute("SELECT root_path FROM projects WHERE id = ?", (project_id,)).fetchone()
        if not root_row or not root_row["root_path"]:
            raise ValueError("project has no canonical root for a local work-item path")
        root = Path(root_row["root_path"]).resolve()
        candidate = Path(local_path)
        candidate = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("work-item path escapes the canonical project root") from exc
    conn.execute(
        """
        INSERT INTO work_items(project_id, item_type, external_id, local_path, qa_state, decision,
            attempt_count, fallback, next_action, metadata_json, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(project_id, item_type, external_id) DO UPDATE SET
            local_path=excluded.local_path, qa_state=excluded.qa_state, decision=excluded.decision,
            attempt_count=excluded.attempt_count, fallback=excluded.fallback,
            next_action=excluded.next_action, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at
        """,
        (project_id, item_type, external_id, local_path, qa_state, decision, max(0, int(attempt_count)), fallback, next_action, _json_text(metadata or {}), now_iso()),
    )
    conn.commit()
    return {"status": "ok", "project": project, "item_type": item_type, "external_id": external_id}


def reconcile_work_items(conn, project: str) -> dict:
    init_continuity_schema(conn)
    project_id = ensure_project(conn, project)
    root_row = conn.execute("SELECT root_path FROM projects WHERE id = ?", (project_id,)).fetchone()
    root = Path(root_row["root_path"]) if root_row and root_row["root_path"] else None
    conflicts = []
    items = []
    for row in conn.execute("SELECT * FROM work_items WHERE project_id = ? ORDER BY item_type, external_id", (project_id,)):
        item = dict(row)
        local_path = item.get("local_path")
        exists = None
        resolved = None
        if local_path:
            candidate = Path(local_path)
            candidate = candidate if candidate.is_absolute() else ((root / candidate) if root else candidate)
            resolved = candidate.resolve()
            exists = resolved.is_file()
            if not exists and item["decision"] in {"accepted", "approved", "complete"}:
                conflicts.append({"external_id": item["external_id"], "type": "accepted_file_missing", "path": local_path})
            if exists and item["qa_state"] in {"unknown", "pending", "failed"}:
                conflicts.append({"external_id": item["external_id"], "type": "file_exists_without_passed_qa", "path": local_path})
        item["exists"] = exists
        item["resolved_path"] = str(resolved) if resolved else None
        item.pop("metadata_json", None)
        items.append(item)
    return {"status": "ok", "project": project, "items": items, "conflicts": conflicts, "conflict_count": len(conflicts)}


def operational_readiness(
    conn, project: str, *, lifecycle: dict | None = None, include_event_count: bool = True,
    active_root: str | Path | None = None,
    repository_inspection: RepositoryInspection | None = None,
) -> dict:
    init_continuity_schema(conn)
    project_id = ensure_project(conn, project)
    checkpoint = latest_checkpoint(conn, project)
    reconciliation = reconcile_work_items(conn, project)
    integrity = integrity_diagnostics(
        conn,
        project=project,
        active_root=active_root,
        repository_inspection=repository_inspection,
    )
    temporal = temporal_readiness(conn, project=project)
    event_count = (
        int(conn.execute("SELECT COUNT(*) AS c FROM session_events WHERE project_id = ?", (project_id,)).fetchone()["c"])
        if include_event_count else None
    )
    reasons = []
    if checkpoint is None:
        reasons.append("no_structured_checkpoint")
    elif checkpoint.get("source") == "agent":
        reasons.append("unverified_agent_checkpoint")
    elif checkpoint.get("source") == "continuity-daemon":
        truncated = conn.execute(
            "SELECT 1 FROM session_events WHERE project_id = ? AND event_type = 'history_truncated' LIMIT 1",
            (project_id,),
        ).fetchone()
        if truncated:
            reasons.append("continuity_history_truncated")
    if reconciliation["conflict_count"]:
        reasons.append("work_state_conflicts")
    if not integrity["operationally_ready"]:
        reasons.append("project_integrity")
    if not temporal["ledger_intact"]:
        reasons.append("truth_ledger_integrity")
    if temporal["high_impact_contradiction_count"]:
        reasons.append("truth_contradictions")
    if temporal["failed_critical_validator_count"]:
        reasons.append("truth_validator_failures")
    if temporal["expired_accepted_claim_count"]:
        reasons.append("truth_expired_accepted_claims")
    manual_continuation_ready = not reasons
    from .trusted_lifecycle import derive_continuation_health

    continuation_health = derive_continuation_health(
        lifecycle,
        manual_checkpoint_available=manual_continuation_ready,
    )
    reasons.extend(continuation_health["reason_codes"])
    continuation_ready = not reasons
    return {
        "status": "ok",
        "project": project,
        "database_healthy": True,
        "continuation_ready": continuation_ready,
        "manual_continuation_ready": manual_continuation_ready,
        "automatic_capture_ready": continuation_health["automatic_capture_ready"],
        "continuation_health": continuation_health,
        "operational_state": "ready" if continuation_ready else "operationally_not_ready",
        "reasons": reasons,
        "latest_checkpoint": checkpoint,
        "event_count": event_count,
        "work_state_conflicts": reconciliation["conflicts"],
        "integrity": integrity,
        "temporal_truth": temporal,
        "continuity": lifecycle,
    }
