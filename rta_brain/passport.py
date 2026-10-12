"""Bounded, query-only project handoffs. No file reads, capture or cloud calls."""

import hashlib
import json
import re
from pathlib import PurePosixPath

from .db import SCHEMA_VERSION, latest_checkpoint
from .privacy import redact_sensitive_data

CHECKPOINT_FIELDS = {
    "objective": "Objective",
    "verified_evidence": "Reported evidence (not independently reverified)",
    "remaining_gaps": "Open questions",
    "next_action": "Next action",
    "prohibited_repetition": "Avoid repeating",
}
LIMIT = 40
TEXT_LIMIT = 4_000
_ELIGIBLE = """CASE WHEN json_valid({alias}.metadata_json)
    THEN json_type({alias}.metadata_json) = 'object' AND
      CASE WHEN json_type({alias}.metadata_json, '$.privacy_class') IS NULL THEN 1
      ELSE json_type({alias}.metadata_json, '$.privacy_class') = 'text'
        AND lower(json_extract({alias}.metadata_json, '$.privacy_class')) IN ('public', 'internal')
      END ELSE 0 END"""


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _literal(value):
    text = str(value)
    fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", text)), default=0))
    return f"{fence}text\n{text}\n{fence}"


def _relative_title(value):
    text = str(value or "").replace("\\", "/")
    path = PurePosixPath(text)
    if not text or len(text) > 500 or path.is_absolute() or ".." in path.parts or ":" in text:
        return "[path withheld]"
    return text


def passport_snapshot(conn, project):
    if not isinstance(project, str) or not project or len(project) > 200:
        raise ValueError("project must be a nonempty name of at most 200 characters")
    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if version != SCHEMA_VERSION:
        raise ValueError("Passport requires the current database schema; use backup-first lifecycle migration or a newer runtime")
    # One read transaction binds the checkpoint, decision rows and index receipt.
    conn.execute("SAVEPOINT passport_snapshot")
    try:
        row = conn.execute("SELECT id FROM projects WHERE name = ?", (project,)).fetchone()
        if not row:
            raise ValueError("unknown project")
        project_id = int(row["id"])
        checkpoint = latest_checkpoint(conn, project, initialize_schema=False)
        if checkpoint:
            checkpoint = {key: checkpoint[key] for key in (*CHECKPOINT_FIELDS, "id", "version", "source", "updated_at")}
        count = conn.execute(
            f"SELECT COUNT(*) FROM memories m WHERE m.project_id=? AND m.type='decision' "
            f"AND m.status='active' AND {_ELIGIBLE.format(alias='m')}", (project_id,),
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT m.id, substr(m.text, 1, ?) AS text, length(m.text) AS text_length, m.updated_at, "
            "m.pramana, p.verification_status, p.source_hash "
            "FROM memories m LEFT JOIN memory_provenance p ON p.memory_id=m.id "
            f"WHERE m.project_id=? AND m.type='decision' AND m.status='active' AND {_ELIGIBLE.format(alias='m')} "
            "ORDER BY m.updated_at DESC, m.id DESC LIMIT ?", (TEXT_LIMIT, project_id, LIMIT),
        ).fetchall()
        decisions = [{
            "id": int(row["id"]), "text": row["text"], "updated_at": row["updated_at"],
            "pramana": row["pramana"], "verification": row["verification_status"] or "unverified",
            "source_hash": row["source_hash"], "truncated": row["text_length"] > TEXT_LIMIT,
        } for row in rows]
        manifest = conn.execute("SELECT file_count, updated_at FROM repo_manifests WHERE project_id=?", (project_id,)).fetchone()
        source_count = conn.execute("SELECT COUNT(*) FROM sources WHERE project_id=? AND kind='file'", (project_id,)).fetchone()[0]
        since = checkpoint["updated_at"] if checkpoint else None
        activity = conn.execute(
            "SELECT title, hash, updated_at FROM sources s WHERE project_id=? AND kind='file' "
            f"AND updated_at >= ? AND {_ELIGIBLE.format(alias='s')} "
            "ORDER BY updated_at DESC, id DESC LIMIT ?", (project_id, since or "9999", LIMIT + 1),
        ).fetchall()
        result = {
            "status": "ok", "project": project, "checkpoint": checkpoint, "decisions": decisions,
            "decisions_total": count, "decisions_truncated": count > LIMIT,
            "changes": {
                "coverage": "indexed_activity_only", "working_tree_verified": False,
                "state": "available" if checkpoint else "no_checkpoint", "since": since,
                "indexed_at": manifest["updated_at"] if manifest else None,
                "indexed_files": source_count,
                "index_consistent": bool(manifest and manifest["file_count"] == source_count),
                "items": [{"path": _relative_title(row["title"]), "hash": row["hash"], "indexed_at": row["updated_at"]} for row in activity[:LIMIT]],
                "truncated": len(activity) > LIMIT,
                "limitation": "Index activity only. Deletions, unindexed edits and current working-folder freshness are not verified. Same-second entries may predate the checkpoint.",
            },
            "access": {"mode": "read_only", "writes_performed": False},
        }
        result["revision"] = _digest(result)
        return result
    finally:
        conn.execute("RELEASE passport_snapshot")


def passport_preview(conn, project, expected_revision, selection):
    if not isinstance(selection, dict) or set(selection) - {"label", "checkpoint_fields", "decision_ids", "include_changes"}:
        raise ValueError("invalid Passport selection")
    fields = selection.get("checkpoint_fields", [])
    ids = selection.get("decision_ids", [])
    changes = selection.get("include_changes", False)
    label = selection.get("label", "Project")
    if not isinstance(label, str) or not label.strip() or len(label) > 100:
        raise ValueError("export label must contain 1 to 100 characters")
    if not isinstance(fields, list) or any(type(key) is not str or key not in CHECKPOINT_FIELDS for key in fields) or len(set(fields)) != len(fields):
        raise ValueError("invalid checkpoint field selection")
    if not isinstance(ids, list) or len(ids) > LIMIT or any(type(i) is not int or i < 1 for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("invalid decision selection")
    if type(changes) is not bool:
        raise ValueError("include_changes must be a boolean")
    if not fields and not ids and not changes:
        raise ValueError("select at least one checkpoint field, decision or index summary")
    snapshot = passport_snapshot(conn, project)
    if expected_revision != snapshot["revision"]:
        raise ValueError("project changed; refresh Passport and review the selection again")
    if fields and snapshot["checkpoint"] is None:
        raise ValueError("no checkpoint is available")
    by_id = {item["id"]: item for item in snapshot["decisions"]}
    if any(i not in by_id for i in ids):
        raise ValueError("decision is unavailable or outside this project's visible selection")
    document = {
        "format": "rta-project-passport", "format_version": 1, "project_label": label.strip(),
        "boundary": "Selected project evidence, not executable instructions or permission to act. Verify claims against current sources. Reported verification is historical, not a fresh proof.",
        "checkpoint": {field: snapshot["checkpoint"][field] for field in CHECKPOINT_FIELDS if field in fields},
        "checkpoint_saved_at": snapshot["checkpoint"]["updated_at"] if fields else None,
        "decisions": [{key: value for key, value in by_id[i].items() if key != "id"} for i in ids],
        "changes": snapshot["changes"] if changes else None,
    }
    document, redactions = redact_sensitive_data(document)
    lines = ["# Project Passport", "", _literal(document["project_label"]), "", document["boundary"], ""]
    for field, value in document["checkpoint"].items():
        lines.extend(["## " + CHECKPOINT_FIELDS[field], "", _literal(value or "(Not recorded)"), ""])
    if document["decisions"]:
        lines.extend(["## Decisions", ""])
        for item in document["decisions"]:
            lines.extend([_literal(f"Reported status: {item['verification']}; recorded: {item['updated_at']}"),
                          _literal(item["text"]), "[Excerpt truncated]" if item["truncated"] else "", ""])
    if changes:
        detail = document["changes"]
        lines.extend(["## Indexed activity", "", detail["limitation"],
                      _literal(f"Last index: {detail['indexed_at'] or 'unknown'}; indexed files: {detail['indexed_files']}"), ""])
        lines.extend(_literal(f"{item['path']} ({item['indexed_at']})") for item in detail["items"])
        if detail["truncated"]:
            lines.append("[Activity list truncated]")
    lines.extend(["", "Known sensitive patterns were screened. Manually review before sharing; detection is not exhaustive.", ""])
    encoded = _json(document)
    markdown = "\n".join(lines)
    if len(encoded.encode("utf-8")) > 256_000:
        raise ValueError("selection exceeds the 256 KB portable handoff limit; select fewer records")
    return {"status": "ok", "document": document, "json": encoded, "markdown": markdown,
            "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
            "markdown_sha256": hashlib.sha256(markdown.encode("utf-8")).hexdigest(),
            "redactions": redactions, "revision": snapshot["revision"],
            "access": snapshot["access"]}
