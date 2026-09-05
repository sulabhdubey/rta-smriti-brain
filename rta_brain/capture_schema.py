"""Schema v10 for bounded universal capture observations."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from functools import lru_cache

from .capture_types import canonical_json, capture_event_envelope

CAPTURE_TABLES = frozenset({
    "capture_policies", "capture_sources", "capture_events", "capture_event_content",
    "capture_payloads",
    "capture_adapter_cursors", "capture_session_bindings", "capture_projections",
    "capture_tombstones", "capture_retention_runs",
})
CAPTURE_TRIGGERS = frozenset({
    "capture_events_no_update", "capture_events_no_delete",
    "capture_policies_no_update", "capture_policies_no_delete",
    "capture_session_bindings_guard_update", "capture_session_bindings_no_delete",
    "capture_tombstones_no_update", "capture_tombstones_no_delete",
})
CAPTURE_INDEXES = frozenset({
    "idx_capture_events_project_sequence", "idx_capture_events_session",
    "idx_capture_events_trace", "idx_capture_events_external_identity",
    "idx_capture_events_project_privacy_sequence",
    "idx_capture_sources_project_state",
    "idx_capture_event_content_expiry", "idx_capture_payloads_expiry",
    "idx_capture_retention_project_state",
})


_SCHEMA = """
CREATE TABLE IF NOT EXISTS capture_policies (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    policy_id TEXT NOT NULL,
    policy_version INTEGER NOT NULL CHECK(policy_version > 0),
    profile TEXT NOT NULL CHECK(profile IN ('metadata-only', 'continuity', 'forensic')),
    enabled_event_names_json TEXT NOT NULL CHECK(json_valid(enabled_event_names_json)),
    field_allowlist_json TEXT NOT NULL CHECK(json_valid(field_allowlist_json)),
    privacy_ceiling TEXT NOT NULL CHECK(privacy_ceiling IN ('public', 'internal', 'sensitive', 'restricted')),
    retain_payloads INTEGER NOT NULL CHECK(retain_payloads IN (0, 1)),
    retention_seconds INTEGER NOT NULL CHECK(retention_seconds >= 0 AND retention_seconds <= 315360000),
    max_event_bytes INTEGER NOT NULL CHECK(max_event_bytes >= 1024 AND max_event_bytes <= 1048576),
    max_field_chars INTEGER NOT NULL CHECK(max_field_chars >= 256 AND max_field_chars <= 256000),
    max_collection_items INTEGER NOT NULL CHECK(max_collection_items >= 1 AND max_collection_items <= 10000),
    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
    created_at TEXT NOT NULL,
    retired_at TEXT,
    UNIQUE(project_id, policy_id, policy_version),
    UNIQUE(project_id, policy_digest),
    UNIQUE(id, project_id, policy_digest),
    CHECK(profile = 'forensic' OR retain_payloads = 0)
);

CREATE TABLE IF NOT EXISTS capture_sources (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    source_id TEXT NOT NULL,
    adapter TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    installation_scope TEXT NOT NULL CHECK(installation_scope IN ('project', 'user', 'transcript', 'api')),
    config_fingerprint TEXT NOT NULL CHECK(length(config_fingerprint) = 64),
    policy_row_id INTEGER NOT NULL,
    policy_digest TEXT NOT NULL,
    repository_identity TEXT,
    checkout_identity TEXT,
    state TEXT NOT NULL CHECK(state IN ('active', 'paused', 'error', 'removed')),
    last_heartbeat_at TEXT,
    last_event_at TEXT,
    last_error_class TEXT,
    consecutive_errors INTEGER NOT NULL DEFAULT 0 CHECK(consecutive_errors >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    removed_at TEXT,
    UNIQUE(project_id, source_id),
    UNIQUE(id, project_id, source_id),
    FOREIGN KEY(policy_row_id, project_id, policy_digest)
        REFERENCES capture_policies(id, project_id, policy_digest) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS capture_events (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    project_sequence INTEGER NOT NULL CHECK(project_sequence > 0),
    event_id TEXT NOT NULL,
    source_row_id INTEGER NOT NULL,
    source_id TEXT NOT NULL,
    external_session_id TEXT NOT NULL,
    external_event_id TEXT,
    source_cursor TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    event_name TEXT NOT NULL,
    occurred_at TEXT,
    observed_at TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    trace_id TEXT,
    span_id TEXT,
    parent_span_id TEXT,
    causation_event_id TEXT,
    correlation_id TEXT,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    repository_identity TEXT,
    checkout_identity TEXT,
    repository_ref TEXT,
    repository_commit TEXT,
    dirty_digest TEXT,
    attributes_json TEXT NOT NULL CHECK(json_valid(attributes_json)),
    payload_row_id INTEGER,
    source_sha256 TEXT,
    normalized_sha256 TEXT NOT NULL CHECK(length(normalized_sha256) = 64),
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL CHECK(length(event_hash) = 64),
    original_bytes INTEGER NOT NULL CHECK(original_bytes >= 0),
    stored_bytes INTEGER NOT NULL CHECK(stored_bytes >= 0),
    redaction_count INTEGER NOT NULL CHECK(redaction_count >= 0),
    truncation_count INTEGER NOT NULL CHECK(truncation_count >= 0),
    privacy_class TEXT NOT NULL CHECK(privacy_class IN ('public', 'internal', 'sensitive', 'restricted')),
    verification_status TEXT NOT NULL CHECK(verification_status IN ('unverified', 'verified', 'failed', 'stale')),
    policy_row_id INTEGER NOT NULL,
    policy_digest TEXT NOT NULL,
    gap_state TEXT NOT NULL CHECK(gap_state IN ('none', 'detected', 'resolved')),
    UNIQUE(project_id, project_sequence),
    UNIQUE(event_id),
    UNIQUE(project_id, source_id, idempotency_key),
    UNIQUE(id, project_id),
    UNIQUE(id, project_id, event_id),
    FOREIGN KEY(source_row_id, project_id, source_id)
        REFERENCES capture_sources(id, project_id, source_id) ON DELETE RESTRICT,
    FOREIGN KEY(policy_row_id, project_id, policy_digest)
        REFERENCES capture_policies(id, project_id, policy_digest) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS capture_payloads (
    id INTEGER PRIMARY KEY,
    event_row_id INTEGER NOT NULL UNIQUE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    storage_mode TEXT NOT NULL CHECK(storage_mode IN ('encrypted', 'local-plaintext')),
    content_encoding TEXT NOT NULL,
    key_reference TEXT,
    grant_id TEXT,
    nonce TEXT,
    payload_blob BLOB,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0 AND payload_bytes <= 1048576),
    expires_at TEXT,
    deleted_at TEXT,
    deletion_reason TEXT,
    CHECK((deleted_at IS NULL AND payload_blob IS NOT NULL) OR (deleted_at IS NOT NULL AND payload_blob IS NULL)),
    CHECK(storage_mode != 'encrypted' OR (length(grant_id) = 64 AND key_reference IS NOT NULL)),
    FOREIGN KEY(event_row_id, project_id)
        REFERENCES capture_events(id, project_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS capture_event_content (
    event_row_id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    content_json TEXT CHECK(content_json IS NULL OR json_valid(content_json)),
    content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
    content_bytes INTEGER NOT NULL CHECK(content_bytes >= 0 AND content_bytes <= 1048576),
    expires_at TEXT,
    deleted_at TEXT,
    deletion_reason TEXT,
    CHECK((deleted_at IS NULL AND content_json IS NOT NULL) OR (deleted_at IS NOT NULL AND content_json IS NULL)),
    FOREIGN KEY(event_row_id, project_id)
        REFERENCES capture_events(id, project_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS capture_adapter_cursors (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    adapter TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    cursor TEXT NOT NULL,
    cursor_kind TEXT NOT NULL CHECK(cursor_kind IN ('byte-offset', 'sequence', 'opaque')),
    source_path TEXT,
    source_hash TEXT,
    binding_offset INTEGER NOT NULL DEFAULT 0 CHECK(binding_offset >= 0),
    last_event_id TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(project_id, source_id, stream_id)
);

CREATE TABLE IF NOT EXISTS capture_session_bindings (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    binding_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    external_session_id TEXT NOT NULL,
    cursor_kind TEXT NOT NULL CHECK(cursor_kind IN ('byte-offset', 'sequence', 'opaque')),
    start_cursor TEXT NOT NULL,
    root_fingerprint TEXT NOT NULL CHECK(length(root_fingerprint) = 64),
    repository_identity TEXT,
    checkout_identity TEXT,
    status TEXT NOT NULL CHECK(status IN ('active', 'closed', 'revoked')),
    created_by_type TEXT NOT NULL CHECK(created_by_type = 'operator'),
    created_by_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    closed_at TEXT,
    UNIQUE(project_id, binding_id),
    UNIQUE(project_id, source_id, external_session_id, start_cursor)
);

CREATE TABLE IF NOT EXISTS capture_projections (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    projection_name TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    last_event_sequence INTEGER NOT NULL DEFAULT 0 CHECK(last_event_sequence >= 0),
    event_chain_hash TEXT,
    projection_digest TEXT NOT NULL CHECK(length(projection_digest) = 64),
    rebuilt_at TEXT NOT NULL,
    PRIMARY KEY(project_id, projection_name)
);

CREATE TABLE IF NOT EXISTS capture_tombstones (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    tombstone_id TEXT NOT NULL,
    scope TEXT NOT NULL CHECK(scope IN ('event-content', 'session-content', 'source-content', 'project-content')),
    scope_token TEXT NOT NULL,
    reason_class TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK(actor_type = 'operator'),
    actor_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
    affected_events INTEGER NOT NULL CHECK(affected_events >= 0),
    affected_payloads INTEGER NOT NULL CHECK(affected_payloads >= 0),
    verification_json TEXT NOT NULL CHECK(json_valid(verification_json)),
    created_at TEXT NOT NULL,
    UNIQUE(project_id, tombstone_id)
);

CREATE TABLE IF NOT EXISTS capture_retention_runs (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    run_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
    cutoff_at TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('running', 'complete', 'partial', 'failed')),
    cursor TEXT,
    examined_events INTEGER NOT NULL DEFAULT 0 CHECK(examined_events >= 0),
    deleted_payloads INTEGER NOT NULL DEFAULT 0 CHECK(deleted_payloads >= 0),
    redacted_events INTEGER NOT NULL DEFAULT 0 CHECK(redacted_events >= 0),
    error_class TEXT,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    UNIQUE(project_id, run_id)
);

CREATE TRIGGER IF NOT EXISTS capture_events_no_update
BEFORE UPDATE ON capture_events
BEGIN SELECT RAISE(ABORT, 'capture events are immutable'); END;

CREATE TRIGGER IF NOT EXISTS capture_events_no_delete
BEFORE DELETE ON capture_events
BEGIN SELECT RAISE(ABORT, 'capture events are immutable'); END;

CREATE TRIGGER IF NOT EXISTS capture_policies_no_update
BEFORE UPDATE ON capture_policies
WHEN NEW.id IS NOT OLD.id
  OR NEW.project_id IS NOT OLD.project_id
  OR NEW.policy_id IS NOT OLD.policy_id
  OR NEW.policy_version IS NOT OLD.policy_version
  OR NEW.profile IS NOT OLD.profile
  OR NEW.enabled_event_names_json IS NOT OLD.enabled_event_names_json
  OR NEW.field_allowlist_json IS NOT OLD.field_allowlist_json
  OR NEW.privacy_ceiling IS NOT OLD.privacy_ceiling
  OR NEW.retain_payloads IS NOT OLD.retain_payloads
  OR NEW.retention_seconds IS NOT OLD.retention_seconds
  OR NEW.max_event_bytes IS NOT OLD.max_event_bytes
  OR NEW.max_field_chars IS NOT OLD.max_field_chars
  OR NEW.max_collection_items IS NOT OLD.max_collection_items
  OR NEW.policy_digest IS NOT OLD.policy_digest
  OR NEW.created_at IS NOT OLD.created_at
  OR OLD.retired_at IS NOT NULL
  OR NEW.retired_at IS NULL
BEGIN SELECT RAISE(ABORT, 'capture policies are immutable except one-way retirement'); END;

CREATE TRIGGER IF NOT EXISTS capture_policies_no_delete
BEFORE DELETE ON capture_policies
BEGIN SELECT RAISE(ABORT, 'capture policies are immutable'); END;

CREATE TRIGGER IF NOT EXISTS capture_session_bindings_guard_update
BEFORE UPDATE ON capture_session_bindings
WHEN NEW.id IS NOT OLD.id
  OR NEW.project_id IS NOT OLD.project_id
  OR NEW.binding_id IS NOT OLD.binding_id
  OR NEW.source_id IS NOT OLD.source_id
  OR NEW.external_session_id IS NOT OLD.external_session_id
  OR NEW.cursor_kind IS NOT OLD.cursor_kind
  OR NEW.start_cursor IS NOT OLD.start_cursor
  OR NEW.root_fingerprint IS NOT OLD.root_fingerprint
  OR NEW.repository_identity IS NOT OLD.repository_identity
  OR NEW.checkout_identity IS NOT OLD.checkout_identity
  OR NEW.created_by_type IS NOT OLD.created_by_type
  OR NEW.created_by_id IS NOT OLD.created_by_id
  OR NEW.created_at IS NOT OLD.created_at
  OR OLD.status != 'active'
  OR NEW.status NOT IN ('closed', 'revoked')
  OR NEW.closed_at IS NULL
BEGIN SELECT RAISE(ABORT, 'capture session binding receipt is immutable'); END;

CREATE TRIGGER IF NOT EXISTS capture_session_bindings_no_delete
BEFORE DELETE ON capture_session_bindings
BEGIN SELECT RAISE(ABORT, 'capture session binding receipts are immutable'); END;

CREATE TRIGGER IF NOT EXISTS capture_tombstones_no_update
BEFORE UPDATE ON capture_tombstones
BEGIN SELECT RAISE(ABORT, 'capture deletion receipts are immutable'); END;

CREATE TRIGGER IF NOT EXISTS capture_tombstones_no_delete
BEFORE DELETE ON capture_tombstones
BEGIN SELECT RAISE(ABORT, 'capture deletion receipts are immutable'); END;

CREATE INDEX IF NOT EXISTS idx_capture_events_project_sequence
    ON capture_events(project_id, project_sequence DESC);
CREATE INDEX IF NOT EXISTS idx_capture_events_project_privacy_sequence
    ON capture_events(project_id, privacy_class, project_sequence);
CREATE INDEX IF NOT EXISTS idx_capture_events_session
    ON capture_events(project_id, external_session_id, project_sequence);
CREATE INDEX IF NOT EXISTS idx_capture_events_trace
    ON capture_events(project_id, trace_id, project_sequence);
CREATE INDEX IF NOT EXISTS idx_capture_events_external_identity
    ON capture_events(
        project_id, source_id, external_session_id, external_event_id, project_sequence
    );
CREATE INDEX IF NOT EXISTS idx_capture_sources_project_state
    ON capture_sources(project_id, state, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_capture_payloads_expiry
    ON capture_payloads(project_id, expires_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_capture_event_content_expiry
    ON capture_event_content(project_id, expires_at) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_capture_retention_project_state
    ON capture_retention_runs(project_id, state, updated_at DESC);
"""


def _object_names(conn: sqlite3.Connection, object_type: str) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = ?", (object_type,))
    }


def _normalize_sql(value: str | None) -> str:
    return " ".join(str(value or "").strip().lower().split())


@lru_cache(maxsize=1)
def _expected_schema_objects() -> dict[tuple[str, str], str]:
    expected = sqlite3.connect(":memory:")
    try:
        _execute_schema(expected)
        names = CAPTURE_TABLES | CAPTURE_TRIGGERS | CAPTURE_INDEXES
        placeholders = ",".join("?" for _ in names)
        # Interpolation contains generated parameter placeholders only.
        query = (
            f"SELECT type, name, sql FROM sqlite_master WHERE name IN ({placeholders})"  # nosec B608
        )
        return {
            (str(row[0]), str(row[1])): _normalize_sql(row[2])
            for row in expected.execute(
                query,
                tuple(sorted(names)),
            )
        }
    finally:
        expected.close()


def _validate_schema_objects(conn: sqlite3.Connection) -> None:
    expected = _expected_schema_objects()
    names = {name for _, name in expected}
    placeholders = ",".join("?" for _ in names)
    # Interpolation contains generated parameter placeholders only.
    object_query = (
        f"SELECT type, name, sql FROM sqlite_master WHERE name IN ({placeholders})"  # nosec B608
    )
    actual = {
        (str(row[0]), str(row[1])): _normalize_sql(row[2])
        for row in conn.execute(
            object_query,
            tuple(sorted(names)),
        )
    }
    collisions = sorted(
        name for (object_type, name), sql in expected.items()
        if actual.get((object_type, name)) != sql
    )
    if collisions:
        raise RuntimeError(f"capture schema v10 collision: {', '.join(collisions)}")
    trigger_placeholders = ",".join("?" for _ in CAPTURE_TABLES)
    # Interpolation contains generated parameter placeholders only.
    trigger_query = (
        "SELECT name FROM sqlite_master WHERE type = 'trigger' "
        f"AND tbl_name IN ({trigger_placeholders})"  # nosec B608
    )
    governed_triggers = {
        str(row[0])
        for row in conn.execute(
            trigger_query,
            tuple(sorted(CAPTURE_TABLES)),
        )
    }
    unexpected_triggers = sorted(governed_triggers - CAPTURE_TRIGGERS)
    if unexpected_triggers:
        raise RuntimeError(
            f"unexpected capture trigger: {', '.join(unexpected_triggers)}"
        )


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone() is not None


def _table_columns(conn: sqlite3.Connection, name: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f'PRAGMA table_info("{name}")')}


def _expected_table_sql(name: str) -> str:
    expected = sqlite3.connect(":memory:")
    try:
        _execute_schema(expected)
        row = expected.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
        ).fetchone()
        if row is None or not row[0]:
            raise RuntimeError(f"capture schema is missing the expected {name} table")
        return str(row[0])
    finally:
        expected.close()


_PAYLOAD_COLUMNS = frozenset({
    "id", "event_row_id", "project_id", "storage_mode", "content_encoding",
    "key_reference", "grant_id", "nonce", "payload_blob", "payload_sha256",
    "payload_bytes", "expires_at", "deleted_at", "deletion_reason",
})
_RETENTION_COLUMNS = frozenset({
    "id", "project_id", "run_id", "policy_digest", "cutoff_at", "state", "cursor",
    "examined_events", "deleted_payloads", "redacted_events", "error_class",
    "started_at", "updated_at", "completed_at",
})


def capture_schema_v10_patch_required(conn: sqlite3.Connection) -> bool:
    if not _table_exists(conn, "capture_payloads") or not _table_exists(
        conn, "capture_retention_runs"
    ):
        return False
    return (
        "grant_id" not in _table_columns(conn, "capture_payloads")
        or "cutoff_at" not in _table_columns(conn, "capture_retention_runs")
        or not _table_exists(conn, "capture_event_content")
    )


def _rebuild_pre_grant_payloads(conn: sqlite3.Connection) -> None:
    columns = _table_columns(conn, "capture_payloads")
    if columns != _PAYLOAD_COLUMNS - {"grant_id"}:
        raise RuntimeError("capture payload schema is not an approved pre-grant layout")
    legacy_table = "capture_payloads_pre_grant_v10"
    if _table_exists(conn, legacy_table):
        raise RuntimeError("capture payload patch recovery table already exists")
    conn.execute("DROP INDEX IF EXISTS idx_capture_payloads_expiry")
    conn.execute(f"ALTER TABLE capture_payloads RENAME TO {legacy_table}")
    conn.execute(_expected_table_sql("capture_payloads"))
    unbound_grant = hashlib.sha256(b"rta-smriti/pre-grant-payload/v10").hexdigest()
    retired_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    # The recovery table name is a fixed internal constant.
    conn.execute(
        f"""
        INSERT INTO capture_payloads(
            id, event_row_id, project_id, storage_mode, content_encoding,
            key_reference, grant_id, nonce, payload_blob, payload_sha256,
            payload_bytes, expires_at, deleted_at, deletion_reason
        )
        SELECT id, event_row_id, project_id, storage_mode, content_encoding,
               key_reference,
               CASE WHEN storage_mode = 'encrypted' THEN ? ELSE NULL END,
               nonce,
               CASE WHEN storage_mode = 'encrypted' THEN NULL ELSE payload_blob END,
               payload_sha256, payload_bytes, expires_at,
               CASE WHEN storage_mode = 'encrypted'
                    THEN COALESCE(deleted_at, ?) ELSE deleted_at END,
               CASE WHEN storage_mode = 'encrypted'
                    THEN COALESCE(deletion_reason, 'migration-unbound-grant')
                    ELSE deletion_reason END
        FROM {legacy_table}
        """,  # nosec B608
        (unbound_grant, retired_at),
    )
    conn.execute(f"DROP TABLE {legacy_table}")


def _rebuild_pre_cutoff_retention_runs(conn: sqlite3.Connection) -> None:
    columns = _table_columns(conn, "capture_retention_runs")
    if columns != _RETENTION_COLUMNS - {"cutoff_at"}:
        raise RuntimeError("capture retention schema is not an approved pre-cutoff layout")
    legacy_table = "capture_retention_runs_pre_cutoff_v10"
    if _table_exists(conn, legacy_table):
        raise RuntimeError("capture retention patch recovery table already exists")
    conn.execute("DROP INDEX IF EXISTS idx_capture_retention_project_state")
    conn.execute(f"ALTER TABLE capture_retention_runs RENAME TO {legacy_table}")
    conn.execute(_expected_table_sql("capture_retention_runs"))
    # The recovery table name is a fixed internal constant.
    conn.execute(
        f"""
        INSERT INTO capture_retention_runs(
            id, project_id, run_id, policy_digest, cutoff_at, state, cursor,
            examined_events, deleted_payloads, redacted_events, error_class,
            started_at, updated_at, completed_at
        )
        SELECT id, project_id, run_id, policy_digest, started_at, state, cursor,
               examined_events, deleted_payloads, redacted_events, error_class,
               started_at, updated_at, completed_at
        FROM {legacy_table}
        """  # nosec B608
    )
    conn.execute(f"DROP TABLE {legacy_table}")


def upgrade_capture_schema_v10_patch(conn: sqlite3.Connection) -> None:
    """Upgrade the uncommitted pre-grant/pre-cutoff v10 layout atomically."""

    if not capture_schema_v10_patch_required(conn):
        return
    if "grant_id" not in _table_columns(conn, "capture_payloads"):
        _rebuild_pre_grant_payloads(conn)
    if "cutoff_at" not in _table_columns(conn, "capture_retention_runs"):
        _rebuild_pre_cutoff_retention_runs(conn)
    _execute_schema(conn)
    validate_capture_schema_v10(conn)


def _execute_schema(conn: sqlite3.Connection) -> None:
    statement = ""
    for line in _SCHEMA.splitlines(keepends=True):
        statement += line
        if not sqlite3.complete_statement(statement):
            continue
        sql = statement.strip()
        if sql:
            conn.execute(sql)
        statement = ""
    if statement.strip():
        raise RuntimeError("capture schema contains an incomplete SQL statement")


def _upgrade_policy_retirement_trigger(conn: sqlite3.Connection) -> None:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'capture_policies_no_update'"
    ).fetchone()
    if row is None:
        return
    legacy = _normalize_sql(
        """
        CREATE TRIGGER capture_policies_no_update
        BEFORE UPDATE ON capture_policies
        BEGIN SELECT RAISE(ABORT, 'capture policies are immutable'); END
        """
    )
    if _normalize_sql(row[0]) == legacy:
        conn.execute("DROP TRIGGER capture_policies_no_update")


def validate_capture_schema_v10(conn: sqlite3.Connection) -> None:
    missing_tables = CAPTURE_TABLES.difference(_object_names(conn, "table"))
    missing_triggers = CAPTURE_TRIGGERS.difference(_object_names(conn, "trigger"))
    missing_indexes = CAPTURE_INDEXES.difference(_object_names(conn, "index"))
    if missing_tables or missing_triggers or missing_indexes:
        raise RuntimeError(
            "capture schema v10 is incomplete: "
            f"tables={sorted(missing_tables)}, triggers={sorted(missing_triggers)}, "
            f"indexes={sorted(missing_indexes)}"
        )
    _validate_schema_objects(conn)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(capture_events)")}
    required = {
        "project_sequence", "event_id", "source_id", "source_cursor", "idempotency_key",
        "event_name", "occurred_at", "observed_at", "recorded_at", "trace_id", "span_id",
        "causation_event_id", "attributes_json", "normalized_sha256", "previous_event_hash",
        "event_hash", "privacy_class", "verification_status", "policy_digest", "gap_state",
    }
    missing_columns = required.difference(columns)
    if missing_columns:
        raise RuntimeError(f"capture schema v10 is missing event columns: {sorted(missing_columns)}")


def _legacy_policy_digest() -> str:
    payload = {
        "profile": "metadata-only", "events": ["vendor.event.v1"],
        "retention_seconds": 0, "retain_payloads": False,
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _migrate_legacy_cursors(conn: sqlite3.Connection) -> None:
    if _table_exists(conn, "adapter_cursors"):
        rows = conn.execute(
            """
            SELECT project_id, adapter, stream_id, cursor, source_path, source_hash, updated_at
            FROM adapter_cursors ORDER BY project_id, adapter, stream_id
            """
        ).fetchall()
        for row in rows:
            source_id = f"legacy:{row['adapter']}:{row['stream_id']}"
            cursor_kind = "byte-offset" if row["adapter"] == "codex-jsonl" else "opaque"
            expected = {
                "project_id": int(row["project_id"]), "source_id": source_id,
                "adapter": str(row["adapter"]), "stream_id": str(row["stream_id"]),
                "cursor": str(row["cursor"]), "cursor_kind": cursor_kind,
                "source_path": row["source_path"], "source_hash": row["source_hash"],
                "binding_offset": 0, "last_event_id": None,
                "updated_at": str(row["updated_at"]),
            }
            conn.execute(
                """
                INSERT OR IGNORE INTO capture_adapter_cursors(
                    project_id, source_id, adapter, stream_id, cursor, cursor_kind,
                    source_path, source_hash, binding_offset, last_event_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)
                """,
                (
                    expected["project_id"], source_id, expected["adapter"],
                    expected["stream_id"], expected["cursor"], cursor_kind,
                    expected["source_path"], expected["source_hash"], expected["updated_at"],
                ),
            )
            actual = conn.execute(
                """
                SELECT project_id, source_id, adapter, stream_id, cursor, cursor_kind,
                       source_path, source_hash, binding_offset, last_event_id, updated_at
                FROM capture_adapter_cursors
                WHERE project_id = ? AND source_id = ? AND stream_id = ?
                """,
                (expected["project_id"], source_id, expected["stream_id"]),
            ).fetchone()
            if actual is None or dict(actual) != expected:
                raise RuntimeError(
                    "legacy cursor migration conflict for a project-scoped adapter stream"
                )


def _register_legacy_session_events(conn: sqlite3.Connection) -> None:
    if not _table_exists(conn, "session_events"):
        return
    policy_digest = _legacy_policy_digest()
    config_fingerprint = hashlib.sha256(b"rta-smriti:legacy-session-events:v1").hexdigest()
    rows = conn.execute(
        """
        SELECT id, project_id, session_id, cursor, event_type, payload_json,
               source_hash, verification_status, occurred_at, recorded_at
        FROM session_events ORDER BY project_id, id
        """
    ).fetchall()
    for row in rows:
        project_id = int(row["project_id"])
        conn.execute(
            """
            INSERT OR IGNORE INTO capture_policies(
                project_id, policy_id, policy_version, profile,
                enabled_event_names_json, field_allowlist_json, privacy_ceiling,
                retain_payloads, retention_seconds, max_event_bytes,
                max_field_chars, max_collection_items, policy_digest, created_at
            ) VALUES (?, 'legacy-metadata', 1, 'metadata-only', '["vendor.event.v1"]',
                      '{}', 'internal', 0, 0, 262144, 16000, 100, ?, ?)
            """,
            (project_id, policy_digest, str(row["recorded_at"])),
        )
        policy = conn.execute(
            """
            SELECT id, policy_digest FROM capture_policies
            WHERE project_id = ? AND policy_id = 'legacy-metadata' AND policy_version = 1
            """,
            (project_id,),
        ).fetchone()
        if policy is None or policy["policy_digest"] != policy_digest:
            raise RuntimeError("legacy event policy migration conflict")
        conn.execute(
            """
            INSERT OR IGNORE INTO capture_sources(
                project_id, source_id, adapter, adapter_version,
                installation_scope, config_fingerprint, policy_row_id,
                policy_digest, state, created_at, updated_at
            ) VALUES (?, 'legacy-session-events', 'legacy-session-events', '1',
                      'transcript', ?, ?, ?, 'active', ?, ?)
            """,
            (
                project_id, config_fingerprint, int(policy["id"]), policy_digest,
                str(row["recorded_at"]), str(row["recorded_at"]),
            ),
        )
        source = conn.execute(
            """
            SELECT id, config_fingerprint, policy_row_id, policy_digest
            FROM capture_sources
            WHERE project_id = ? AND source_id = 'legacy-session-events'
            """,
            (project_id,),
        ).fetchone()
        if (
            source is None or source["config_fingerprint"] != config_fingerprint
            or int(source["policy_row_id"]) != int(policy["id"])
            or source["policy_digest"] != policy_digest
        ):
            raise RuntimeError("legacy event source migration conflict")
        attributes = {
            "legacy_event_type": str(row["event_type"]),
            "legacy_session_event_id": int(row["id"]),
            "payload_retained_in": "session_events",
        }
        attributes_json = json.dumps(attributes, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        normalized_sha256 = hashlib.sha256(attributes_json.encode("ascii")).hexdigest()
        event_identity = hashlib.sha256(
            f"{project_id}\0{row['id']}\0{row['session_id']}\0{row['cursor']}".encode()
        ).hexdigest()
        event_id = f"legacy-{event_identity}"
        verification_status = (
            row["verification_status"]
            if row["verification_status"] in {"unverified", "verified", "failed", "stale"}
            else "unverified"
        )
        existing = conn.execute(
            """
            SELECT * FROM capture_events WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
        expected_existing = {
            "project_id": project_id,
            "source_row_id": int(source["id"]),
            "source_id": "legacy-session-events",
            "external_session_id": str(row["session_id"]),
            "source_cursor": str(row["cursor"]),
            "idempotency_key": f"legacy-session-event:{row['id']}",
            "event_name": "vendor.event.v1",
            "occurred_at": row["occurred_at"],
            "observed_at": row["recorded_at"],
            "recorded_at": row["recorded_at"],
            "actor_type": "adapter",
            "actor_id": "legacy-session-events",
            "attributes_json": attributes_json,
            "source_sha256": row["source_hash"],
            "normalized_sha256": normalized_sha256,
            "original_bytes": len(str(row["payload_json"]).encode("utf-8")),
            "stored_bytes": len(attributes_json.encode("ascii")),
            "redaction_count": 0,
            "truncation_count": 0,
            "privacy_class": "internal",
            "verification_status": verification_status,
            "policy_row_id": int(policy["id"]),
            "policy_digest": policy_digest,
            "gap_state": "none",
        }
        if existing is not None:
            if any(existing[key] != value for key, value in expected_existing.items()):
                raise RuntimeError("legacy session event migration conflict")
            expected_hash = hashlib.sha256(
                canonical_json(capture_event_envelope(existing)).encode("utf-8")
            ).hexdigest()
            if existing["event_hash"] != expected_hash:
                raise RuntimeError("legacy session event hash migration conflict")
            continue
        previous = conn.execute(
            "SELECT project_sequence, event_hash FROM capture_events WHERE project_id = ? ORDER BY project_sequence DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["project_sequence"]) + 1
        previous_hash = None if previous is None else str(previous["event_hash"])
        event_values = {
            "actor_id": "legacy-session-events",
            "actor_type": "adapter",
            "attributes_json": attributes_json,
            "payload_row_id": None,
            "causation_event_id": None,
            "checkout_identity": None,
            "correlation_id": None,
            "dirty_digest": None,
            "event_id": event_id,
            "event_name": "vendor.event.v1",
            "external_event_id": None,
            "external_session_id": str(row["session_id"]),
            "gap_state": "none",
            "idempotency_key": f"legacy-session-event:{row['id']}",
            "normalized_sha256": normalized_sha256,
            "observed_at": row["recorded_at"],
            "occurred_at": row["occurred_at"],
            "original_bytes": len(str(row["payload_json"]).encode("utf-8")),
            "parent_span_id": None,
            "policy_digest": policy_digest,
            "previous_event_hash": previous_hash,
            "privacy_class": "internal",
            "project_id": project_id,
            "project_sequence": sequence,
            "recorded_at": row["recorded_at"],
            "redaction_count": 0,
            "repository_commit": None,
            "repository_identity": None,
            "repository_ref": None,
            "source_cursor": str(row["cursor"]),
            "source_id": "legacy-session-events",
            "source_sha256": row["source_hash"],
            "span_id": None,
            "stored_bytes": len(attributes_json.encode("ascii")),
            "trace_id": None,
            "truncation_count": 0,
            "verification_status": verification_status,
        }
        event_hash = hashlib.sha256(
            canonical_json(capture_event_envelope(event_values)).encode("utf-8")
        ).hexdigest()
        conn.execute(
            """
            INSERT OR IGNORE INTO capture_events(
                project_id, project_sequence, event_id, source_row_id, source_id,
                external_session_id, source_cursor, idempotency_key, event_name,
                occurred_at, observed_at, recorded_at, actor_type, actor_id,
                attributes_json, source_sha256, normalized_sha256,
                previous_event_hash, event_hash, original_bytes, stored_bytes,
                redaction_count, truncation_count, privacy_class,
                verification_status, policy_row_id, policy_digest, gap_state
            ) VALUES (?, ?, ?, ?, 'legacy-session-events', ?, ?, ?,
                      'vendor.event.v1', ?, ?, ?, 'adapter', 'legacy-session-events',
                      ?, ?, ?, ?, ?, ?, ?, 0, 0, 'internal', ?, ?, ?, 'none')
            """,
            (
                project_id, sequence, event_id, int(source["id"]), str(row["session_id"]),
                str(row["cursor"]), f"legacy-session-event:{row['id']}",
                row["occurred_at"], row["recorded_at"], row["recorded_at"],
                attributes_json, row["source_hash"], normalized_sha256, previous_hash,
                event_hash, len(str(row["payload_json"]).encode("utf-8")),
                len(attributes_json.encode("ascii")),
                verification_status,
                int(policy["id"]), policy_digest,
            ),
        )
        actual = conn.execute(
            "SELECT normalized_sha256, event_hash FROM capture_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if actual is None or actual["normalized_sha256"] != normalized_sha256 or actual["event_hash"] != event_hash:
            raise RuntimeError("legacy session event migration conflict")


def migrate_capture_schema_v10(conn: sqlite3.Connection) -> None:
    _upgrade_policy_retirement_trigger(conn)
    _execute_schema(conn)
    _migrate_legacy_cursors(conn)
    _register_legacy_session_events(conn)
    validate_capture_schema_v10(conn)
