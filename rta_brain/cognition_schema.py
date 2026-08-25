import sqlite3


COGNITION_SCHEMA_VERSION = 1


_SCHEMA = """
CREATE TABLE IF NOT EXISTS cognition_observations (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    observation_id TEXT NOT NULL,
    subsystem TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    expected_state TEXT,
    observed_state TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN (
        'observed', 'expected', 'missing', 'stale', 'conflicting', 'blocked', 'unknown'
    )),
    source_identifier TEXT NOT NULL,
    source_hash TEXT,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    observed_at TEXT NOT NULL,
    valid_until TEXT,
    privacy_class TEXT NOT NULL DEFAULT 'internal',
    sharing_policy TEXT NOT NULL DEFAULT 'local-only',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, observation_id)
);

CREATE TABLE IF NOT EXISTS cognition_reconciliation_receipts (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    receipt_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    action TEXT NOT NULL,
    outcome TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(project_id, receipt_id)
);

CREATE TABLE IF NOT EXISTS multimodal_sources (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_id TEXT NOT NULL,
    source_identifier TEXT NOT NULL,
    media_kind TEXT NOT NULL CHECK(media_kind IN (
        'pdf', 'image', 'audio', 'video', 'diagram', 'document', 'unknown'
    )),
    mime_type TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    byte_size INTEGER NOT NULL CHECK(byte_size >= 0),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    privacy_class TEXT NOT NULL DEFAULT 'internal',
    sharing_policy TEXT NOT NULL DEFAULT 'local-only',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(project_id, source_id),
    UNIQUE(project_id, source_identifier, content_sha256)
);

CREATE TABLE IF NOT EXISTS multimodal_derivations (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    derivation_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    method TEXT NOT NULL,
    tool_identity TEXT NOT NULL,
    model_identity TEXT,
    source_sha256 TEXT NOT NULL,
    output_sha256 TEXT NOT NULL,
    text TEXT NOT NULL CHECK(length(text) <= 65536),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    verification_status TEXT NOT NULL CHECK(verification_status IN (
        'unverified', 'verified', 'failed', 'stale'
    )),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    privacy_class TEXT NOT NULL DEFAULT 'internal',
    sharing_policy TEXT NOT NULL DEFAULT 'local-only',
    created_at TEXT NOT NULL,
    UNIQUE(project_id, derivation_id),
    FOREIGN KEY(project_id, source_id)
        REFERENCES multimodal_sources(project_id, source_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cognition_observations_project_status
    ON cognition_observations(project_id, status, subsystem);
CREATE INDEX IF NOT EXISTS idx_cognition_receipts_observation
    ON cognition_reconciliation_receipts(project_id, observation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_multimodal_sources_project_kind
    ON multimodal_sources(project_id, media_kind, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_multimodal_derivations_source
    ON multimodal_derivations(project_id, source_id, created_at DESC);

CREATE TRIGGER IF NOT EXISTS cognition_receipts_no_update
BEFORE UPDATE ON cognition_reconciliation_receipts
BEGIN
    SELECT RAISE(ABORT, 'cognition reconciliation receipts are immutable');
END;

CREATE TRIGGER IF NOT EXISTS cognition_receipts_no_delete
BEFORE DELETE ON cognition_reconciliation_receipts
BEGIN
    SELECT RAISE(ABORT, 'cognition reconciliation receipts are immutable');
END;
"""


def migrate_cognition_schema_v11(conn: sqlite3.Connection) -> None:
    statement = ""
    for line in _SCHEMA.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            sql = statement.strip()
            if sql:
                conn.execute(sql)
            statement = ""
    if statement.strip():
        raise ValueError("incomplete internal cognition schema statement")


def validate_cognition_schema_v11(conn: sqlite3.Connection) -> None:
    required = {
        "cognition_observations",
        "cognition_reconciliation_receipts",
        "multimodal_sources",
        "multimodal_derivations",
    }
    tables = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    missing = sorted(required - tables)
    if missing:
        raise ValueError(f"cognition schema v11 is incomplete: {', '.join(missing)}")
