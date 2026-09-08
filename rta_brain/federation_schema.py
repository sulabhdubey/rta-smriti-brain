"""Schema v12 for governed, encrypted federation records."""

from __future__ import annotations

import sqlite3

FEDERATION_TABLES = frozenset(
    {
        "federation_identities",
        "federation_spaces",
        "federation_scopes",
        "federation_scope_epochs",
        "federation_peers",
        "federation_capability_events",
        "federation_key_envelopes",
        "federation_events",
        "federation_event_validation",
        "federation_sync_cursors",
        "federation_quarantine",
        "federation_quarantine_receipts",
        "federation_domain_events",
        "federation_projections",
        "federation_invitation_receipts",
        "federation_operation_receipts",
    }
)

FEDERATION_TRIGGERS = frozenset(
    {
        "federation_identities_no_update",
        "federation_identities_no_delete",
        "federation_spaces_no_update",
        "federation_spaces_no_delete",
        "federation_scopes_no_update",
        "federation_scopes_no_delete",
        "federation_scope_epochs_no_update",
        "federation_scope_epochs_no_delete",
        "federation_peers_no_update",
        "federation_peers_no_delete",
        "federation_capability_events_no_update",
        "federation_capability_events_no_delete",
        "federation_key_envelopes_no_update",
        "federation_key_envelopes_no_delete",
        "federation_events_no_update",
        "federation_events_no_delete",
        "federation_quarantine_no_update",
        "federation_quarantine_no_delete",
        "federation_quarantine_receipts_no_update",
        "federation_quarantine_receipts_no_delete",
        "federation_domain_events_no_update",
        "federation_domain_events_no_delete",
        "federation_invitation_receipts_no_update",
        "federation_invitation_receipts_no_delete",
        "federation_operation_receipts_no_update",
        "federation_operation_receipts_no_delete",
    }
)

FEDERATION_INDEXES = frozenset(
    {
        "idx_federation_events_space_scope_epoch",
        "idx_federation_events_author_sequence",
        "idx_federation_events_validation",
        "idx_federation_capabilities_subject",
        "idx_federation_key_envelopes_recipient",
        "idx_federation_quarantine_state",
        "idx_federation_quarantine_receipts",
        "idx_federation_quarantine_final_disposition",
        "idx_federation_sync_cursors_space",
    }
)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS federation_identities (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    identity_id TEXT NOT NULL CHECK(length(identity_id) = 64),
    signing_public_key BLOB NOT NULL CHECK(length(signing_public_key) = 32),
    envelope_public_key BLOB NOT NULL CHECK(length(envelope_public_key) = 32),
    key_fingerprint TEXT NOT NULL CHECK(length(key_fingerprint) = 64),
    key_reference TEXT NOT NULL CHECK(length(key_reference) BETWEEN 1 AND 4096),
    created_at TEXT NOT NULL,
    UNIQUE(project_id, identity_id),
    UNIQUE(project_id, key_fingerprint)
);

CREATE TABLE IF NOT EXISTS federation_spaces (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    wire_schema TEXT NOT NULL CHECK(wire_schema = 'rta-smriti.federation/v1'),
    owner_peer_id TEXT NOT NULL CHECK(length(owner_peer_id) = 64),
    created_at TEXT NOT NULL,
    UNIQUE(project_id, space_id)
);

CREATE TABLE IF NOT EXISTS federation_scopes (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    scope_id TEXT NOT NULL CHECK(length(scope_id) = 64),
    scope_kind TEXT NOT NULL CHECK(scope_kind IN ('team', 'review', 'custom')),
    label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 256),
    created_by_peer_id TEXT NOT NULL CHECK(length(created_by_peer_id) = 64),
    created_at TEXT NOT NULL,
    UNIQUE(project_id, space_id, scope_id),
    FOREIGN KEY(project_id, space_id)
        REFERENCES federation_spaces(project_id, space_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS federation_peers (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    peer_id TEXT NOT NULL CHECK(length(peer_id) = 64),
    label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 256),
    signing_public_key BLOB NOT NULL CHECK(length(signing_public_key) = 32),
    envelope_public_key BLOB NOT NULL CHECK(length(envelope_public_key) = 32),
    added_at TEXT NOT NULL,
    UNIQUE(project_id, space_id, peer_id),
    FOREIGN KEY(project_id, space_id)
        REFERENCES federation_spaces(project_id, space_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS federation_scope_epochs (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    scope_id TEXT NOT NULL CHECK(length(scope_id) = 64),
    epoch INTEGER NOT NULL CHECK(epoch > 0),
    rotation_event_id TEXT NOT NULL CHECK(length(rotation_event_id) = 64),
    key_digest TEXT NOT NULL CHECK(length(key_digest) = 64),
    created_at TEXT NOT NULL,
    UNIQUE(project_id, space_id, scope_id, epoch),
    UNIQUE(project_id, space_id, rotation_event_id),
    FOREIGN KEY(project_id, space_id, scope_id)
        REFERENCES federation_scopes(project_id, space_id, scope_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS federation_capability_events (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    scope_id TEXT CHECK(scope_id IS NULL OR length(scope_id) = 64),
    event_id TEXT NOT NULL CHECK(length(event_id) = 64),
    subject_peer_id TEXT NOT NULL CHECK(length(subject_peer_id) = 64),
    action TEXT NOT NULL CHECK(action IN (
        'grant', 'suspend', 'revoke', 'readmit', 'rotate', 'resolve_conflict'
    )),
    capabilities_json TEXT NOT NULL CHECK(
        json_valid(capabilities_json) AND length(capabilities_json) <= 16384
    ),
    author_peer_id TEXT NOT NULL CHECK(length(author_peer_id) = 64),
    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
    parents_json TEXT NOT NULL CHECK(
        json_valid(parents_json) AND length(parents_json) <= 65536
    ),
    event_digest TEXT NOT NULL CHECK(length(event_digest) = 64),
    signature BLOB NOT NULL CHECK(length(signature) = 64),
    recorded_at TEXT NOT NULL,
    UNIQUE(project_id, space_id, event_id),
    UNIQUE(project_id, space_id, author_peer_id, author_sequence)
);

CREATE TABLE IF NOT EXISTS federation_key_envelopes (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    scope_id TEXT NOT NULL CHECK(length(scope_id) = 64),
    epoch INTEGER NOT NULL CHECK(epoch > 0),
    envelope_id TEXT NOT NULL CHECK(length(envelope_id) = 64),
    recipient_peer_id TEXT NOT NULL CHECK(length(recipient_peer_id) = 64),
    issuer_peer_id TEXT NOT NULL CHECK(length(issuer_peer_id) = 64),
    hpke_ciphertext BLOB NOT NULL CHECK(length(hpke_ciphertext) BETWEEN 1 AND 65536),
    envelope_digest TEXT NOT NULL CHECK(length(envelope_digest) = 64),
    signature BLOB NOT NULL CHECK(length(signature) = 64),
    created_at TEXT NOT NULL,
    UNIQUE(project_id, space_id, scope_id, epoch, recipient_peer_id),
    UNIQUE(project_id, space_id, envelope_id)
);

CREATE TABLE IF NOT EXISTS federation_events (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    scope_id TEXT NOT NULL CHECK(length(scope_id) = 64),
    epoch INTEGER NOT NULL CHECK(epoch > 0),
    event_id TEXT NOT NULL CHECK(length(event_id) = 64),
    author_peer_id TEXT NOT NULL CHECK(length(author_peer_id) = 64),
    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
    capability_event_id TEXT NOT NULL CHECK(length(capability_event_id) = 64),
    parents_json TEXT NOT NULL CHECK(
        json_valid(parents_json) AND length(parents_json) <= 65536
    ),
    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 1048576),
    ciphertext_sha256 TEXT NOT NULL CHECK(length(ciphertext_sha256) = 64),
    signature BLOB NOT NULL CHECK(length(signature) = 64),
    received_at TEXT NOT NULL,
    UNIQUE(id, project_id),
    UNIQUE(project_id, space_id, event_id),
    UNIQUE(project_id, space_id, author_peer_id, author_sequence),
    UNIQUE(project_id, space_id, scope_id, epoch, nonce)
);

CREATE TABLE IF NOT EXISTS federation_event_validation (
    event_row_id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    validation_state TEXT NOT NULL CHECK(validation_state IN (
        'received', 'pending_parent', 'accepted', 'quarantined'
    )),
    reason_code TEXT,
    validated_at TEXT,
    projection_sequence INTEGER CHECK(projection_sequence IS NULL OR projection_sequence > 0),
    FOREIGN KEY(event_row_id, project_id)
        REFERENCES federation_events(id, project_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS federation_sync_cursors (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    transport_id TEXT NOT NULL CHECK(length(transport_id) BETWEEN 1 AND 256),
    cursor TEXT NOT NULL CHECK(length(cursor) BETWEEN 1 AND 4096),
    inventory_digest TEXT NOT NULL CHECK(length(inventory_digest) = 64),
    state TEXT NOT NULL CHECK(state IN ('idle', 'partial', 'complete', 'error')),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(project_id, space_id, transport_id)
);

CREATE TABLE IF NOT EXISTS federation_quarantine (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT CHECK(space_id IS NULL OR length(space_id) = 64),
    claimed_event_id TEXT CHECK(claimed_event_id IS NULL OR length(claimed_event_id) = 64),
    reason_code TEXT NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 128),
    envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256) = 64),
    encoded_bytes INTEGER NOT NULL CHECK(encoded_bytes BETWEEN 0 AND 2097152),
    state TEXT NOT NULL CHECK(state IN ('pending', 'rejected', 'promoted')),
    recorded_at TEXT NOT NULL,
    UNIQUE(project_id, envelope_sha256)
);

CREATE TABLE IF NOT EXISTS federation_quarantine_receipts (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    quarantine_id INTEGER NOT NULL REFERENCES federation_quarantine(id) ON DELETE RESTRICT,
    disposition_id TEXT NOT NULL CHECK(length(disposition_id) = 64),
    action TEXT NOT NULL CHECK(action IN ('promoted', 'rejected')),
    actor_peer_id TEXT NOT NULL CHECK(length(actor_peer_id) = 64),
    reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 512),
    recorded_at TEXT NOT NULL,
    UNIQUE(project_id, disposition_id)
);

CREATE TABLE IF NOT EXISTS federation_projections (
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    projection_name TEXT NOT NULL CHECK(length(projection_name) BETWEEN 1 AND 128),
    schema_version INTEGER NOT NULL CHECK(schema_version > 0),
    accepted_event_count INTEGER NOT NULL CHECK(accepted_event_count >= 0),
    head_digest TEXT NOT NULL CHECK(length(head_digest) = 64),
    state TEXT NOT NULL CHECK(state IN ('ready', 'partial', 'conflict', 'blocked')),
    rebuilt_at TEXT NOT NULL,
    PRIMARY KEY(project_id, space_id, projection_name)
);

CREATE TABLE IF NOT EXISTS federation_domain_events (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    scope_id TEXT NOT NULL CHECK(length(scope_id) = 64),
    event_id TEXT NOT NULL CHECK(length(event_id) = 64),
    event_type TEXT NOT NULL CHECK(length(event_type) BETWEEN 1 AND 128),
    object_id TEXT NOT NULL CHECK(length(object_id) BETWEEN 1 AND 512),
    author_peer_id TEXT NOT NULL CHECK(length(author_peer_id) = 64),
    causal_depth INTEGER NOT NULL CHECK(causal_depth >= 0),
    deterministic_order INTEGER NOT NULL CHECK(deterministic_order > 0),
    payload_json TEXT NOT NULL CHECK(
        json_valid(payload_json) AND length(payload_json) <= 1048576
    ),
    payload_digest TEXT NOT NULL CHECK(length(payload_digest) = 64),
    projected_at TEXT NOT NULL,
    UNIQUE(project_id, space_id, event_id),
    FOREIGN KEY(project_id, space_id, event_id)
        REFERENCES federation_events(project_id, space_id, event_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS federation_invitation_receipts (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    space_id TEXT NOT NULL CHECK(length(space_id) = 64),
    invitation_id TEXT NOT NULL CHECK(length(invitation_id) = 64),
    direction TEXT NOT NULL CHECK(direction IN ('outbound', 'inbound')),
    action TEXT NOT NULL CHECK(action IN ('issued', 'accepted', 'rejected', 'expired')),
    peer_id TEXT NOT NULL CHECK(length(peer_id) = 64),
    bundle_digest TEXT NOT NULL CHECK(length(bundle_digest) = 64),
    recorded_at TEXT NOT NULL,
    UNIQUE(project_id, invitation_id, direction, action)
);

CREATE TABLE IF NOT EXISTS federation_operation_receipts (
    id INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL CHECK(length(operation_id) = 64),
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 64),
    actor_peer_id TEXT NOT NULL CHECK(length(actor_peer_id) = 64),
    request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
    state_before_digest TEXT NOT NULL CHECK(length(state_before_digest) = 64),
    state_after_digest TEXT NOT NULL CHECK(length(state_after_digest) = 64),
    result_digest TEXT NOT NULL CHECK(length(result_digest) = 64),
    recorded_at TEXT NOT NULL,
    UNIQUE(project_id, operation_id)
);

CREATE INDEX IF NOT EXISTS idx_federation_events_space_scope_epoch
    ON federation_events(project_id, space_id, scope_id, epoch, event_id);
CREATE INDEX IF NOT EXISTS idx_federation_events_author_sequence
    ON federation_events(project_id, space_id, author_peer_id, author_sequence);
CREATE INDEX IF NOT EXISTS idx_federation_events_validation
    ON federation_event_validation(project_id, validation_state, event_row_id);
CREATE INDEX IF NOT EXISTS idx_federation_capabilities_subject
    ON federation_capability_events(
        project_id, space_id, subject_peer_id, scope_id, author_sequence
    );
CREATE INDEX IF NOT EXISTS idx_federation_key_envelopes_recipient
    ON federation_key_envelopes(
        project_id, space_id, recipient_peer_id, scope_id, epoch
    );
CREATE INDEX IF NOT EXISTS idx_federation_quarantine_state
    ON federation_quarantine(project_id, state, recorded_at);
CREATE INDEX IF NOT EXISTS idx_federation_quarantine_receipts
    ON federation_quarantine_receipts(project_id, quarantine_id, recorded_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_federation_quarantine_final_disposition
    ON federation_quarantine_receipts(project_id, quarantine_id);
CREATE INDEX IF NOT EXISTS idx_federation_sync_cursors_space
    ON federation_sync_cursors(project_id, space_id, state, updated_at);

CREATE TRIGGER IF NOT EXISTS federation_identities_no_update
BEFORE UPDATE ON federation_identities
BEGIN SELECT RAISE(ABORT, 'federation identities are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_identities_no_delete
BEFORE DELETE ON federation_identities
BEGIN SELECT RAISE(ABORT, 'federation identities are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_spaces_no_update
BEFORE UPDATE ON federation_spaces
BEGIN SELECT RAISE(ABORT, 'federation spaces are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_spaces_no_delete
BEFORE DELETE ON federation_spaces
BEGIN SELECT RAISE(ABORT, 'federation spaces are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_scopes_no_update
BEFORE UPDATE ON federation_scopes
BEGIN SELECT RAISE(ABORT, 'federation scopes are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_scopes_no_delete
BEFORE DELETE ON federation_scopes
BEGIN SELECT RAISE(ABORT, 'federation scopes are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_scope_epochs_no_update
BEFORE UPDATE ON federation_scope_epochs
BEGIN SELECT RAISE(ABORT, 'federation scope epochs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_scope_epochs_no_delete
BEFORE DELETE ON federation_scope_epochs
BEGIN SELECT RAISE(ABORT, 'federation scope epochs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_peers_no_update
BEFORE UPDATE ON federation_peers
BEGIN SELECT RAISE(ABORT, 'federation peers are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_peers_no_delete
BEFORE DELETE ON federation_peers
BEGIN SELECT RAISE(ABORT, 'federation peers are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_capability_events_no_update
BEFORE UPDATE ON federation_capability_events
BEGIN SELECT RAISE(ABORT, 'federation capability events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_capability_events_no_delete
BEFORE DELETE ON federation_capability_events
BEGIN SELECT RAISE(ABORT, 'federation capability events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_key_envelopes_no_update
BEFORE UPDATE ON federation_key_envelopes
BEGIN SELECT RAISE(ABORT, 'federation key envelopes are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_key_envelopes_no_delete
BEFORE DELETE ON federation_key_envelopes
BEGIN SELECT RAISE(ABORT, 'federation key envelopes are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_events_no_update
BEFORE UPDATE ON federation_events
BEGIN SELECT RAISE(ABORT, 'federation events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_events_no_delete
BEFORE DELETE ON federation_events
BEGIN SELECT RAISE(ABORT, 'federation events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_quarantine_no_update
BEFORE UPDATE ON federation_quarantine
BEGIN SELECT RAISE(ABORT, 'federation quarantine receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_quarantine_no_delete
BEFORE DELETE ON federation_quarantine
BEGIN SELECT RAISE(ABORT, 'federation quarantine receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_quarantine_receipts_no_update
BEFORE UPDATE ON federation_quarantine_receipts
BEGIN SELECT RAISE(ABORT, 'federation quarantine dispositions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_quarantine_receipts_no_delete
BEFORE DELETE ON federation_quarantine_receipts
BEGIN SELECT RAISE(ABORT, 'federation quarantine dispositions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_domain_events_no_update
BEFORE UPDATE ON federation_domain_events
BEGIN SELECT RAISE(ABORT, 'federation domain projections are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_domain_events_no_delete
BEFORE DELETE ON federation_domain_events
BEGIN SELECT RAISE(ABORT, 'federation domain projections are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_invitation_receipts_no_update
BEFORE UPDATE ON federation_invitation_receipts
BEGIN SELECT RAISE(ABORT, 'federation invitation receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_invitation_receipts_no_delete
BEFORE DELETE ON federation_invitation_receipts
BEGIN SELECT RAISE(ABORT, 'federation invitation receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_operation_receipts_no_update
BEFORE UPDATE ON federation_operation_receipts
BEGIN SELECT RAISE(ABORT, 'federation operation receipts are immutable'); END;
CREATE TRIGGER IF NOT EXISTS federation_operation_receipts_no_delete
BEFORE DELETE ON federation_operation_receipts
BEGIN SELECT RAISE(ABORT, 'federation operation receipts are immutable'); END;
"""


def _execute_schema(conn: sqlite3.Connection) -> None:
    statement = ""
    for line in _SCHEMA.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            sql = statement.strip()
            if sql:
                conn.execute(sql)
            statement = ""
    if statement.strip():
        raise ValueError("incomplete internal federation schema statement")


def migrate_federation_schema_v12(conn: sqlite3.Connection) -> None:
    _execute_schema(conn)


def _object_names(conn: sqlite3.Connection, object_type: str) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = ?", (object_type,)
        )
    }


def validate_federation_schema_v12(conn: sqlite3.Connection) -> None:
    missing_tables = sorted(FEDERATION_TABLES - _object_names(conn, "table"))
    missing_triggers = sorted(FEDERATION_TRIGGERS - _object_names(conn, "trigger"))
    missing_indexes = sorted(FEDERATION_INDEXES - _object_names(conn, "index"))
    missing = missing_tables + missing_triggers + missing_indexes
    if missing:
        raise ValueError(f"federation schema v12 is incomplete: {', '.join(missing)}")
