import json
import math
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rta_brain import db

CAPTURE_TABLES = {
    "capture_policies",
    "capture_sources",
    "capture_events",
    "capture_payloads",
    "capture_adapter_cursors",
    "capture_session_bindings",
    "capture_projections",
    "capture_tombstones",
    "capture_retention_runs",
}


class CaptureSchemaTests(unittest.TestCase):
    def _table_names(self, conn):
        return {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }

    def _make_v9_database(self, path: Path):
        conn = db.connect(path)
        try:
            db.init_schema(conn)
        finally:
            conn.close()
        legacy = sqlite3.connect(path)
        try:
            capture_objects = legacy.execute(
                """
                SELECT type, name FROM sqlite_master
                WHERE name LIKE 'capture_%'
                ORDER BY CASE type WHEN 'trigger' THEN 0 WHEN 'index' THEN 1 ELSE 2 END
                """
            ).fetchall()
            for object_type, name in capture_objects:
                if object_type in {"trigger", "index"}:
                    legacy.execute(f'DROP {object_type.upper()} IF EXISTS "{name}"')
                elif object_type == "table":
                    legacy.execute(f'DROP TABLE IF EXISTS "{name}"')
            legacy.execute(
                """
                CREATE TABLE IF NOT EXISTS adapter_cursors (
                    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    adapter TEXT NOT NULL,
                    stream_id TEXT NOT NULL,
                    cursor INTEGER NOT NULL,
                    source_path TEXT,
                    source_hash TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(project_id, adapter, stream_id)
                )
                """
            )
            legacy.execute(
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
                )
                """
            )
            legacy.execute("PRAGMA user_version = 9")
            legacy.commit()
        finally:
            legacy.close()

    def _insert_capture_event(self, conn, project_id: int, suffix: str) -> int:
        policy_digest = (suffix[0] if suffix else "a") * 64
        policy_row_id = conn.execute(
            """
            INSERT INTO capture_policies(
                project_id, policy_id, policy_version, profile,
                enabled_event_names_json, field_allowlist_json,
                privacy_ceiling, retain_payloads, retention_seconds,
                max_event_bytes, max_field_chars, max_collection_items,
                policy_digest, created_at
            ) VALUES (?, ?, 1, 'metadata-only', '[]', '{}', 'internal',
                      0, 86400, 262144, 16000, 100, ?,
                      '2026-08-22T00:00:00+00:00')
            """,
            (project_id, f"policy-{suffix}", policy_digest),
        ).lastrowid
        source_row_id = conn.execute(
            """
            INSERT INTO capture_sources(
                project_id, source_id, adapter, adapter_version,
                installation_scope, config_fingerprint, policy_row_id,
                policy_digest, state, created_at, updated_at
            ) VALUES (?, ?, 'generic', '1', 'project', ?, ?, ?, 'active',
                      '2026-08-22T00:00:00+00:00',
                      '2026-08-22T00:00:00+00:00')
            """,
            (
                project_id, f"source-{suffix}", "b" * 64,
                policy_row_id, policy_digest,
            ),
        ).lastrowid
        return conn.execute(
            """
            INSERT INTO capture_events(
                project_id, project_sequence, event_id, source_row_id,
                source_id, external_session_id, source_cursor,
                idempotency_key, event_name, occurred_at, observed_at,
                recorded_at, actor_type, actor_id, attributes_json,
                normalized_sha256, previous_event_hash, event_hash,
                original_bytes, stored_bytes, redaction_count,
                truncation_count, privacy_class, verification_status,
                policy_row_id, policy_digest, gap_state
            ) VALUES (?, 1, ?, ?, ?, ?, '1', ?, 'session.started.v1',
                      '2026-08-22T00:00:00+00:00',
                      '2026-08-22T00:00:00+00:00',
                      '2026-08-22T00:00:00+00:00', 'adapter', 'generic',
                      '{}', ?, NULL, ?, 2, 2, 0, 0, 'internal',
                      'unverified', ?, ?, 'none')
            """,
            (
                project_id, f"event-{suffix}", source_row_id,
                f"source-{suffix}", f"session-{suffix}", f"idem-{suffix}",
                "c" * 64, "d" * 64, policy_row_id, policy_digest,
            ),
        ).lastrowid

    def test_capture_types_are_strict_and_versioned(self):
        from rta_brain.capture_types import (
            CAPTURE_EVENT_NAMES,
            CAPTURE_SCHEMA_VERSION,
            CaptureEnvelope,
            CapturePolicy,
            CaptureReplayPage,
            CaptureSource,
            NormalizedEvent,
            canonical_json,
        )

        self.assertEqual(CAPTURE_SCHEMA_VERSION, "rta-smriti.capture/v1")
        self.assertIn("session.started.v1", CAPTURE_EVENT_NAMES)
        self.assertIn("capture.gap.v1", CAPTURE_EVENT_NAMES)
        policy = CapturePolicy.continuity()
        self.assertEqual(policy.profile, "continuity")
        self.assertFalse(policy.retain_payloads)
        self.assertEqual(len(policy.digest), 64)
        with self.assertRaises(ValueError):
            CapturePolicy(profile="unbounded")
        with self.assertRaises((TypeError, ValueError)):
            CapturePolicy(max_event_bytes="262144")
        with self.assertRaises((TypeError, ValueError)):
            CapturePolicy(max_event_bytes=True)
        with self.assertRaises(ValueError):
            canonical_json({"value": math.nan})
        envelope = CaptureEnvelope(
            adapter="generic", adapter_version="1", event_name="session.started.v1",
            session_id="session-1", source_cursor="1",
            observed_at="2026-08-22T00:00:00+00:00", payload={},
            trace_id="1" * 32, span_id="2" * 16,
        )
        event = NormalizedEvent.from_envelope(envelope, attributes={})
        source = CaptureSource(
            source_id="source-1", adapter="generic", adapter_version="1",
            installation_scope="api", config_fingerprint="a" * 64,
        )
        page = CaptureReplayPage(events=(event,), next_cursor="1", complete=True)
        self.assertEqual(source.source_id, "source-1")
        self.assertEqual(page.events[0].trace_id, "1" * 32)
        with self.assertRaises(ValueError):
            CaptureEnvelope(
                adapter="generic", adapter_version="1", event_name="session.started.v1",
                session_id="session-1", source_cursor="1",
                observed_at="2026-08-22T00:00:00+00:00", payload={},
                trace_id="private-project-name", span_id=None,
            )

    def test_init_schema_migrates_v9_to_v10_and_preserves_legacy_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._make_v9_database(database)
            legacy = sqlite3.connect(database)
            try:
                legacy.row_factory = sqlite3.Row
                legacy.execute(
                    "INSERT OR IGNORE INTO projects(name, root_path, created_at) VALUES ('demo', NULL, '2026-08-22T00:00:00+00:00')"
                )
                project_id = legacy.execute(
                    "SELECT id FROM projects WHERE name = 'demo'"
                ).fetchone()[0]
                legacy.execute(
                    """
                    INSERT INTO adapter_cursors(
                        project_id, adapter, stream_id, cursor, source_path,
                        source_hash, updated_at
                    ) VALUES (?, 'codex-jsonl', 'session-1', 42, 'session.jsonl',
                              'source-hash', '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id,),
                )
                legacy.execute(
                    """
                    INSERT INTO session_events(
                        project_id, session_id, cursor, event_type, payload_json,
                        source, source_hash, verification_status, occurred_at, recorded_at
                    ) VALUES (?, 'session-1', '42', 'assistant_message',
                              '{"text":"already redacted"}', 'codex-jsonl',
                              'event-source-hash', 'unverified',
                              '2026-08-22T00:00:00+00:00',
                              '2026-08-22T00:00:01+00:00')
                    """,
                    (project_id,),
                )
                legacy.commit()
            finally:
                legacy.close()

            conn = db.connect(database)
            try:
                db.init_schema(conn)
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
                self.assertTrue(CAPTURE_TABLES.issubset(self._table_names(conn)))
                cursor = conn.execute(
                    """
                    SELECT adapter, stream_id, cursor, cursor_kind, source_path,
                           source_hash, binding_offset
                    FROM capture_adapter_cursors
                    """
                ).fetchone()
                self.assertEqual(dict(cursor), {
                    "adapter": "codex-jsonl",
                    "stream_id": "session-1",
                    "cursor": "42",
                    "cursor_kind": "byte-offset",
                    "source_path": "session.jsonl",
                    "source_hash": "source-hash",
                    "binding_offset": 0,
                })
                triggers = {
                    row["name"]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                self.assertTrue({
                    "capture_events_no_update",
                    "capture_events_no_delete",
                    "capture_policies_no_update",
                    "capture_policies_no_delete",
                    "capture_session_bindings_guard_update",
                    "capture_session_bindings_no_delete",
                }.issubset(triggers))
                legacy_event = conn.execute(
                    """
                    SELECT event_name, source_sha256, attributes_json
                    FROM capture_events
                    WHERE external_session_id = 'session-1' AND source_cursor = '42'
                    """
                ).fetchone()
                self.assertIsNotNone(legacy_event)
                self.assertEqual(legacy_event["event_name"], "vendor.event.v1")
                self.assertEqual(legacy_event["source_sha256"], "event-source-hash")
                self.assertEqual(
                    json.loads(legacy_event["attributes_json"]),
                    {
                        "legacy_event_type": "assistant_message",
                        "legacy_session_event_id": 1,
                        "payload_retained_in": "session_events",
                    },
                )
                from rta_brain.capture import verify_journal

                journal = verify_journal(conn, project="demo")
                self.assertTrue(journal["chain_valid"])
                self.assertEqual(journal["events_verified"], 1)
                conn.execute("DROP TRIGGER capture_events_no_update")
                conn.execute(
                    "UPDATE capture_events SET actor_id = 'tampered-legacy-actor'"
                )
                conn.execute(
                    """
                    CREATE TRIGGER capture_events_no_update
                    BEFORE UPDATE ON capture_events
                    BEGIN SELECT RAISE(ABORT, 'capture events are immutable'); END
                    """
                )
                conn.commit()
                with self.assertRaisesRegex(ValueError, "envelope hash mismatch"):
                    verify_journal(conn, project="demo")
            finally:
                conn.close()

    def test_init_schema_upgrades_pre_patch_v10_capture_tables_idempotently(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", str(Path(tmp) / "repo"))
                project_id = conn.execute(
                    "SELECT id FROM projects WHERE name = 'demo'"
                ).fetchone()[0]
                event_row_id = self._insert_capture_event(conn, project_id, "patch")
                conn.execute(
                    """
                    INSERT INTO capture_payloads(
                        event_row_id, project_id, storage_mode, content_encoding,
                        key_reference, grant_id, nonce, payload_blob, payload_sha256,
                        payload_bytes, expires_at
                    ) VALUES (?, ?, 'encrypted', 'binary', 'capture-key:legacy', ?,
                              '00', X'010203', ?, 3, '2026-08-24T00:00:00+00:00')
                    """,
                    (event_row_id, project_id, "e" * 64, "f" * 64),
                )
                conn.execute(
                    """
                    INSERT INTO capture_retention_runs(
                        project_id, run_id, policy_digest, cutoff_at, state,
                        started_at, updated_at
                    ) VALUES (?, 'legacy-run', ?, '2026-08-23T00:00:00+00:00',
                              'partial', '2026-08-22T00:00:00+00:00',
                              '2026-08-22T00:01:00+00:00')
                    """,
                    (project_id, "a" * 64),
                )
                conn.execute("DROP INDEX idx_capture_payloads_expiry")
                conn.execute("ALTER TABLE capture_payloads RENAME TO capture_payloads_current")
                conn.execute(
                    """
                    CREATE TABLE capture_payloads (
                        id INTEGER PRIMARY KEY,
                        event_row_id INTEGER NOT NULL UNIQUE,
                        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
                        storage_mode TEXT NOT NULL CHECK(storage_mode IN ('encrypted', 'local-plaintext')),
                        content_encoding TEXT NOT NULL,
                        key_reference TEXT,
                        nonce TEXT,
                        payload_blob BLOB,
                        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
                        payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0 AND payload_bytes <= 1048576),
                        expires_at TEXT,
                        deleted_at TEXT,
                        deletion_reason TEXT,
                        CHECK((deleted_at IS NULL AND payload_blob IS NOT NULL) OR (deleted_at IS NOT NULL AND payload_blob IS NULL)),
                        FOREIGN KEY(event_row_id, project_id)
                            REFERENCES capture_events(id, project_id) ON DELETE RESTRICT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO capture_payloads(
                        id, event_row_id, project_id, storage_mode, content_encoding,
                        key_reference, nonce, payload_blob, payload_sha256,
                        payload_bytes, expires_at, deleted_at, deletion_reason
                    )
                    SELECT id, event_row_id, project_id, storage_mode, content_encoding,
                           key_reference, nonce, payload_blob, payload_sha256,
                           payload_bytes, expires_at, deleted_at, deletion_reason
                    FROM capture_payloads_current
                    """
                )
                conn.execute("DROP TABLE capture_payloads_current")
                conn.execute("DROP INDEX idx_capture_retention_project_state")
                conn.execute(
                    "ALTER TABLE capture_retention_runs RENAME TO capture_retention_runs_current"
                )
                conn.execute(
                    """
                    CREATE TABLE capture_retention_runs (
                        id INTEGER PRIMARY KEY,
                        project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
                        run_id TEXT NOT NULL,
                        policy_digest TEXT NOT NULL CHECK(length(policy_digest) = 64),
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
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO capture_retention_runs(
                        id, project_id, run_id, policy_digest, state, cursor,
                        examined_events, deleted_payloads, redacted_events,
                        error_class, started_at, updated_at, completed_at
                    )
                    SELECT id, project_id, run_id, policy_digest, state, cursor,
                           examined_events, deleted_payloads, redacted_events,
                           error_class, started_at, updated_at, completed_at
                    FROM capture_retention_runs_current
                    """
                )
                conn.execute("DROP TABLE capture_retention_runs_current")
                conn.commit()

                def fail_after_patch_write(active_conn):
                    active_conn.execute(
                        "ALTER TABLE capture_payloads ADD COLUMN transient_patch_column TEXT"
                    )
                    raise RuntimeError("forced v10 patch failure")

                with mock.patch(
                    "rta_brain.capture_schema.upgrade_capture_schema_v10_patch",
                    side_effect=fail_after_patch_write,
                ), self.assertRaisesRegex(RuntimeError, "forced v10 patch failure"):
                    db.init_schema(conn)
                self.assertNotIn(
                    "transient_patch_column",
                    {row["name"] for row in conn.execute("PRAGMA table_info(capture_payloads)")},
                )

                db.init_schema(conn)
                db.init_schema(conn)

                payload_columns = {
                    row["name"] for row in conn.execute("PRAGMA table_info(capture_payloads)")
                }
                retention_columns = {
                    row["name"] for row in conn.execute("PRAGMA table_info(capture_retention_runs)")
                }
                migrated = conn.execute(
                    "SELECT * FROM capture_retention_runs WHERE run_id = 'legacy-run'"
                ).fetchone()
                migrated_payload = conn.execute("SELECT * FROM capture_payloads").fetchone()
                self.assertIn("grant_id", payload_columns)
                self.assertIn("cutoff_at", retention_columns)
                self.assertEqual(migrated["state"], "partial")
                self.assertEqual(migrated["cutoff_at"], migrated["started_at"])
                self.assertIsNone(migrated_payload["payload_blob"])
                self.assertIsNotNone(migrated_payload["deleted_at"])
                self.assertEqual(
                    migrated_payload["deletion_reason"], "migration-unbound-grant"
                )
                self.assertEqual(len(migrated_payload["grant_id"]), 64)
                self.assertEqual(migrated_payload["key_reference"], "capture-key:legacy")
                self.assertEqual(migrated_payload["payload_sha256"], "f" * 64)
                self.assertEqual(migrated_payload["payload_bytes"], 3)
            finally:
                conn.close()

    def test_capture_migration_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._make_v9_database(database)
            legacy = sqlite3.connect(database)
            try:
                legacy.execute(
                    "INSERT INTO projects(name, root_path, created_at) VALUES ('demo', NULL, '2026-08-22T00:00:00+00:00')"
                )
                project_id = legacy.execute(
                    "SELECT id FROM projects WHERE name = 'demo'"
                ).fetchone()[0]
                legacy.execute(
                    """
                    INSERT INTO session_events(
                        project_id, session_id, cursor, event_type, payload_json,
                        source, source_hash, verification_status, occurred_at, recorded_at
                    ) VALUES (?, 'session-1', '1', 'assistant_message',
                              '{"text":"already redacted"}', 'codex-jsonl',
                              'event-source-hash', 'verified',
                              '2026-08-22T00:00:00+00:00',
                              '2026-08-22T00:00:01+00:00')
                    """,
                    (project_id,),
                )
                legacy.commit()
            finally:
                legacy.close()
            conn = db.connect(database)
            try:
                db.init_schema(conn)
                first = {
                    row["name"]: row["sql"]
                    for row in conn.execute(
                        "SELECT name, sql FROM sqlite_master WHERE name LIKE 'capture_%'"
                    )
                }
                conn.execute("PRAGMA user_version = 9")
                conn.commit()
                db.init_schema(conn)
                second = {
                    row["name"]: row["sql"]
                    for row in conn.execute(
                        "SELECT name, sql FROM sqlite_master WHERE name LIKE 'capture_%'"
                    )
                }
                self.assertEqual(first, second)
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_conflicting_legacy_cursor_fails_migration(self):
        from rta_brain import capture_schema

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._make_v9_database(database)
            raw = sqlite3.connect(database)
            try:
                raw.execute(
                    "INSERT OR IGNORE INTO projects(name, root_path, created_at) VALUES ('demo', NULL, '2026-08-22T00:00:00+00:00')"
                )
                project_id = raw.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()[0]
                raw.execute(
                    """
                    INSERT INTO adapter_cursors(
                        project_id, adapter, stream_id, cursor, source_path,
                        source_hash, updated_at
                    ) VALUES (?, 'codex-jsonl', 'session-1', 42, 'session.jsonl',
                              'source-hash', '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id,),
                )
                capture_schema._execute_schema(raw)
                raw.execute(
                    """
                    INSERT INTO capture_adapter_cursors(
                        project_id, source_id, adapter, stream_id, cursor,
                        cursor_kind, source_path, source_hash, binding_offset,
                        updated_at
                    ) VALUES (?, 'legacy:codex-jsonl:session-1', 'codex-jsonl',
                              'session-1', '10', 'byte-offset', 'other.jsonl',
                              'wrong-hash', 0, '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id,),
                )
                raw.commit()
            finally:
                raw.close()
            conn = db.connect(database)
            try:
                with self.assertRaisesRegex(RuntimeError, "legacy cursor migration conflict"):
                    db.init_schema(conn)
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 9)
            finally:
                conn.close()

    def test_schema_validation_rejects_counterfeit_trigger_and_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.init_schema(conn)
                conn.execute("DROP TRIGGER capture_events_no_update")
                conn.execute(
                    """
                    CREATE TRIGGER capture_events_no_update
                    BEFORE UPDATE ON capture_events BEGIN SELECT 1; END
                    """
                )
                conn.commit()
                with self.assertRaisesRegex(RuntimeError, "capture schema v10 collision"):
                    db.init_schema(conn)
            finally:
                conn.close()
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.init_schema(conn)
                conn.execute("DROP INDEX idx_capture_events_trace")
                conn.execute(
                    "CREATE INDEX idx_capture_events_trace ON capture_events(project_id, actor_id)"
                )
                conn.commit()
                with self.assertRaisesRegex(RuntimeError, "capture schema v10 collision"):
                    db.init_schema(conn)
            finally:
                conn.close()

    def test_schema_validation_reuses_the_immutable_reference_schema(self):
        from rta_brain import capture_schema

        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_schema(conn)
                cache_clear = getattr(
                    capture_schema._expected_schema_objects, "cache_clear", None
                )
                if cache_clear is not None:
                    cache_clear()
                with mock.patch(
                    "rta_brain.capture_schema._execute_schema",
                    wraps=capture_schema._execute_schema,
                ) as execute_schema:
                    capture_schema.validate_capture_schema_v10(conn)
                    capture_schema.validate_capture_schema_v10(conn)
                self.assertEqual(execute_schema.call_count, 1)
            finally:
                conn.close()

    def test_event_id_is_global_and_cursor_identity_includes_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "one", Path(tmp) / "one")
                db.init_project(conn, "two", Path(tmp) / "two")
                event_indexes = {
                    tuple(row[2] for row in conn.execute(f"PRAGMA index_info('{index[1]}')"))
                    for index in conn.execute("PRAGMA index_list('capture_events')")
                    if index[2]
                }
                self.assertIn(("event_id",), event_indexes)
                cursor_pk = [
                    row[1]
                    for row in sorted(
                        conn.execute("PRAGMA table_info(capture_adapter_cursors)"),
                        key=lambda row: row[5],
                    )
                    if row[5]
                ]
                self.assertEqual(cursor_pk, ["project_id", "source_id", "stream_id"])
            finally:
                conn.close()

    def test_v9_truth_and_context_rows_are_unchanged_by_capture_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._make_v9_database(database)
            raw = sqlite3.connect(database)
            try:
                raw.execute(
                    "INSERT OR IGNORE INTO projects(name, root_path, created_at) VALUES ('demo', NULL, '2026-08-22T00:00:00+00:00')"
                )
                project_id = raw.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()[0]
                raw.execute(
                    """
                    INSERT INTO truth_events(
                        project_id, project_sequence, event_id, stream_id,
                        stream_version, event_type, event_schema, idempotency_key,
                        payload_json, payload_sha256, event_hash, actor_type,
                        actor_id, source, verification_status, recorded_at,
                        privacy_class
                    ) VALUES (?, 1, 'truth-1', 'claim:one', 1, 'claim_asserted.v1',
                              1, 'truth-idem-1', '{}', ?, ?, 'operator', 'owner',
                              'operator', 'verified', '2026-08-22T00:00:00+00:00',
                              'internal')
                    """,
                    (project_id, "a" * 64, "b" * 64),
                )
                raw.execute(
                    """
                    INSERT INTO agent_profiles(project_id, profile_id, created_at)
                    VALUES (?, 'universal', '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id,),
                )
                before_truth = [tuple(row) for row in raw.execute("SELECT * FROM truth_events")]
                before_context = [tuple(row) for row in raw.execute("SELECT * FROM agent_profiles")]
                raw.commit()
            finally:
                raw.close()
            conn = db.connect(database)
            try:
                db.init_schema(conn)
                self.assertEqual(
                    [tuple(row) for row in conn.execute("SELECT * FROM truth_events")],
                    before_truth,
                )
                self.assertEqual(
                    [tuple(row) for row in conn.execute("SELECT * FROM agent_profiles")],
                    before_context,
                )
            finally:
                conn.close()

    def test_capture_events_and_policies_are_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                project_id = conn.execute(
                    "SELECT id FROM projects WHERE name = 'demo'"
                ).fetchone()[0]
                policy_id = conn.execute(
                    """
                    INSERT INTO capture_policies(
                        project_id, policy_id, policy_version, profile,
                        enabled_event_names_json, field_allowlist_json,
                        privacy_ceiling, retain_payloads, retention_seconds,
                        max_event_bytes, max_field_chars, max_collection_items,
                        policy_digest, created_at
                    ) VALUES (?, 'policy-1', 1, 'metadata-only', '[]', '{}',
                              'internal', 0, 86400, 262144, 16000, 100,
                              ?, '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id, "a" * 64),
                ).lastrowid
                source_id = conn.execute(
                    """
                    INSERT INTO capture_sources(
                        project_id, source_id, adapter, adapter_version,
                        installation_scope, config_fingerprint, policy_row_id,
                        policy_digest, state, created_at, updated_at
                    ) VALUES (?, 'source-1', 'generic', '1', 'project', ?, ?, ?,
                              'active', '2026-08-22T00:00:00+00:00',
                              '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id, "b" * 64, policy_id, "a" * 64),
                ).lastrowid
                conn.execute(
                    """
                    INSERT INTO capture_events(
                        project_id, project_sequence, event_id, source_row_id,
                        source_id, external_session_id, source_cursor,
                        idempotency_key, event_name, occurred_at, observed_at,
                        recorded_at, actor_type, actor_id, attributes_json,
                        normalized_sha256, previous_event_hash, event_hash,
                        original_bytes, stored_bytes, redaction_count,
                        truncation_count, privacy_class, verification_status,
                        policy_row_id, policy_digest, gap_state
                    ) VALUES (?, 1, 'event-1', ?, 'source-1', 'session-1', '1',
                              'idem-1', 'session.started.v1',
                              '2026-08-22T00:00:00+00:00',
                              '2026-08-22T00:00:00+00:00',
                              '2026-08-22T00:00:00+00:00', 'agent', 'generic',
                              '{}', ?, NULL, ?, 2, 2, 0, 0, 'internal',
                              'unverified', ?, ?, 'none')
                    """,
                    (project_id, source_id, "c" * 64, "d" * 64, policy_id, "a" * 64),
                )
                conn.commit()
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    conn.execute("UPDATE capture_events SET actor_id = 'changed'")
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    conn.execute("DELETE FROM capture_policies")
            finally:
                conn.close()

    def test_capture_payload_cannot_cross_project_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                project_a = db.init_project(
                    conn, "project-a", str(Path(tmp) / "a")
                )["project"]["id"]
                project_b = db.init_project(
                    conn, "project-b", str(Path(tmp) / "b")
                )["project"]["id"]
                event_row_id = self._insert_capture_event(conn, project_a, "a")
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO capture_payloads(
                            event_row_id, project_id, storage_mode,
                            content_encoding, payload_blob, payload_sha256,
                            payload_bytes
                        ) VALUES (?, ?, 'local-plaintext', 'application/json',
                                  X'7B7D', ?, 2)
                        """,
                        (event_row_id, project_b, "e" * 64),
                    )
            finally:
                conn.close()

    def test_capture_schema_rejects_unregistered_trigger_on_governed_table(self):
        from rta_brain.capture_schema import validate_capture_schema_v10

        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_schema(conn)
                conn.execute(
                    """
                    CREATE TRIGGER capture_events_unregistered
                    AFTER INSERT ON capture_events
                    BEGIN SELECT 1; END
                    """
                )
                with self.assertRaisesRegex(RuntimeError, "unexpected capture trigger"):
                    validate_capture_schema_v10(conn)
            finally:
                conn.close()

    def test_capture_migration_rolls_back_on_validation_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._make_v9_database(database)
            conn = db.connect(database)
            try:
                with mock.patch(
                    "rta_brain.capture_schema.validate_capture_schema_v10",
                    side_effect=RuntimeError("forced validation failure"),
                ), self.assertRaisesRegex(RuntimeError, "forced validation failure"):
                    db.init_schema(conn)
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 9)
                self.assertFalse(CAPTURE_TABLES.intersection(self._table_names(conn)))
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
