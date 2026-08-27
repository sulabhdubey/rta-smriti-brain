import hashlib
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from rta_brain import db

CONTEXT_TABLES = {
    "agent_profiles",
    "agent_profile_versions",
    "task_contracts",
    "context_authority_grants",
    "context_authority_revocations",
    "context_compilations",
    "context_candidate_receipts",
    "context_pack_variants",
    "context_variant_candidate_receipts",
    "context_outcomes",
    "context_attribution_edges",
    "context_benchmark_runs",
    "context_benchmark_metrics",
}


class ContextSchemaMigrationTests(unittest.TestCase):
    def _table_names(self, conn):
        return {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }

    def _v8_database(self, path: Path):
        legacy = sqlite3.connect(path)
        try:
            legacy.executescript(
                """
                CREATE TABLE projects (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    root_path TEXT,
                    repository_identity TEXT,
                    checkout_identity TEXT,
                    created_at TEXT NOT NULL
                );
                INSERT INTO projects VALUES (
                    1, 'demo', NULL, NULL, NULL, '2026-08-22T00:00:00+00:00'
                );
                PRAGMA user_version = 8;
                """
            )
            legacy.commit()
        finally:
            legacy.close()

    def _seed_profile(self, conn, project_id: int) -> int:
        profile_id = conn.execute(
            """
            INSERT INTO agent_profiles(project_id, profile_id, created_at)
            VALUES (?, 'universal', '2026-08-22T00:00:00+00:00')
            """,
            (project_id,),
        ).lastrowid
        return conn.execute(
            """
            INSERT INTO agent_profile_versions(
                agent_profile_id, project_id, profile_id, version, schema_version,
                source, verification_status, canonical_json, digest, created_at,
                created_by
            ) VALUES (?, ?, 'universal', 1, 'v1', 'builtin', 'verified', '{}',
                      'profile-digest', '2026-08-22T00:00:00+00:00', 'system')
            """,
            (profile_id, project_id),
        ).lastrowid

    def _seed_authority_grant(
        self,
        conn,
        project_id: int,
        task_contract_id: int,
        *,
        suffix: str = "default",
        issued_at_epoch_ms: int | None = None,
        expires_at_epoch_ms: int | None = None,
    ) -> int:
        now_ms = int(time.time() * 1000)
        issued_at = now_ms - 60_000 if issued_at_epoch_ms is None else issued_at_epoch_ms
        expires_at = now_ms + 3_600_000 if expires_at_epoch_ms is None else expires_at_epoch_ms
        capability_digest = hashlib.sha256(
            f"{project_id}:{task_contract_id}:{suffix}".encode()
        ).hexdigest()
        return conn.execute(
            """
            INSERT INTO context_authority_grants(
                project_id, task_contract_id, grant_id, claims_json,
                capability_digest, issued_at_epoch_ms, expires_at_epoch_ms,
                issued_by_type, issued_by_id, created_at
            ) VALUES (?, ?, ?, '{}', ?, ?, ?, 'operator', 'owner',
                      '2026-08-22T00:00:00+00:00')
            """,
            (
                project_id,
                task_contract_id,
                f"grant-{suffix}",
                capability_digest,
                issued_at,
                expires_at,
            ),
        ).lastrowid
    def test_init_schema_migrates_v8_to_v9_with_context_tables_and_immutable_triggers(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._v8_database(database)
            conn = db.connect(database)
            try:
                db.init_schema(conn)
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
                self.assertTrue(CONTEXT_TABLES.issubset(self._table_names(conn)))
                triggers = {
                    row["name"]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                self.assertTrue(
                    {
                        "task_contracts_no_update",
                        "task_contracts_no_delete",
                        "context_compilations_finalize_guard",
                        "context_compilations_no_delete",
                        "context_candidate_receipts_no_update",
                        "context_candidate_receipts_no_delete",
                        "context_variant_candidate_receipts_no_update",
                        "context_variant_candidate_receipts_no_delete",
                        "context_variant_candidates_building_guard",
                    }.issubset(triggers)
                )
            finally:
                conn.close()

    def test_v9_migration_retry_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._v8_database(database)
            conn = db.connect(database)
            try:
                db.init_schema(conn)
                first = {
                    row["name"]: row["sql"]
                    for row in conn.execute(
                        "SELECT name, sql FROM sqlite_master WHERE name LIKE 'context_%' OR name LIKE 'agent_%' OR name = 'task_contracts'"
                    )
                }
                db.init_schema(conn)
                second = {
                    row["name"]: row["sql"]
                    for row in conn.execute(
                        "SELECT name, sql FROM sqlite_master WHERE name LIKE 'context_%' OR name LIKE 'agent_%' OR name = 'task_contracts'"
                    )
                }
                self.assertEqual(first, second)
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
            finally:
                conn.close()

    def test_variant_candidate_receipts_cannot_cross_compilations_or_mutate(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                project_id = conn.execute(
                    "SELECT id FROM projects WHERE name = 'demo'"
                ).fetchone()[0]
                profile_version_id = self._seed_profile(conn, project_id)
                contract_id = conn.execute(
                    """
                    INSERT INTO task_contracts(
                        project_id, agent_profile_version_id, contract_id,
                        schema_version, canonical_json, digest,
                        authorization_state, profile_id, profile_digest,
                        created_at, actor_type, actor_id
                    ) VALUES (?, ?, 'variant-contract', 'v1', '{}',
                              'contract-digest', 'operator_authorized',
                              'universal', 'profile-digest',
                              '2026-08-22T00:00:00+00:00', 'operator', 'owner')
                    """,
                    (project_id, profile_version_id),
                ).lastrowid
                authority_grant_id = self._seed_authority_grant(
                    conn, project_id, contract_id, suffix="variant-receipts"
                )

                compilation_ids = []
                for public_id in ("variant-compile-one", "variant-compile-two"):
                    compilation_ids.append(
                        conn.execute(
                            """
                            INSERT INTO context_compilations(
                                compilation_id, project_id, task_contract_id,
                                authority_grant_id, contract_digest, profile_digest,
                                envelope_digest, snapshot_digest, compiler_version,
                                compiler_mode, status, effective_budget_json, created_at
                            ) VALUES (?, ?, ?, ?, 'contract-digest', 'profile-digest',
                                      'envelope', 'snapshot', 'v1', 'balanced',
                                      'building', '{}', '2026-08-22T00:00:00+00:00')
                            """,
                            (public_id, project_id, contract_id, authority_grant_id),
                        ).lastrowid
                    )
                pack_variant_id = conn.execute(
                    """
                    INSERT INTO context_pack_variants(
                        compilation_id, project_id, variant_id, mode, pack_digest,
                        token_count, coverage_json, privacy_class, created_at
                    ) VALUES (?, ?, 'mode:minimal', 'minimal', 'pack', 1, '{}',
                              'internal', '2026-08-22T00:00:00+00:00')
                    """,
                    (compilation_ids[0], project_id),
                ).lastrowid
                receipt_sql = """
                    INSERT INTO context_variant_candidate_receipts(
                        pack_variant_id, compilation_id, candidate_id, disposition,
                        source_id, component_scores_json, token_cost,
                        explanation_json, privacy_class, created_at
                    ) VALUES (?, ?, ?, 'included_ranked', 'source', '{}', 1,
                              '{}', 'internal', '2026-08-22T00:00:00+00:00')
                """
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "their building compilation"
                ):
                    conn.execute(
                        receipt_sql,
                        (pack_variant_id, compilation_ids[1], "crossed"),
                    )
                receipt_id = conn.execute(
                    receipt_sql,
                    (pack_variant_id, compilation_ids[0], "valid"),
                ).lastrowid
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    conn.execute(
                        "UPDATE context_variant_candidate_receipts SET token_cost = 2 WHERE id = ?",
                        (receipt_id,),
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    conn.execute(
                        "DELETE FROM context_variant_candidate_receipts WHERE id = ?",
                        (receipt_id,),
                    )
                conn.execute(
                    """
                    UPDATE context_compilations
                    SET status = 'complete', receipt_digest = 'receipt',
                        finalized_at = '2026-08-22T00:00:01+00:00'
                    WHERE id = ?
                    """,
                    (compilation_ids[0],),
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "their building compilation"
                ):
                    conn.execute(
                        receipt_sql,
                        (pack_variant_id, compilation_ids[0], "late"),
                    )
            finally:
                conn.close()

    def test_malformed_schema_collision_is_not_certified_as_v9(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._v8_database(database)
            malformed = sqlite3.connect(database)
            try:
                malformed.execute(
                    """
                    CREATE TABLE task_contracts(
                        id INTEGER PRIMARY KEY, project_id INTEGER,
                        agent_profile_version_id INTEGER, contract_id TEXT,
                        schema_version TEXT, canonical_json TEXT, digest TEXT,
                        authorization_state TEXT, profile_id TEXT, profile_digest TEXT,
                        created_at TEXT, actor_type TEXT, actor_id TEXT
                    )
                    """
                )
                malformed.commit()
            finally:
                malformed.close()
            conn = db.connect(database)
            try:
                with self.assertRaisesRegex(ValueError, "invalid schema v9 collision"):
                    db.init_schema(conn)
            finally:
                conn.close()
            verify = sqlite3.connect(database)
            try:
                self.assertEqual(verify.execute("PRAGMA user_version").fetchone()[0], 8)
                self.assertEqual(
                    verify.execute("PRAGMA foreign_key_list(task_contracts)").fetchall(), []
                )
            finally:
                verify.close()

    def test_current_v9_rejects_same_named_unsafe_trigger(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_schema(conn)
                conn.executescript(
                    """
                    DROP TRIGGER task_contracts_no_delete;
                    CREATE TRIGGER task_contracts_no_delete
                    BEFORE DELETE ON task_contracts WHEN 0
                    BEGIN SELECT RAISE(ABORT, 'task_contracts is immutable'); END;
                    """
                )
                with self.assertRaisesRegex(ValueError, "unsafe trigger task_contracts_no_delete"):
                    db.init_schema(conn)
            finally:
                conn.close()

    def test_current_v9_rejects_unregistered_trigger_on_governed_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_schema(conn)
                conn.execute(
                    """
                    CREATE TRIGGER unregistered_side_effect
                    AFTER INSERT ON task_contracts
                    BEGIN SELECT 1; END
                    """
                )
                with self.assertRaisesRegex(ValueError, "unexpected trigger unregistered_side_effect"):
                    db.init_schema(conn)
            finally:
                conn.close()

    def test_interrupted_context_migration_rolls_back_all_v9_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._v8_database(database)
            conn = db.connect(database)
            try:
                before = list(
                    conn.execute("SELECT name, type, sql FROM sqlite_master ORDER BY name")
                )
                from rta_brain import context_schema

                real_migration = context_schema.migrate_context_schema_v9

                def fail_after_ddl(connection):
                    real_migration(connection)
                    raise RuntimeError("synthetic migration interruption")

                with (
                    mock.patch(
                        "rta_brain.context_schema.migrate_context_schema_v9",
                        side_effect=fail_after_ddl,
                    ),
                    self.assertRaisesRegex(
                        RuntimeError, "synthetic migration interruption"
                    ),
                ):
                    db.init_schema(conn)

                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 8)
                after = list(
                    conn.execute("SELECT name, type, sql FROM sqlite_master ORDER BY name")
                )
                self.assertEqual(after, before)
                self.assertEqual(
                    conn.execute("SELECT name FROM projects WHERE id = 1").fetchone()[0],
                    "demo",
                )
            finally:
                conn.close()

    def test_future_schema_fails_before_mutating_the_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            future = sqlite3.connect(database)
            try:
                future.executescript(
                    """
                    CREATE TABLE future_marker(value TEXT NOT NULL);
                    INSERT INTO future_marker VALUES ('preserve-me');
                    PRAGMA user_version = 99;
                    """
                )
                future.commit()
            finally:
                future.close()

            self.assertFalse(Path(f"{database}-wal").exists())
            with self.assertRaises(ValueError) as raised:
                db.connect(database)
            message = str(raised.exception)
            self.assertIn("newer schema version 99", message)
            self.assertIn("Upgrade the active Rta-Smriti launcher", message)
            self.assertIn("Do not downgrade or rewrite the brain database", message)
            self.assertFalse(Path(f"{database}-wal").exists())
            verify = sqlite3.connect(database)
            try:
                self.assertEqual(verify.execute("PRAGMA user_version").fetchone()[0], 99)
                self.assertEqual(verify.execute("SELECT value FROM future_marker").fetchone()[0], "preserve-me")
            finally:
                verify.close()

    def test_init_schema_rejects_future_raw_connection_inside_the_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = sqlite3.connect(database)
            conn.row_factory = sqlite3.Row
            try:
                conn.executescript(
                    "CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES ('keep'); PRAGMA user_version = 99;"
                )
                before = list(conn.execute("SELECT name, type, sql FROM sqlite_master ORDER BY name"))
                with self.assertRaisesRegex(ValueError, "newer schema version 99"):
                    db.init_schema(conn)
                after = list(conn.execute("SELECT name, type, sql FROM sqlite_master ORDER BY name"))
                self.assertEqual(after, before)
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 99)
            finally:
                conn.close()

    def test_init_schema_rejects_active_transaction_without_foreign_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(Path(tmp) / "brain.sqlite")
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("BEGIN")
                self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 0)
                with self.assertRaisesRegex(RuntimeError, "foreign key enforcement"):
                    db.init_schema(conn)
            finally:
                conn.rollback()
                conn.close()

    def test_locked_schema_reread_validates_a_concurrent_current_schema_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            self._v8_database(database)
            inner = sqlite3.connect(database)
            inner.row_factory = sqlite3.Row

            class RacingConnection:
                raced = False

                @property
                def in_transaction(self):
                    return inner.in_transaction

                def execute(self, sql, parameters=()):
                    if sql == "BEGIN IMMEDIATE" and not self.raced:
                        self.raced = True
                        other = sqlite3.connect(database)
                        try:
                            other.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION}")
                            other.commit()
                        finally:
                            other.close()
                    return inner.execute(sql, parameters)

                def __getattr__(self, name):
                    return getattr(inner, name)

            try:
                with self.assertRaisesRegex(ValueError, "invalid schema v9 collision"):
                    db.init_schema(RacingConnection())
                self.assertEqual(
                    inner.execute("PRAGMA user_version").fetchone()[0],
                    db.SCHEMA_VERSION,
                )
            finally:
                inner.close()

    def test_checkpoint_does_not_commit_an_existing_caller_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_schema(conn)
                conn.execute("CREATE TABLE caller_probe(value TEXT)")
                conn.commit()
                conn.execute("INSERT INTO caller_probe VALUES ('uncommitted')")
                db.save_checkpoint(
                    conn,
                    "new-project",
                    "Preserve caller transaction ownership",
                )
                conn.rollback()
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM caller_probe").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0], 0)
            finally:
                conn.close()

    def test_receipt_tables_reject_invalid_references_and_all_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                project_id = conn.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()[0]
                profile_version_id = self._seed_profile(conn, project_id)
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO context_compilations(
                            compilation_id, project_id, task_contract_id, authority_grant_id,
                            contract_digest,
                            profile_digest, envelope_digest, snapshot_digest, compiler_version,
                            compiler_mode, status, effective_budget_json, created_at
                        ) VALUES ('compile-invalid', 999, 999, 999, 'c', 'p', 'e', 's', 'v1',
                                  'balanced', 'building', '{}', '2026-08-22T00:00:00+00:00')
                        """
                    )

                contract_id = conn.execute(
                    """
                    INSERT INTO task_contracts(
                        project_id, agent_profile_version_id, contract_id, schema_version, canonical_json, digest,
                        authorization_state, profile_id, profile_digest, created_at,
                        actor_type, actor_id
                    ) VALUES (?, ?, 'contract-1', 'v1', '{}', 'contract-digest',
                              'operator_authorized', 'universal', 'profile-digest',
                              '2026-08-22T00:00:00+00:00', 'operator', 'owner')
                    """,
                    (project_id, profile_version_id),
                ).lastrowid
                authority_grant_id = self._seed_authority_grant(
                    conn, project_id, contract_id, suffix="receipt"
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO task_contracts(
                            project_id, agent_profile_version_id, contract_id, schema_version,
                            canonical_json, digest, authorization_state, profile_id,
                            profile_digest, created_at, actor_type, actor_id
                        ) VALUES (?, ?, 'forged', 'v1', '{}', 'forged-digest',
                                  'operator_authorized', 'universal', 'profile-digest',
                                  '2026-08-22T00:00:00+00:00', 'agent_proposal', 'agent')
                        """,
                        (project_id, profile_version_id),
                    )
                proposal_id = conn.execute(
                    """
                    INSERT INTO task_contracts(
                        project_id, agent_profile_version_id, contract_id, schema_version,
                        canonical_json, digest, authorization_state, profile_id,
                        profile_digest, created_at, actor_type, actor_id
                    ) VALUES (?, ?, 'proposal', 'v1', '{}', 'proposal-digest', 'proposal',
                              'universal', 'profile-digest', '2026-08-22T00:00:00+00:00',
                              'agent_proposal', 'agent')
                    """,
                    (project_id, profile_version_id),
                ).lastrowid
                with self.assertRaisesRegex(sqlite3.IntegrityError, "operator authority"):
                    conn.execute(
                        """
                        INSERT INTO context_compilations(
                            compilation_id, project_id, task_contract_id, authority_grant_id,
                            contract_digest,
                            profile_digest, envelope_digest, snapshot_digest, compiler_version,
                            compiler_mode, status, effective_budget_json, created_at
                        ) VALUES ('proposal-compile', ?, ?, NULL, 'proposal-digest', 'profile-digest',
                                  'e', 's', 'v1', 'balanced', 'building', '{}',
                                  '2026-08-22T00:00:00+00:00')
                        """,
                        (project_id, proposal_id),
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "building state"):
                    conn.execute(
                        """
                        INSERT INTO context_compilations(
                            compilation_id, project_id, task_contract_id, authority_grant_id,
                            contract_digest,
                            profile_digest, envelope_digest, snapshot_digest, compiler_version,
                            compiler_mode, status, effective_budget_json, receipt_digest,
                            created_at, finalized_at
                        ) VALUES ('direct-terminal', ?, ?, ?, 'contract-digest', 'profile-digest',
                                  'e0', 's0', 'v1', 'balanced', 'complete', '{}', 'r0',
                                  '2026-08-22T00:00:00+00:00',
                                  '2026-08-22T00:00:01+00:00')
                        """,
                        (project_id, contract_id, authority_grant_id),
                    )
                conn.execute(
                    """
                    INSERT INTO context_compilations(
                        compilation_id, project_id, task_contract_id, authority_grant_id,
                        contract_digest,
                        profile_digest, envelope_digest, snapshot_digest, compiler_version,
                        compiler_mode, status, effective_budget_json, created_at
                    ) VALUES ('compile-1', ?, ?, ?, 'contract-digest', 'profile-digest',
                              'envelope-digest', 'snapshot-digest', 'v1', 'balanced',
                              'building', '{}', '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id, contract_id, authority_grant_id),
                )
                conn.execute(
                    """UPDATE context_compilations
                       SET status = 'complete', receipt_digest = 'receipt-digest',
                           finalized_at = '2026-08-22T00:00:01+00:00'
                       WHERE compilation_id = 'compile-1'"""
                )
                conn.commit()

                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    conn.execute(
                        "UPDATE context_compilations SET envelope_digest = 'changed' WHERE compilation_id = 'compile-1'"
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    conn.execute(
                        "DELETE FROM task_contracts WHERE id = ?", (contract_id,)
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO task_contracts(
                            project_id, agent_profile_version_id, contract_id, schema_version,
                            canonical_json, digest, authorization_state, profile_id,
                            profile_digest, created_at, actor_type, actor_id
                        ) VALUES (?, ?, 'contract-1', 'v1', '{}', 'replacement-digest',
                                  'proposal', 'universal', 'profile-digest',
                                  '2026-08-22T00:00:02+00:00', 'agent_proposal', 'agent')
                        """,
                        (project_id, profile_version_id),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO context_compilations(
                            compilation_id, project_id, task_contract_id, authority_grant_id,
                            contract_digest,
                            profile_digest, envelope_digest, snapshot_digest, compiler_version,
                            compiler_mode, status, effective_budget_json, created_at
                        ) VALUES ('compile-wrong-digest', ?, ?, ?, 'wrong', 'profile-digest',
                                  'e2', 's2', 'v1', 'balanced', 'building', '{}',
                                  '2026-08-22T00:00:00+00:00')
                        """,
                        (project_id, contract_id, authority_grant_id),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO context_compilations(
                            compilation_id, project_id, task_contract_id, authority_grant_id,
                            contract_digest,
                            profile_digest, envelope_digest, snapshot_digest, compiler_version,
                            compiler_mode, status, effective_budget_json, created_at
                        ) VALUES ('compile-bad-state', ?, ?, ?, 'contract-digest', 'profile-digest',
                                  'e3', 's3', 'v1', 'balanced', 'invented', '{}',
                                  '2026-08-22T00:00:00+00:00')
                        """,
                        (project_id, contract_id, authority_grant_id),
                    )
            finally:
                conn.close()

    def test_outcomes_and_attribution_cannot_cross_project_or_receipt_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "one", str(Path(tmp) / "one"))
                db.init_project(conn, "two", str(Path(tmp) / "two"))
                project_one = conn.execute("SELECT id FROM projects WHERE name = 'one'").fetchone()[0]
                project_two = conn.execute("SELECT id FROM projects WHERE name = 'two'").fetchone()[0]
                version_id = self._seed_profile(conn, project_one)
                contract_id = conn.execute(
                    """
                    INSERT INTO task_contracts(
                        project_id, agent_profile_version_id, contract_id, schema_version,
                        canonical_json, digest, authorization_state, profile_id,
                        profile_digest, created_at, actor_type, actor_id
                    ) VALUES (?, ?, 'c', 'v1', '{}', 'cd', 'operator_authorized',
                              'universal', 'profile-digest', '2026-08-22T00:00:00+00:00',
                              'operator', 'owner')
                    """,
                    (project_one, version_id),
                ).lastrowid
                authority_grant_id = self._seed_authority_grant(
                    conn, project_one, contract_id, suffix="outcome"
                )
                compilation_id = conn.execute(
                    """
                    INSERT INTO context_compilations(
                        compilation_id, project_id, task_contract_id, authority_grant_id,
                        contract_digest,
                        profile_digest, envelope_digest, snapshot_digest, compiler_version,
                        compiler_mode, status, effective_budget_json, created_at
                    ) VALUES ('compile', ?, ?, ?, 'cd', 'profile-digest', 'ed', 'sd', 'v1',
                              'balanced', 'building', '{}', '2026-08-22T00:00:00+00:00')
                    """,
                    (project_one, contract_id, authority_grant_id),
                ).lastrowid
                receipt_id = conn.execute(
                    """
                    INSERT INTO context_candidate_receipts(
                        compilation_id, candidate_id, disposition, source_id,
                        component_scores_json, token_cost, explanation_json,
                        privacy_class, created_at
                    ) VALUES (?, 'candidate-1', 'included_ranked', 'source-1', '{}', 5,
                              '{}', 'internal', '2026-08-22T00:00:00+00:00')
                    """,
                    (compilation_id,),
                ).lastrowid
                with self.assertRaisesRegex(sqlite3.IntegrityError, "terminal compilation"):
                    conn.execute(
                        """
                        INSERT INTO context_outcomes(
                            project_id, compilation_id, outcome_id, task_status,
                            attribution_level, evidence_json, acceptance_results_json,
                            created_at, actor_type, actor_id
                        ) VALUES (?, ?, 'too-early', 'success', 'observed', '{}', '{}',
                                  '2026-08-22T00:00:00+00:00', 'operator', 'owner')
                        """,
                        (project_one, compilation_id),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO context_outcomes(
                            project_id, compilation_id, outcome_id, task_status,
                            attribution_level, evidence_json, acceptance_results_json,
                            created_at, actor_type, actor_id
                        ) VALUES (?, ?, 'empty-confirmation', 'success', 'operator_confirmed',
                                  '{ }', '{}', '2026-08-22T00:00:02+00:00',
                                  'operator', 'owner')
                        """,
                        (project_one, compilation_id),
                    )
                conn.execute(
                    """UPDATE context_compilations
                       SET status = 'complete', receipt_digest = 'rd',
                           finalized_at = '2026-08-22T00:00:01+00:00'
                       WHERE id = ?""",
                    (compilation_id,),
                )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "active operator authority"):
                    conn.execute(
                        """
                        INSERT INTO context_outcomes(
                            project_id, compilation_id, authority_grant_id, outcome_id,
                            task_status, attribution_level, evidence_json,
                            acceptance_results_json, created_at, actor_type, actor_id
                        ) VALUES (?, ?, ?, 'forged-confirmation', 'success',
                                  'operator_confirmed', '{"test":"passed"}', '{}',
                                  '2026-08-22T00:00:02+00:00', 'operator', 'owner')
                        """,
                        (project_one, compilation_id, authority_grant_id),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO context_outcomes(
                            project_id, compilation_id, outcome_id, task_status,
                            attribution_level, evidence_json, acceptance_results_json,
                            created_at, actor_type, actor_id
                        ) VALUES (?, ?, 'wrong-project', 'success', 'observed', '{}', '{}',
                                  '2026-08-22T00:00:00+00:00', 'operator', 'owner')
                        """,
                        (project_two, compilation_id),
                    )
                outcome_id = conn.execute(
                    """
                    INSERT INTO context_outcomes(
                        project_id, compilation_id, outcome_id, task_status,
                        attribution_level, evidence_json, acceptance_results_json,
                        created_at, actor_type, actor_id
                    ) VALUES (?, ?, 'outcome-1', 'success', 'observed', '{}', '{}',
                              '2026-08-22T00:00:00+00:00', 'operator', 'owner')
                    """,
                    (project_one, compilation_id),
                ).lastrowid
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO context_outcomes(
                            project_id, compilation_id, outcome_id, task_status,
                            attribution_level, evidence_json, acceptance_results_json,
                            created_at, actor_type, actor_id
                        ) VALUES (?, ?, 'false-confirmation', 'success', 'operator_confirmed',
                                  '{}', '{}', '2026-08-22T00:00:02+00:00', 'agent', 'agent')
                        """,
                        (project_one, compilation_id),
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot exceed"):
                    conn.execute(
                        """
                        INSERT INTO context_attribution_edges(
                            outcome_id, compilation_id, candidate_receipt_id, candidate_id,
                            assessment, attribution_level, evidence_json, created_at
                        ) VALUES (?, ?, ?, 'candidate-1', 'helpful', 'correlated', '{}',
                                  '2026-08-22T00:00:02+00:00')
                        """,
                        (outcome_id, compilation_id, receipt_id),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO context_attribution_edges(
                            outcome_id, compilation_id, candidate_receipt_id, candidate_id,
                            assessment, attribution_level, evidence_json, created_at
                        ) VALUES (?, ?, ?, 'not-candidate-1', 'helpful', 'observed', '{}',
                                  '2026-08-22T00:00:00+00:00')
                        """,
                        (outcome_id, compilation_id, receipt_id),
                    )
            finally:
                conn.close()

    def test_profile_identity_is_immutable_and_pack_retention_requires_a_grant(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                project_id = conn.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()[0]
                version_id = self._seed_profile(conn, project_id)
                profile_id = conn.execute("SELECT agent_profile_id FROM agent_profile_versions WHERE id = ?", (version_id,)).fetchone()[0]
                with self.assertRaisesRegex(sqlite3.IntegrityError, "identity is immutable"):
                    conn.execute("UPDATE agent_profiles SET profile_id = 'changed' WHERE id = ?", (profile_id,))
                contract_id = conn.execute(
                    """
                    INSERT INTO task_contracts(
                        project_id, agent_profile_version_id, contract_id, schema_version,
                        canonical_json, digest, authorization_state, profile_id,
                        profile_digest, created_at, actor_type, actor_id
                    ) VALUES (?, ?, 'c', 'v1', '{}', 'cd', 'operator_authorized',
                              'universal', 'profile-digest', '2026-08-22T00:00:00+00:00',
                              'operator', 'owner')
                    """,
                    (project_id, version_id),
                ).lastrowid
                authority_grant_id = self._seed_authority_grant(
                    conn, project_id, contract_id, suffix="retention"
                )
                conn.execute(
                    "UPDATE agent_profiles SET retired_at = '2026-08-23T00:00:00+00:00' WHERE id = ?",
                    (profile_id,),
                )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "retirement is immutable"):
                    conn.execute("UPDATE agent_profiles SET retired_at = NULL WHERE id = ?", (profile_id,))
                with self.assertRaisesRegex(sqlite3.IntegrityError, "retired agent profile"):
                    conn.execute(
                        """
                        INSERT INTO task_contracts(
                            project_id, agent_profile_version_id, contract_id, schema_version,
                            canonical_json, digest, authorization_state, profile_id,
                            profile_digest, created_at, actor_type, actor_id
                        ) VALUES (?, ?, 'blocked', 'v1', '{}', 'blocked-digest',
                                  'operator_authorized', 'universal', 'profile-digest',
                                  '2026-08-24T00:00:00+00:00', 'operator', 'owner')
                        """,
                        (project_id, version_id),
                    )
                compilation_id = conn.execute(
                    """
                    INSERT INTO context_compilations(
                        compilation_id, project_id, task_contract_id, authority_grant_id,
                        contract_digest,
                        profile_digest, envelope_digest, snapshot_digest, compiler_version,
                        compiler_mode, status, effective_budget_json, created_at
                    ) VALUES ('compile', ?, ?, ?, 'cd', 'profile-digest', 'ed', 'sd', 'v1',
                              'balanced', 'building', '{}', '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id, contract_id, authority_grant_id),
                ).lastrowid
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO context_pack_variants(
                            compilation_id, project_id, variant_id, mode, pack_digest,
                            token_count, coverage_json, bounded_preview, preview_redacted,
                            privacy_class, created_at
                        ) VALUES (?, ?, 'v', 'balanced', 'pd', 10, '{}', 'private body', 0,
                                  'sensitive', '2026-08-22T00:00:00+00:00')
                        """,
                        (compilation_id, project_id),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        """
                        INSERT INTO context_pack_variants(
                            compilation_id, project_id, variant_id, mode, pack_digest,
                            token_count, coverage_json, bounded_preview, preview_redacted,
                            privacy_class, created_at
                        ) VALUES (?, ?, 'too-large', 'balanced', 'pd2', 10, '{}', ?, 1,
                                  'sensitive', '2026-08-22T00:00:00+00:00')
                        """,
                        (compilation_id, project_id, "x" * 8193),
                    )
                now_ms = int(time.time() * 1000)
                grant_id = conn.execute(
                    """
                    INSERT INTO context_retention_grants(
                        project_id, grant_id, policy_digest, max_privacy_class,
                        max_payload_bytes, authorized_by_type, authorized_by_id,
                        valid_from_epoch_ms, expires_at_epoch_ms, created_at
                    ) VALUES (?, 'grant-1', 'policy-digest', 'sensitive', 1024,
                              'operator', 'owner', ?, ?, '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id, now_ms - 60_000, now_ms + 3_600_000),
                ).lastrowid
                variant_id = conn.execute(
                    """
                    INSERT INTO context_pack_variants(
                        compilation_id, project_id, variant_id, mode, pack_digest,
                        token_count, coverage_json, bounded_preview, preview_redacted,
                        privacy_class, retention_grant_id, retention_policy_id,
                        retention_policy_digest, created_at
                    ) VALUES (?, ?, 'retained', 'balanced', 'pack-digest', 10, '{}',
                              '[redacted]', 1, 'sensitive', ?, 'grant-1', 'policy-digest',
                              '2026-08-22T00:00:00+00:00')
                    """,
                    (compilation_id, project_id, grant_id),
                ).lastrowid
                conn.execute(
                    """
                    INSERT INTO context_retained_payloads(
                        pack_variant_id, project_id, retention_grant_id, payload_text,
                        payload_digest, created_at_epoch_ms, expires_at_epoch_ms
                    ) VALUES (?, ?, ?, 'authorized private body', 'payload-digest',
                              ?, ?)
                    """,
                    (variant_id, project_id, grant_id, now_ms, now_ms + 1_800_000),
                )
                conn.execute(
                    "DELETE FROM context_retained_payloads WHERE pack_variant_id = ?",
                    (variant_id,),
                )
                while int(time.time() * 1000) % 1000 < 650:
                    time.sleep(0.01)
                subsecond_now_ms = int(time.time() * 1000)
                expired_grant_id = conn.execute(
                    """
                    INSERT INTO context_retention_grants(
                        project_id, grant_id, policy_digest, max_privacy_class,
                        max_payload_bytes, authorized_by_type, authorized_by_id,
                        valid_from_epoch_ms, expires_at_epoch_ms, created_at
                    ) VALUES (?, 'expired', 'expired-policy', 'sensitive', 1024,
                              'operator', 'owner', ?, ?, '2000-01-01T00:00:00+00:00')
                    """,
                    (project_id, subsecond_now_ms - 1_000, subsecond_now_ms - 100),
                ).lastrowid
                expired_variant_id = conn.execute(
                    """
                    INSERT INTO context_pack_variants(
                        compilation_id, project_id, variant_id, mode, pack_digest,
                        token_count, coverage_json, preview_redacted, privacy_class,
                        retention_grant_id, retention_policy_id,
                        retention_policy_digest, created_at
                    ) VALUES (?, ?, 'expired-retention', 'balanced', 'expired-pack', 10,
                              '{}', 1, 'sensitive', ?, 'expired', 'expired-policy',
                              '2026-08-22T00:00:00+00:00')
                    """,
                    (compilation_id, project_id, expired_grant_id),
                ).lastrowid
                with self.assertRaisesRegex(sqlite3.IntegrityError, "authorization grant"):
                    conn.execute(
                        """
                        INSERT INTO context_retained_payloads(
                            pack_variant_id, project_id, retention_grant_id, payload_text,
                            payload_digest, created_at_epoch_ms, expires_at_epoch_ms
                        ) VALUES (?, ?, ?, 'historical replay', 'expired-digest', ?, ?)
                        """,
                        (
                            expired_variant_id,
                            project_id,
                            expired_grant_id,
                            subsecond_now_ms - 900,
                            subsecond_now_ms - 100,
                        ),
                    )
                conn.execute(
                    """UPDATE context_compilations
                       SET status = 'complete', receipt_digest = 'rd',
                           finalized_at = '2026-08-22T00:00:01+00:00'
                       WHERE id = ?""",
                    (compilation_id,),
                )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "building compilation"):
                    conn.execute(
                        """
                        INSERT INTO context_candidate_receipts(
                            compilation_id, candidate_id, disposition, source_id,
                            component_scores_json, token_cost, explanation_json,
                            privacy_class, created_at
                        ) VALUES (?, 'late', 'included_ranked', 'source', '{}', 1, '{}',
                                  'internal', '2026-08-22T00:00:02+00:00')
                        """,
                        (compilation_id,),
                    )
            finally:
                conn.close()

    def test_benchmark_metric_set_is_finalized_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                project_id = conn.execute(
                    "SELECT id FROM projects WHERE name = 'demo'"
                ).fetchone()[0]
                with self.assertRaisesRegex(sqlite3.IntegrityError, "building state"):
                    conn.execute(
                        """
                        INSERT INTO context_benchmark_runs(
                            project_id, run_id, corpus_id, compiler_version,
                            profile_digest, contract_digest, environment_json, status,
                            receipt_digest, created_at, finalized_at
                        ) VALUES (?, 'direct', 'corpus', 'v1', 'p', 'c', '{}', 'complete',
                                  'receipt', '2026-08-22T00:00:00+00:00',
                                  '2026-08-22T00:00:01+00:00')
                        """,
                        (project_id,),
                    )
                run_id = conn.execute(
                    """
                    INSERT INTO context_benchmark_runs(
                        project_id, run_id, corpus_id, compiler_version,
                        profile_digest, contract_digest, environment_json, status, created_at
                    ) VALUES (?, 'run-1', 'corpus', 'v1', 'p', 'c', '{}', 'building',
                              '2026-08-22T00:00:00+00:00')
                    """,
                    (project_id,),
                ).lastrowid
                conn.execute(
                    """
                    INSERT INTO context_benchmark_metrics(
                        run_id, metric_name, metric_value, sample_count, details_json, created_at
                    ) VALUES (?, 'recall', 0.9, 10, '{}', '2026-08-22T00:00:00+00:00')
                    """,
                    (run_id,),
                )
                conn.execute(
                    """UPDATE context_benchmark_runs
                       SET status = 'complete', receipt_digest = 'run-receipt',
                           finalized_at = '2026-08-22T00:00:01+00:00'
                       WHERE id = ?""",
                    (run_id,),
                )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "building run"):
                    conn.execute(
                        """
                        INSERT INTO context_benchmark_metrics(
                            run_id, metric_name, metric_value, sample_count,
                            details_json, created_at
                        ) VALUES (?, 'late', 1.0, 1, '{}', '2026-08-22T00:00:02+00:00')
                        """,
                        (run_id,),
                    )
            finally:
                conn.close()

    def test_v8_compatible_export_reports_v9_omissions_without_flattening_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                project_id = conn.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()[0]
                profile_version_id = self._seed_profile(conn, project_id)
                conn.execute(
                    """
                    INSERT INTO task_contracts(
                        project_id, agent_profile_version_id, contract_id, schema_version, canonical_json, digest,
                        authorization_state, profile_id, profile_digest, created_at,
                        actor_type, actor_id
                    ) VALUES (?, ?, 'contract-1', 'v1', '{"private":"not-exported"}', 'digest',
                              'operator_authorized', 'universal', 'profile-digest',
                              '2026-08-22T00:00:00+00:00', 'operator', 'owner')
                    """,
                    (project_id, profile_version_id),
                )
                conn.commit()

                try:
                    from rta_brain.context_schema import describe_v8_compatibility
                except (ImportError, ModuleNotFoundError):
                    self.fail("v8 compatibility manifest is not implemented")
                exported = describe_v8_compatibility(conn, project="demo")

                self.assertEqual(exported["operation"], "v8_compatibility_omission_manifest")
                self.assertEqual(exported["schema_version"], 8)
                self.assertEqual(exported["project"]["name"], "demo")
                self.assertEqual(exported["omitted_v9"]["task_contracts"], 1)
                self.assertNotIn("task_contracts", exported)
                self.assertNotIn("private", json.dumps(exported, sort_keys=True))
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
