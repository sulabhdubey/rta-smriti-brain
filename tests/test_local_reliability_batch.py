import io
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from rta_brain import cli, db, cognition


class LocalReliabilityTests(unittest.TestCase):
    def test_call_resolution_starts_with_call_entities(self):
        (self.root / "app.py").write_text("def run():\n    return work()\n", encoding="utf-8")
        statements = []
        self.conn.set_trace_callback(statements.append)
        try:
            db.ingest_repo(self.conn, self.root, project="demo")
        finally:
            self.conn.set_trace_callback(None)
        query = next(sql for sql in statements if "SELECT e.from_entity_id AS file_id" in sql)
        plan = [row[3] for row in self.conn.execute("EXPLAIN QUERY PLAN " + query)]
        self.assertIn("SEARCH c", plan[0], plan)
        self.assertTrue(any("SEARCH e" in step and "to_entity_id=?" in step for step in plan), plan)

    def test_edge_insertion_is_idempotent_with_nullable_ownership(self):
        project_id = self.conn.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()[0]
        origin = db.ensure_entity(self.conn, project_id, "file", "app.py")
        target = db.ensure_entity(self.conn, project_id, "symbol", "run")
        self.assertTrue(db.add_edge(self.conn, project_id, origin, "calls", target))
        self.assertFalse(db.add_edge(self.conn, project_id, origin, "calls", target))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0], 1)

    def test_edge_deduplication_preserves_distinct_sources(self):
        project_id = self.conn.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()[0]
        origin = db.ensure_entity(self.conn, project_id, "file", "app.py")
        target = db.ensure_entity(self.conn, project_id, "symbol", "run")
        first = db.upsert_source(self.conn, project_id, "file", "first.py", "first", "a", {})
        second = db.upsert_source(self.conn, project_id, "file", "second.py", "second", "b", {})
        self.assertTrue(db.add_edge(self.conn, project_id, origin, "calls", target, source_id=first))
        self.assertFalse(db.add_edge(self.conn, project_id, origin, "calls", target, source_id=first))
        self.assertTrue(db.add_edge(self.conn, project_id, origin, "calls", target, source_id=second))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0], 2)

    def test_curated_continuation_is_searchable_without_exposing_checkpoint(self):
        import json
        from rta_brain.mcp_server import RtaBrainMcpServer
        db.save_checkpoint(self.conn, "demo", "private_checkpoint_sentinel")
        db.remember(self.conn,
                    "Preparing for reliability-first pilot onboarding; preparation is not readiness. Do not publish.",
                    project="demo", pramana="sabda", metadata={"privacy_class": "internal"})
        server = RtaBrainMcpServer(self.database, "demo", expected_root=self.root,
                                  maximum_privacy_ceiling="internal", tool_profile="core")
        result = server.call_tool("brain_context_pack", {
            "task": "reliability-first pilot onboarding", "max_tokens": 1200,
        })
        rendered = json.dumps(result)
        self.assertIn("preparation is not readiness", rendered)
        self.assertNotIn("private_checkpoint_sentinel", rendered)

    def test_discovery_excludes_guardian_but_keeps_coding_sessions(self):
        import json
        from rta_brain.continuity_daemon import discover_codex_sessions
        sessions = Path(self.tmp.name) / "sessions"
        sessions.mkdir()
        for name, source in (("guardian", {"subagent": {"other": "guardian"}}),
                             ("coding", {"subagent": {"other": "worker"}}),
                             ("desktop", "cli")):
            (sessions / (name + ".jsonl")).write_text(json.dumps({
                "type": "session_meta", "payload": {
                    "id": name, "cwd": str(self.root), "source": source,
                },
            }) + "\n", encoding="utf-8")
        self.assertEqual([s["session_id"] for s in discover_codex_sessions(sessions, self.root)],
                         ["coding", "desktop"])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        self.database = Path(self.tmp.name) / "brain.sqlite"
        self.conn = db.connect(self.database)
        db.init_project(self.conn, "demo", str(self.root))
        self.conn.commit()
        self.addCleanup(self.conn.close)

    def run_cli(self, arguments):
        self.stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(self.stderr):
            return cli.main([*arguments, "--db", str(self.database), "--project", "demo", "--json"])

    def test_deep_check_uses_ingestion_limit_for_control_documents(self):
        path = self.root / "PROJECT_LIVE_CONTEXT.md"
        path.write_text("current source evidence " * 26000, encoding="utf-8")
        db.ingest_repo(self.conn, self.root, project="demo")
        report = db.stale_check(self.conn, project="demo", deep=True, refresh_hashes=True)
        self.assertEqual(report["changed"], 0)
        self.assertEqual(report["fresh"], 1)

    def test_deep_check_detects_same_stat_control_document_change(self):
        import os
        path = self.root / "PROJECT_LIVE_CONTEXT.md"
        path.write_text("current source evidence " * 26000, encoding="utf-8")
        db.ingest_repo(self.conn, self.root, project="demo")
        stat = path.stat()
        path.write_text("changed source evidence " * 26000, encoding="utf-8")
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        report = db.stale_check(self.conn, project="demo", deep=True, refresh_hashes=True)
        self.assertEqual(report["changed"], 1)

    def test_write_cli_waits_before_opening_database(self):
        @contextmanager
        def denied(*args, **kwargs):
            raise TimeoutError("test writer is busy")
            yield

        with patch.object(cli, "database_writer_lease", denied, create=True), patch.object(cli, "connect") as connect:
            self.assertEqual(self.run_cli(["stale-check", "--rehash"]), 1)
            connect.assert_not_called()

    def test_search_never_enrolls_writer(self):
        with patch.object(cli, "database_writer_lease", side_effect=AssertionError("read joined writer queue"), create=True):
            self.assertEqual(self.run_cli(["search", "architecture"]), 0)

    def test_first_ingest_bootstraps_a_new_database(self):
        self.database = Path(self.tmp.name) / "new.sqlite"
        (self.root / "README.md").write_text("current architecture", encoding="utf-8")
        self.assertEqual(self.run_cli(["ingest-repo", str(self.root)]), 0, self.stderr.getvalue())

    def test_chunk_replacement_indexes_foreign_key_lookups_on_existing_brain(self):
        path = self.root / "README.md"
        path.write_text("initial architecture", encoding="utf-8")
        db.ingest_repo(self.conn, self.root, project="demo")
        self.conn.execute("DROP INDEX IF EXISTS idx_evidence_chunk_id")
        self.conn.execute("DROP INDEX IF EXISTS idx_chunk_embeddings_chunk_id")
        self.conn.commit()
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        path.write_text("updated architecture", encoding="utf-8")
        db.ingest_repo(self.conn, self.root, project="demo")
        plan = [r[3] for r in self.conn.execute("EXPLAIN QUERY PLAN DELETE FROM chunks WHERE source_id = 1")]
        self.assertFalse(any("SCAN chunk_embeddings" in p or "SCAN evidence" in p for p in plan), plan)
        self.assertEqual(self.conn.execute("PRAGMA user_version").fetchone()[0], version)
        self.assertEqual(list(self.conn.execute("PRAGMA foreign_key_check")), [])

    def test_existing_project_ingest_prepares_outside_writer_turn(self):
        path = self.root / "README.md"
        path.write_text("architecture evidence", encoding="utf-8")
        active = False
        turns = 0

        @contextmanager
        def lease(*args, **kwargs):
            nonlocal active, turns
            self.assertFalse(active, "nested writer lease")
            active = True
            turns += 1
            try:
                yield {}
            finally:
                active = False

        original_build = db._repo_stat_manifest

        def build(*args, **kwargs):
            self.assertFalse(active, "repository inventory held the writer turn")
            return original_build(*args, **kwargs)

        with patch.object(cli, "database_writer_lease", lease, create=True), patch.object(db, "_repo_stat_manifest", build):
            self.assertEqual(self.run_cli(["ingest-repo", str(self.root)]), 0, self.stderr.getvalue())
        self.assertGreaterEqual(turns, 2)
        self.assertFalse(active)

    def test_change_impact_uses_bounded_edge_lookups(self):
        path = self.root / "app.py"
        path.write_text("def architecture():\n    return 42\n", encoding="utf-8")
        db.ingest_repo(self.conn, self.root, project="demo")
        project_id = self.conn.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()[0]
        statements = []
        self.conn.set_trace_callback(statements.append)
        try:
            with patch.object(cognition, "_changed_paths", return_value=("changed", ["app.py"], None)):
                cognition._change_impact(self.conn, project_id, self.root)
        finally:
            self.conn.set_trace_callback(None)
        query = next(sql for sql in statements if "SELECT DISTINCT test_file.name" in sql)
        plan = [row[3] for row in self.conn.execute("EXPLAIN QUERY PLAN " + query)]
        self.assertTrue(any("SEARCH containment" in item and "from_entity_id=?" in item for item in plan), plan)
        self.assertTrue(any("SEARCH test_edge" in item and "to_entity_id=?" in item for item in plan), plan)

    def test_writer_turn_released_after_cli_error(self):
        states = []

        @contextmanager
        def lease(*args, **kwargs):
            states.append("enter")
            try:
                yield {}
            finally:
                states.append("exit")

        with patch.object(cli, "database_writer_lease", lease, create=True):
            self.assertEqual(self.run_cli(["ingest-repo", str(self.root / "missing")]), 1)
        self.assertEqual(states, ["enter", "exit"])
