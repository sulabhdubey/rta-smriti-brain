import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rta_brain import db, watch_daemon


class WatcherEfficiencyTests(unittest.TestCase):
    def test_directory_event_checks_descendants_without_reparsing_unrelated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            (root / "src").mkdir(parents=True)
            path = root / "src/main.py"
            path.write_text("VALUE = 1\n")
            (root / "unrelated.py").write_text("UNCHANGED = 1\n")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                stat = path.stat()
                path.write_text("VALUE = 2\n")
                os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
                result = db.ingest_repo(conn, root, project="demo", changed_paths=[root / "src"])
                self.assertEqual(result["updated_files"], 1)
                self.assertEqual(result["unchanged_files"], 1)
            finally:
                conn.close()

    def test_events_follow_ingestion_exclusions_without_stat_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            excluded = watch_daemon._repository_event_filter(root, lambda _: False)
            with patch.object(Path, "stat", side_effect=AssertionError("event stat")):
                for relative in (".git/index", "node_modules/pkg/main.js", "logs/run.json",
                                 "output/report.md", "build/bundle.js", "src/image.png",
                                 "src/tmp-result.json", ".worktrees/copy/app.py"):
                    self.assertTrue(excluded(str(root / relative)), relative)
                for relative in ("src/app.py", "README.md", "src/new.py", "src/removed.py"):
                    self.assertFalse(excluded(str(root / relative)), relative)
                self.assertTrue(excluded(str(root.parent / "foreign.py")))

    def test_directory_moves_and_deletes_refresh_but_modified_directory_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            excluded = watch_daemon._repository_event_filter(root, lambda _: False)
            for kind in ("moved", "deleted", "created"):
                event = SimpleNamespace(is_directory=True, event_type=kind,
                                        src_path=str(root / "src"), dest_path=None)
                self.assertTrue(watch_daemon._watchdog_event_requires_refresh(event, excluded))
            event.event_type = "modified"
            self.assertFalse(watch_daemon._watchdog_event_requires_refresh(event, excluded))
            event.event_type = "moved"
            event.src_path = str(root / "src")
            event.dest_path = str(root / "build")
            self.assertTrue(watch_daemon._watchdog_event_requires_refresh(event, excluded))
            event.src_path = str(root / "build")
            event.dest_path = str(root / "src")
            self.assertTrue(watch_daemon._watchdog_event_requires_refresh(event, excluded))

    def test_idle_polling_backoff_remains_bounded_by_deep_verification(self):
        self.assertEqual(watch_daemon._idle_polling_wait_seconds(2, 100, 0), 2)
        self.assertEqual(watch_daemon._idle_polling_wait_seconds(2, 100, 6), 60)
        self.assertEqual(watch_daemon._idle_polling_wait_seconds(2, 15000, 3), 60)
        self.assertEqual(watch_daemon._idle_polling_wait_seconds(90, 100, 8), 90)

    def test_cpu_budget_delays_work_but_io_time_already_counts_as_cooling(self):
        from rta_brain.worker_budget import WorkerBudget
        cpu, wall = [0.0], [0.0]
        waits = []

        def wait(seconds):
            waits.append(seconds)
            wall[0] += seconds
            return False

        budget = WorkerBudget(cpu_fraction=0.2, cpu_clock=lambda: cpu[0],
                              wall_clock=lambda: wall[0], wait=wait)
        cpu[0] = wall[0] = 0.05
        budget.checkpoint()
        self.assertAlmostEqual(sum(waits), 0.2)
        cpu[0], wall[0] = 0.10, 1.0
        budget.checkpoint()
        self.assertAlmostEqual(sum(waits), 0.2)

    def test_cancelled_ingest_rolls_back_and_releases_writer_turn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            source = root / "main.py"
            source.write_text("VALUE = 1\n")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                before = [tuple(r) for r in conn.execute("SELECT path, hash FROM sources")]
                source.write_text("VALUE = 2\n")
                calls = 0

                def checkpoint():
                    nonlocal calls
                    calls += 1
                    if calls == 3:
                        raise InterruptedError("cancelled")

                with self.assertRaises(InterruptedError):
                    db.ingest_repo(conn, root, project="demo", _work_checkpoint=checkpoint)
                self.assertFalse(conn.in_transaction)
                self.assertEqual([tuple(r) for r in conn.execute("SELECT path, hash FROM sources")], before)
                self.assertGreaterEqual(calls, 3)
            finally:
                conn.close()

    def test_cpu_budget_interrupts_long_sql_without_partial_writes(self):
        from rta_brain.worker_budget import WorkerBudget

        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        budget = WorkerBudget(cancelled=lambda: True)
        conn.set_progress_handler(budget.sqlite_progress, 100)
        with self.assertRaisesRegex(sqlite3.OperationalError, "interrupted"):
            conn.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT sum(x) FROM n").fetchone()

    def test_failed_refresh_waits_before_retrying(self):
        self.assertEqual(watch_daemon._retry_wait_seconds(2, 1), 2)
        self.assertEqual(watch_daemon._retry_wait_seconds(2, 6), 60)
        self.assertEqual(watch_daemon._retry_wait_seconds(0.1, 1), 0.1)

    def test_ignored_event_storm_does_not_refresh_but_same_stat_source_change_does(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            source = root / "main.py"
            source.write_text("VALUE = 1\n")
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            db.ingest_repo(conn, root, project="demo")
            expected = conn.execute("SELECT hash FROM sources WHERE title='main.py'").fetchone()[0]
            conn.close()
            started = watch_daemon.start_watcher(database, root, "demo", interval_seconds=0.1)
            try:
                if started["backend"] != "watchdog":
                    self.skipTest("watchdog unavailable")
                deadline = time.monotonic() + 15
                while watch_daemon.watcher_status(database, "demo")["cycles"] < 1:
                    if time.monotonic() > deadline:
                        self.fail("initial index timed out")
                    time.sleep(0.05)
                time.sleep(0.2)
                before = watch_daemon.watcher_status(database, "demo")["cycles"]
                output = root / "output"
                output.mkdir()
                for index in range(100):
                    (output / "report.json").write_text(str(index))
                time.sleep(0.5)
                self.assertEqual(watch_daemon.watcher_status(database, "demo")["cycles"], before)
                stat = source.stat()
                source.write_text("VALUE = 2\n")
                os.utime(source, ns=(stat.st_atime_ns, stat.st_mtime_ns))
                while time.monotonic() < deadline:
                    conn = db.connect_readonly(database)
                    try:
                        actual = conn.execute("SELECT hash FROM sources WHERE title='main.py'").fetchone()[0]
                    finally:
                        conn.close()
                    if actual != expected:
                        break
                    time.sleep(0.1)
                self.assertNotEqual(actual, expected)
            finally:
                watch_daemon.stop_watcher(database, "demo", timeout=10)

    def test_multi_file_refresh_deletes_fts_by_rowid_with_legacy_rowids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            for name in ("first.py", "second.py", "remove.py"):
                (root / name).write_text("OLD_VALUE = 1\n")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                # Legacy FTS rowids are not guaranteed to equal chunk ids.
                rows = conn.execute("SELECT chunk_id,source_id,project_id,path,text FROM chunk_fts").fetchall()
                conn.execute("DELETE FROM chunk_fts")
                for index, row in enumerate(rows, 1000):
                    conn.execute("INSERT INTO chunk_fts(rowid,chunk_id,source_id,project_id,path,text) VALUES (?,?,?,?,?,?)", (index, *row))
                conn.commit()
                for name in ("first.py", "second.py"):
                    (root / name).write_text("NEW_VALUE = 2\n")
                (root / "remove.py").unlink()
                statements = []
                conn.set_trace_callback(statements.append)
                db.ingest_repo(conn, root, project="demo")
                conn.set_trace_callback(None)
                full_scans = [sql for sql in statements if "DELETE FROM chunk_fts WHERE source_id" in sql]
                self.assertEqual(full_scans, [])
                self.assertEqual(len([s for s in statements if s.startswith("SELECT rowid, source_id FROM chunk_fts")]), 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM chunk_fts WHERE chunk_fts MATCH 'OLD_VALUE'").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM chunk_fts WHERE chunk_fts MATCH 'NEW_VALUE'").fetchone()[0], 2)
                self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(list(conn.execute("PRAGMA foreign_key_check")), [])
            finally:
                conn.close()

    def test_call_resolution_does_not_revisit_unrelated_files_but_links_new_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "calls.py").write_text("def run():\n    return later()\n")
            (root / "unrelated.py").write_text("def unaffected():\n    return unaffected()\n")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                original = db.add_edge
                attempts = []

                def record(*args, **kwargs):
                    attempts.append(args[4])
                    return original(*args, **kwargs)

                (root / "new.py").write_text("def later():\n    return 42\n")
                with patch.object(db, "add_edge", side_effect=record):
                    db.ingest_repo(conn, root, project="demo")
                unaffected = conn.execute("SELECT id FROM entities WHERE type='symbol' AND name='unaffected'").fetchone()[0]
                self.assertNotIn(unaffected, attempts)
                resolved = conn.execute("SELECT COUNT(*) FROM edges e JOIN entities f ON f.id=e.from_entity_id JOIN entities s ON s.id=e.to_entity_id WHERE f.name='calls.py' AND s.type='symbol' AND s.name='later' AND e.relation='calls'").fetchone()[0]
                self.assertEqual(resolved, 1)
            finally:
                conn.close()
