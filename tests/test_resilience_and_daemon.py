import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db
from rta_brain.mcp_server import McpRequestScheduler, RtaBrainMcpServer
from rta_brain.parsers import ParserRegistry
from rta_brain.watch_daemon import (
    _internal_event_filter,
    _process_alive,
    _worker_command as watcher_worker_command,
    _polling_wait_seconds,
    _watchdog_event_requires_refresh,
    start_watcher,
    stop_watcher,
    watcher_paths,
    watcher_status,
)


class RtaBrainResilienceTests(unittest.TestCase):
    def test_polling_fallback_backs_off_for_large_repositories(self):
        self.assertEqual(_polling_wait_seconds(2.0, 500), 2.0)
        self.assertEqual(_polling_wait_seconds(2.0, 10_000), 30.0)
        self.assertEqual(_polling_wait_seconds(45.0, 10_000), 45.0)
        self.assertEqual(_polling_wait_seconds(2.0, 50_000), 60.0)

    def test_watcher_status_always_includes_stable_counters(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "brain.sqlite"
            stopped = watcher_status(db_path, "demo")
            self.assertEqual(
                {key: stopped[key] for key in ("cycles", "updated_files", "removed_files", "errors")},
                {"cycles": 0, "updated_files": 0, "removed_files": 0, "errors": 0},
            )

            paths = watcher_paths(db_path, "demo")
            paths["directory"].mkdir(parents=True)
            paths["state"].write_text(
                json.dumps({"project": "demo", "state": "starting", "pid": 0}),
                encoding="utf-8",
            )
            partial = watcher_status(db_path, "demo")
            self.assertEqual(
                {key: partial[key] for key in ("cycles", "updated_files", "removed_files", "errors")},
                {"cycles": 0, "updated_files": 0, "removed_files": 0, "errors": 0},
            )

    def test_ingest_repo_rolls_back_the_whole_refresh_when_a_parser_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            first = root / "a.py"
            second = root / "b.py"
            first.write_text("VALUE = 1\n", encoding="utf-8")
            second.write_text("VALUE = 2\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                before = {
                    row["title"]: row["hash"]
                    for row in conn.execute(
                        "SELECT title, hash FROM sources ORDER BY title"
                    )
                }
                first.write_text("VALUE = 10\n", encoding="utf-8")
                second.write_text("VALUE = 20\n", encoding="utf-8")

                original = db.build_file_record
                calls = 0

                def fail_second(*args, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise RuntimeError("parser failed")
                    return original(*args, **kwargs)

                with patch("rta_brain.db.build_file_record", side_effect=fail_second):
                    with self.assertRaisesRegex(RuntimeError, "parser failed"):
                        db.ingest_repo(conn, root, project="demo")

                after = {
                    row["title"]: row["hash"]
                    for row in conn.execute(
                        "SELECT title, hash FROM sources ORDER BY title"
                    )
                }
                self.assertEqual(after, before)
                self.assertFalse(conn.in_transaction)
            finally:
                conn.close()

    def test_tree_sitter_extracts_symbols_and_imports_for_five_core_ecosystems(self):
        registry = ParserRegistry(load_entry_points=False)
        if not registry.capabilities()["tree-sitter"]["available"]:
            self.skipTest("optional tree-sitter-language-pack is not installed")
        cases = {
            "main.py": (
                "import os\nclass Worker:\n    pass\ndef ready():\n    return True\n",
                {"Worker", "ready"},
                {"os"},
            ),
            "main.ts": (
                'import value from "pkg";\nexport class Worker {}\nexport function ready() {}\n',
                {"Worker", "ready"},
                {"pkg"},
            ),
            "main.go": (
                'package main\nimport "fmt"\ntype Worker struct {}\nfunc Ready() {}\n',
                {"Worker", "Ready"},
                {"fmt"},
            ),
            "main.rs": (
                "use std::io;\nstruct Worker {}\nfn ready() {}\n",
                {"Worker", "ready"},
                {"std::io"},
            ),
            "Main.java": (
                "import java.util.List;\nclass Worker { void ready() {} }\n",
                {"Worker", "ready"},
                {"java.util.List"},
            ),
        }
        for filename, (source, symbols, imports) in cases.items():
            with self.subTest(filename=filename):
                result = registry.parse(Path(filename), source, "tree-sitter")
                self.assertEqual(result.parser, "tree-sitter")
                self.assertTrue(symbols.issubset(set(result.symbols)), result.symbols)
                self.assertTrue(imports.issubset(set(result.imports)), result.imports)

    def test_control_messages_are_not_blocked_by_a_slow_mutation(self):
        class SlowServer(RtaBrainMcpServer):
            async def handle_async(self, request):
                params = request.get("params") or {}
                if params.get("name") == "brain_remember":
                    await asyncio.sleep(0.25)
                return {"jsonrpc": "2.0", "id": request.get("id"), "result": {}}

        async def exercise():
            emitted = []
            first_emit = asyncio.Event()

            async def emit(response):
                emitted.append(response["id"])
                first_emit.set()

            scheduler = McpRequestScheduler(object.__new__(SlowServer), emit)
            await scheduler.submit(
                {
                    "jsonrpc": "2.0",
                    "id": "write",
                    "method": "tools/call",
                    "params": {"name": "brain_remember", "arguments": {"text": "x"}},
                }
            )
            await scheduler.submit({"jsonrpc": "2.0", "id": "ping", "method": "ping"})
            await asyncio.wait_for(first_emit.wait(), timeout=0.10)
            first = emitted[0]
            await scheduler.close()
            return first, emitted

        first, emitted = asyncio.run(exercise())
        self.assertEqual(first, "ping")
        self.assertEqual(set(emitted), {"write", "ping"})

    def test_dashboard_checkpoint_conflict_reloads_the_real_project_loader(self):
        source = (Path(__file__).resolve().parents[1] / "dashboard-src" / "src" / "main.jsx").read_text(
            encoding="utf-8"
        )
        self.assertIn("await loadProjectDetails(selectedProject);", source)
        self.assertNotIn("await loadProject(selectedProject);", source)

    def test_console_exposes_watcher_status_and_lifecycle_controls(self):
        root = Path(__file__).resolve().parents[1]
        console = (root / "rta_brain" / "console.py").read_text(encoding="utf-8")
        dashboard = (root / "dashboard-src" / "src" / "main.jsx").read_text(encoding="utf-8")
        self.assertGreaterEqual(console.count('"/api/watcher"'), 2)
        self.assertIn("Repository sync", dashboard)
        self.assertIn("startWatcher", dashboard)
        self.assertIn("stopWatcher", dashboard)
        self.assertGreaterEqual(console.count('"/api/continuity"'), 2)
        self.assertIn("Task continuity", dashboard)
        self.assertIn("toggleContinuity", dashboard)
        self.assertIn("Automatically captured", dashboard)


class RtaBrainWatchDaemonTests(unittest.TestCase):
    def test_source_watcher_worker_uses_the_minimal_entry_point(self):
        database = Path("brain.sqlite")
        command = watcher_worker_command(
            database,
            Path("repository"),
            "demo",
            {
                "state": Path("state.json"),
                "stop": Path("stop.request"),
                "lock": Path("launch.lock"),
            },
            2.0,
        )
        self.assertTrue(any("rta_brain.watch_worker" in part for part in command))
        self.assertNotIn("rta_brain.cli", command)

    def test_watchdog_ignores_file_access_events_but_keeps_content_changes(self):
        class Event:
            is_directory = False
            src_path = "/repo/main.py"
            dest_path = None

            def __init__(self, event_type):
                self.event_type = event_type

        is_internal = lambda _path: False
        self.assertFalse(_watchdog_event_requires_refresh(Event("opened"), is_internal))
        self.assertFalse(_watchdog_event_requires_refresh(Event("closed"), is_internal))
        self.assertTrue(_watchdog_event_requires_refresh(Event("modified"), is_internal))

    def test_internal_event_filter_ignores_only_database_artifacts_and_control_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            database = root / "brain.sqlite"
            control = root / ".rta-smriti-daemons"
            control.mkdir()
            is_internal = _internal_event_filter(database, control)

            internal_paths = [
                database,
                Path(str(database) + "-wal"),
                Path(str(database) + "-shm"),
                Path(str(database) + "-journal"),
                control / "watcher.json.tmp",
            ]
            for candidate in internal_paths * 100:
                with self.subTest(candidate=candidate):
                    self.assertTrue(is_internal(str(candidate)))

            legitimate_paths = [
                root / "brain.sqlite-notes.py",
                root / "src" / "brain.sqlite-wal.py",
                root / ".rta-smriti-daemons-notes.md",
                root / "main.py",
            ]
            for candidate in legitimate_paths:
                with self.subTest(candidate=candidate):
                    self.assertFalse(is_internal(str(candidate)))

    def test_watchdog_filter_handles_removed_internal_paths_without_resolving_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            database = root / ".rta-smriti" / "brain.sqlite"
            control = root / ".rta-smriti" / ".rta-smriti-daemons"
            is_internal = _internal_event_filter(database, control)

            self.assertTrue(is_internal(str(database) + "-journal"))
            self.assertTrue(is_internal(str(control / "deleted-state.json")))
            self.assertFalse(is_internal(str(root / "deleted-project.py")))

    def test_process_liveness_probe_is_non_destructive(self):
        self.assertTrue(_process_alive(os.getpid()))

    def test_background_watcher_rejects_a_hard_linked_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            db_path = Path(tmp) / "brain.sqlite"
            conn = db.connect(db_path)
            try:
                db.ingest_repo(conn, root, project="demo")
            finally:
                conn.close()
            paths = watcher_paths(db_path, "demo")
            paths["directory"].mkdir()
            victim = Path(tmp) / "victim.log"
            victim.write_text("do not append\n", encoding="utf-8")
            os.link(victim, paths["log"])

            with self.assertRaisesRegex(ValueError, "linked watcher log"):
                start_watcher(db_path, root, "demo", interval_seconds=0.2)

            self.assertEqual(victim.read_text(encoding="utf-8"), "do not append\n")
            self.assertFalse(paths["lock"].exists())

    def test_background_watcher_start_refresh_and_stop_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            source = root / "main.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            db_path = Path(tmp) / "brain.sqlite"
            conn = db.connect(db_path)
            try:
                db.ingest_repo(conn, root, project="demo")
            finally:
                conn.close()

            started = start_watcher(
                db_path=db_path,
                root=root,
                project="demo",
                interval_seconds=0.20,
                startup_timeout=8.0,
            )
            try:
                self.assertEqual(started["state"], "running")
                self.assertIn(started["backend"], {"watchdog", "polling"})
                source.write_text("VALUE = 2\n", encoding="utf-8")
                deadline = time.time() + 8
                indexed = ""
                while time.time() < deadline:
                    conn = db.connect(db_path)
                    try:
                        row = conn.execute(
                            "SELECT c.text FROM chunks c JOIN sources s ON s.id = c.source_id "
                            "JOIN projects p ON p.id = s.project_id "
                            "WHERE p.name = 'demo' AND s.title = 'main.py' ORDER BY c.ordinal LIMIT 1"
                        ).fetchone()
                        indexed = row["text"] if row else ""
                    finally:
                        conn.close()
                    if "VALUE = 2" in indexed:
                        break
                    time.sleep(0.10)
                self.assertIn("VALUE = 2", indexed)
                status = watcher_status(db_path, "demo")
                self.assertEqual(status["state"], "running")
                self.assertTrue(status["heartbeat_at"])
            finally:
                stopped = stop_watcher(db_path, "demo", timeout=8.0)
            self.assertEqual(stopped["state"], "stopped")

    def test_watchdog_ignores_its_own_control_files_inside_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            source = root / "main.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            brain_dir = root / ".rta-smriti"
            brain_dir.mkdir()
            db_path = brain_dir / "brain.sqlite"
            conn = db.connect(db_path)
            try:
                db.ingest_repo(conn, root, project="demo")
            finally:
                conn.close()

            started = start_watcher(db_path, root, "demo", interval_seconds=0.1)
            try:
                if started["backend"] != "watchdog":
                    self.skipTest("watchdog is not installed")
                time.sleep(0.8)
                baseline = watcher_status(db_path, "demo")["cycles"]
                for value in range(25):
                    conn = db.connect(db_path)
                    try:
                        conn.execute("CREATE TABLE IF NOT EXISTS watcher_noise(value INTEGER)")
                        conn.execute("INSERT INTO watcher_noise(value) VALUES (?)", (value,))
                        conn.commit()
                    finally:
                        conn.close()
                time.sleep(0.8)
                after_internal_writes = watcher_status(db_path, "demo")
                self.assertEqual(after_internal_writes["cycles"], baseline, after_internal_writes)

                original = source.stat()
                source.write_text("VALUE = 2\n", encoding="utf-8")
                os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
                deadline = time.time() + 8
                indexed = ""
                while time.time() < deadline:
                    status = watcher_status(db_path, "demo")
                    conn = db.connect(db_path)
                    try:
                        row = conn.execute(
                            "SELECT c.text FROM chunks c JOIN sources s ON s.id = c.source_id "
                            "JOIN projects p ON p.id = s.project_id "
                            "WHERE p.name = 'demo' AND s.title = 'main.py' ORDER BY c.ordinal LIMIT 1"
                        ).fetchone()
                        indexed = row["text"] if row else ""
                    finally:
                        conn.close()
                    if status["cycles"] > baseline and "VALUE = 2" in indexed:
                        break
                    time.sleep(0.1)
                self.assertIn("VALUE = 2", indexed)
            finally:
                stop_watcher(db_path, "demo", timeout=8.0)


if __name__ == "__main__":
    unittest.main()
