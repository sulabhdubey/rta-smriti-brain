import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from os import chdir, getcwd
from pathlib import Path
from unittest.mock import Mock, patch

import rta_brain.console as console_module
import rta_brain.repository as repository
from rta_brain.cli import build_parser
from rta_brain.console import (
    ConsoleConfig,
    _trusted_git_candidates,
    create_dashboard_server,
    dashboard_snapshot,
    is_authorized_request,
    is_local_origin,
    publish_readiness,
    read_file_preview,
    read_file_tree,
    read_memories,
    resolve_brain_db,
    resolve_static_asset,
    run_dashboard,
    scan_brain_databases,
)
from rta_brain.db import connect, graph, ingest_repo, init_project, remember
from rta_brain.ingest import walk_repo

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "rta-brain.py"


class RtaBrainConsoleTests(unittest.TestCase):
    def test_json_closes_request_databases_before_sending_response_headers(self):
        handler_class = console_module.make_handler(
            ConsoleConfig(tool_root=ROOT, brain_dir=ROOT)
        )
        handler = object.__new__(handler_class)
        events = []
        connection = Mock()
        connection.close.side_effect = lambda: events.append("database-close")
        handler.send_response = lambda status: events.append(f"response-{status}")
        handler.send_header = lambda *args: None
        handler.end_headers = lambda: None
        handler.wfile = io.BytesIO()

        console_module._begin_request_database_scope()
        with patch.object(console_module, "connect", return_value=connection):
            opened = console_module._open_db(ROOT / "request-order.sqlite")
        self.assertIs(opened, connection)

        handler._json({"status": "ok"})

        self.assertEqual(connection.close.call_count, 1)
        self.assertLess(events.index("database-close"), events.index("response-200"))

    def test_request_database_cleanup_closes_every_connection_after_a_failure(self):
        handler_class = console_module.make_handler(
            ConsoleConfig(tool_root=ROOT, brain_dir=ROOT)
        )
        handler = object.__new__(handler_class)
        handler.send_response = lambda status: None
        handler.send_header = lambda *args: None
        handler.end_headers = lambda: None
        handler.wfile = io.BytesIO()
        first = Mock()
        second = Mock()
        first.close.side_effect = OSError("simulated close failure")

        console_module._begin_request_database_scope()
        with patch.object(console_module, "connect", side_effect=[first, second]):
            console_module._open_db(ROOT / "first.sqlite")
            console_module._open_db(ROOT / "second.sqlite")

        with self.assertRaisesRegex(OSError, "simulated close failure"):
            handler._json({"status": "ok"})

        self.assertEqual(first.close.call_count, 1)
        self.assertEqual(second.close.call_count, 1)
        self.assertIsNone(console_module._REQUEST_DATABASES.connections)
        console_module._close_request_databases()

    def test_response_write_failure_occurs_after_request_database_cleanup(self):
        handler_class = console_module.make_handler(
            ConsoleConfig(tool_root=ROOT, brain_dir=ROOT)
        )
        handler = object.__new__(handler_class)
        events = []
        connection = Mock()
        connection.close.side_effect = lambda: events.append("database-close")
        handler.send_response = lambda status: events.append(f"response-{status}")
        handler.send_header = lambda *args: None
        handler.end_headers = lambda: None
        handler.wfile = Mock()

        def fail_write(body):
            events.append("response-write")
            raise BrokenPipeError("simulated client disconnect")

        handler.wfile.write.side_effect = fail_write
        console_module._begin_request_database_scope()
        with patch.object(console_module, "connect", return_value=connection):
            console_module._open_db(ROOT / "request-write.sqlite")

        with self.assertRaisesRegex(BrokenPipeError, "simulated client disconnect"):
            handler._json({"status": "ok"})

        self.assertEqual(connection.close.call_count, 1)
        self.assertLess(events.index("database-close"), events.index("response-write"))

    def test_console_and_dashboard_preserve_global_default_db(self):
        parser = build_parser()

        console = parser.parse_args([
            "--db",
            "C:/brains/demo.sqlite",
            "--json",
            "console",
            "start",
            "--brain-dir",
            "C:/brains",
            "--no-open",
        ])
        self.assertEqual(console.db, "C:/brains/demo.sqlite")
        self.assertTrue(console.json)

        dashboard = parser.parse_args([
            "--db",
            "C:/brains/demo.sqlite",
            "dashboard",
            "--no-open",
        ])
        self.assertEqual(dashboard.db, "C:/brains/demo.sqlite")

    def test_dashboard_snapshot_exposes_an_executable_cli_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = dashboard_snapshot(ConsoleConfig(tool_root=ROOT, brain_dir=Path(tmp)))
            self.assertEqual(snapshot["shell"], "powershell" if os.name == "nt" else "posix")
            self.assertIn("rta-brain.py", snapshot["cli_command"])
            self.assertTrue(snapshot["cli_command"].startswith("& '") if os.name == "nt" else not snapshot["cli_command"].startswith("& "))

    def test_git_candidates_never_fall_back_to_the_working_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "Programs" / "Git" / "cmd" / "git.exe"
            fake.parent.mkdir(parents=True)
            fake.write_text("not git", encoding="utf-8")
            previous = getcwd()
            try:
                chdir(tmp)
                with patch.dict(
                    "os.environ",
                    {"ProgramFiles": str(Path(tmp) / "missing-pf"), "ProgramFiles(x86)": str(Path(tmp) / "missing-x86"), "LOCALAPPDATA": ""},
                    clear=False,
                ):
                    self.assertNotIn(fake.resolve(), _trusted_git_candidates())
            finally:
                chdir(previous)
    def test_scan_brain_databases_reports_ready_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain_dir = Path(tmp) / "brains"
            db = brain_dir / "demo.sqlite"
            repo = Path(tmp) / "repo"
            repo.mkdir()
            conn = connect(db)
            try:
                init_project(conn, "demo", str(repo))
                remember(conn, "Use the local dashboard before GitHub publish.", project="demo", memory_type="procedure", pramana="sabda")
            finally:
                conn.close()

            projects = scan_brain_databases(brain_dir)
            self.assertEqual(len(projects), 1)
            self.assertEqual(projects[0]["project"], "demo")
            self.assertTrue(projects[0]["ready"])
            self.assertEqual(projects[0]["memories"], 1)
            self.assertEqual(projects[0]["db_file"], "demo.sqlite")

    def test_scan_brain_databases_fails_closed_when_bound_root_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain_dir = Path(tmp) / "brains"
            database = brain_dir / "demo.sqlite"
            missing = Path(tmp) / "missing-repo"
            conn = connect(database)
            try:
                init_project(conn, "demo", str(missing))
                remember(conn, "Memory remains available, but the claimed root is missing.", project="demo")
            finally:
                conn.close()

            project_entry = scan_brain_databases(brain_dir)[0]
            self.assertFalse(project_entry["ready"])
            self.assertEqual(project_entry["integrity"]["binding"]["state"], "bound_root_missing")

    def test_scan_brain_databases_reuses_repository_inspection_for_shared_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            brain_dir = root / "brains"
            repo.mkdir()
            brain_dir.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "operator@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Rta-Smriti Operator QA"], cwd=repo, check=True)
            (repo / "README.md").write_text("# Shared project\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)

            first = brain_dir / "brain-0.sqlite"
            conn = connect(first)
            try:
                ingest_repo(conn, repo, project="demo")
            finally:
                conn.close()
            shutil.copy2(first, brain_dir / "brain-1.sqlite")
            shutil.copy2(first, brain_dir / "brain-2.sqlite")

            with patch.object(
                repository,
                "run_git_inspection",
                wraps=repository.run_git_inspection,
            ) as run_git:
                projects = scan_brain_databases(brain_dir)

            self.assertEqual(len(projects), 3)
            self.assertLessEqual(run_git.call_count, 4)

    def test_read_memories_filters_by_pramana_and_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            conn = connect(db)
            try:
                init_project(conn, "demo", tmp)
                remember(conn, "Generated prose lives in language.mjs.", project="demo", memory_type="procedure", pramana="sabda")
                remember(conn, "Try a visual mockup for dashboards.", project="demo", memory_type="idea", pramana="kalpana")
            finally:
                conn.close()

            payload = read_memories(db, "demo", query="prose", pramana="sabda")
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(len(payload["memories"]), 1)
            self.assertIn("language.mjs", payload["memories"][0]["text"])

    def test_file_tree_and_preview_are_relative_bounded_and_project_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            (root / "src").mkdir(parents=True)
            (root / "docs").mkdir()
            (root / "src" / "main.py").write_text("def main():\n    return 'ready'\n", encoding="utf-8")
            (root / "src" / "utils.py").write_text("VALUE = 42\n", encoding="utf-8")
            (root / "docs" / "guide.md").write_text("# Guide\n\nLocal only.\n", encoding="utf-8")
            db = Path(tmp) / "brain.sqlite"
            conn = connect(db)
            try:
                ingest_repo(conn, root, project="demo")
            finally:
                conn.close()

            tree = read_file_tree(db, "demo")
            self.assertEqual([entry["name"] for entry in tree["entries"]], ["docs", "src"])
            self.assertTrue(all(":" not in entry["relative_path"] for entry in tree["entries"]))

            src = read_file_tree(db, "demo", prefix="src")
            self.assertEqual({entry["name"] for entry in src["entries"]}, {"main.py", "utils.py"})

            matches = read_file_tree(db, "demo", query="guide")
            self.assertEqual(matches["entries"][0]["relative_path"], "docs/guide.md")

            preview = read_file_preview(db, "demo", "src/main.py")
            self.assertIn("return 'ready'", preview["file"]["content"])
            self.assertNotIn(str(root), str(preview))
            with self.assertRaises(ValueError):
                read_file_tree(db, "demo", prefix="../outside")

    def test_publish_readiness_and_dashboard_help(self):
        readiness = publish_readiness(ROOT)
        names = {item["name"]: item["ok"] for item in readiness["checks"]}
        self.assertIn("README.md", names)
        self.assertIn("LICENSE", names)
        self.assertIn("package-lock.json", names)
        self.assertIn(".github/workflows/ci.yml", names)
        self.assertIn("clean working tree", names)
        self.assertIn("python -m unittest discover -s tests -v", readiness["commands"])
        self.assertNotIn("git add .", readiness["commands"])
        self.assertIn("git status --short", readiness["commands"])

        result = subprocess.run(
            [sys.executable, str(CLI), "dashboard", "--help"],
            text=True,
            capture_output=True,
            cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Run the local operator console", result.stdout)

        readiness_result = subprocess.run(
            [sys.executable, str(CLI), "publish-readiness", "--json"],
            text=True,
            capture_output=True,
            cwd=ROOT,
        )
        self.assertEqual(readiness_result.returncode, 0, readiness_result.stderr)
        self.assertIn("GITHUB_PUBLISH_CHECKLIST.md", readiness_result.stdout)

    def test_static_assets_are_packaged_in_source_tree(self):
        static_dir = ROOT / "rta_brain" / "static"
        assets_dir = static_dir / "assets"
        self.assertTrue((static_dir / "index.html").exists())
        self.assertTrue(any(assets_dir.glob("*.js")))
        self.assertTrue(any(assets_dir.glob("*.css")))
        package_config = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("static/*", package_config)
        self.assertIn("static/assets/*", package_config)

    def test_static_asset_resolution_stays_inside_static_dir(self):
        static_dir = ROOT / "rta_brain" / "static"
        self.assertEqual(resolve_static_asset(static_dir, "/"), static_dir.resolve() / "index.html")
        self.assertIsNone(resolve_static_asset(static_dir, "/../README.md"))
        self.assertIsNone(resolve_static_asset(static_dir, "/assets/../../README.md"))

    def test_local_origin_check_rejects_non_local_origins(self):
        class Headers:
            def __init__(self, values):
                self.values = values

            def get(self, key):
                return self.values.get(key)

        class Handler:
            def __init__(self, values):
                self.headers = Headers(values)

        self.assertTrue(is_local_origin(Handler({})))
        self.assertTrue(is_local_origin(Handler({"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765"})))
        self.assertTrue(is_local_origin(Handler({"Host": "localhost:8765", "Origin": "http://localhost:8765"})))
        self.assertFalse(is_local_origin(Handler({"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:3000"})))
        self.assertFalse(is_local_origin(Handler({"Origin": "https://example.com"})))

    def test_api_capability_is_required_and_compared_exactly(self):
        class Headers:
            def __init__(self, values):
                self.values = values

            def get(self, key):
                return self.values.get(key)

        class Handler:
            def __init__(self, values):
                self.headers = Headers(values)

        config = ConsoleConfig(tool_root=ROOT, brain_dir=ROOT, capability_token="correct-token")
        self.assertFalse(is_authorized_request(Handler({}), config))
        self.assertFalse(is_authorized_request(Handler({"X-Rta-Smriti-Token": "wrong-token"}), config))
        self.assertTrue(is_authorized_request(Handler({"X-Rta-Smriti-Token": "correct-token"}), config))
        self.assertFalse(is_authorized_request(Handler({"Cookie": "rta_smriti_cap=wrong-token"}), config))
        self.assertFalse(is_authorized_request(Handler({"Cookie": "theme=dark; rta_smriti_cap=correct-token"}), config))
        self.assertFalse(is_authorized_request(Handler({"X-Rta-Smriti-Token": "wrong-token", "Cookie": "rta_smriti_cap=correct-token"}), config))

    def test_console_confines_databases_and_host_to_loopback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brain_dir = root / "brains"
            brain_dir.mkdir()
            inside = brain_dir / "inside.sqlite"
            inside.touch()
            outside = root / "outside.sqlite"
            outside.touch()
            config = ConsoleConfig(tool_root=ROOT, brain_dir=brain_dir)
            self.assertEqual(resolve_brain_db(config, inside), inside.resolve())
            with self.assertRaises(ValueError):
                resolve_brain_db(config, outside)
            linked = brain_dir / "linked.sqlite"
            os.link(outside, linked)
            with self.assertRaisesRegex(ValueError, "hard-linked"):
                resolve_brain_db(config, linked)
            with self.assertRaises(ValueError):
                run_dashboard(ROOT, brain_dir, host="0.0.0.0", open_browser=False)

    def test_dashboard_reports_the_actual_server_port_when_zero_is_requested(self):
        class FakeServer:
            server_address = ("127.0.0.1", 43123)

            def __init__(self, *_args, **_kwargs):
                pass

            def serve_forever(self):
                pass

            def server_close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp, patch(
            "rta_brain.console.BoundedThreadingHTTPServer", FakeServer
        ), patch("builtins.print"):
            payload = run_dashboard(ROOT, Path(tmp), port=0, open_browser=False)
        self.assertIn("http://127.0.0.1:43123/", payload["url"])

    def test_loopback_bind_does_not_perform_reverse_dns_lookup(self):
        with tempfile.TemporaryDirectory() as tmp, patch(
            "socket.getfqdn", side_effect=AssertionError("reverse DNS must not run")
        ):
            server, _config, url = create_dashboard_server(
                ROOT, Path(tmp), host="127.0.0.1", port=0
            )
        try:
            self.assertEqual(server.server_name, "127.0.0.1")
            self.assertRegex(url, r"^http://127\.0\.0\.1:\d+/")
        finally:
            server.server_close()

    def test_repo_ingestion_rejects_hard_linked_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            outside = Path(tmp) / "outside.py"
            outside.write_text("SECRET_OUTSIDE = True\n", encoding="utf-8")
            linked = root / "linked.py"
            os.link(outside, linked)
            rejected = []
            self.assertEqual(list(walk_repo(root, rejected=rejected)), [])
            self.assertEqual(rejected[0]["reason"], "hard-link-file")

    def test_graph_lookup_does_not_create_unknown_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = connect(Path(tmp) / "brain.sqlite")
            try:
                init_project(conn, "existing", str(Path(tmp)))
                changes_before = conn.total_changes
                payload = graph(conn, project="missing")
                self.assertEqual(payload["nodes"], [])
                self.assertEqual(conn.total_changes, changes_before)
                count = conn.execute("SELECT COUNT(*) AS count FROM projects").fetchone()["count"]
                self.assertEqual(count, 1)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
