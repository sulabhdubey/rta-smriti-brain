import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from os import chdir, getcwd
from pathlib import Path
from unittest.mock import Mock, patch

import rta_brain.console as console_module
import rta_brain.repository as repository
from rta_brain.cli import build_parser
from rta_brain.console import (
    ConsoleConfig,
    _release_surface_checks,
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
        with patch.object(console_module, "_database_file_identity", return_value=(1, 2)), patch.object(console_module, "connect", return_value=connection):
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
        with patch.object(console_module, "_database_file_identity", return_value=(1, 2)), patch.object(console_module, "connect", side_effect=[first, second]):
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
        with patch.object(console_module, "_database_file_identity", return_value=(1, 2)), patch.object(console_module, "connect", return_value=connection):
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

    def test_database_discovery_is_read_only_and_never_initializes_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain_dir = Path(tmp) / "brains"
            database = brain_dir / "demo.sqlite"
            repo = Path(tmp) / "repo"
            repo.mkdir()
            conn = connect(database)
            try:
                init_project(conn, "demo", str(repo))
            finally:
                conn.close()
            database_before = database.read_bytes()

            with patch.object(
                console_module,
                "init_schema",
                side_effect=AssertionError("discovery must not migrate schemas"),
            ) as initialize:
                projects = scan_brain_databases(brain_dir)
                registry = console_module.scan_brain_registry(brain_dir)

            self.assertEqual(projects[0]["project"], "demo")
            self.assertEqual(registry[0]["project"], "demo")
            self.assertEqual(database.read_bytes(), database_before)
            initialize.assert_not_called()

    def test_open_db_fails_closed_when_database_identity_changes_during_connect(self):
        connection = Mock()
        first_identity = (1, 2)
        second_identity = (1, 3)
        with patch.object(
            console_module,
            "_database_file_identity",
            side_effect=[first_identity, first_identity, second_identity],
            create=True,
        ), patch.object(console_module, "connect", return_value=connection):
            with self.assertRaisesRegex(ValueError, "changed identity"):
                console_module._open_db(ROOT / "identity-race.sqlite")

        connection.close.assert_called_once()

    def test_lifecycle_confirmation_forwards_exact_preview_fields(self):
        confirmation = console_module._lifecycle_confirmation({
            "approved": True,
            "plan_digest": "plan-1",
            "observed_state_digest": "observed-1",
            "desired_state_digest": "desired-1",
        })
        self.assertEqual(confirmation, {
            "approved": True,
            "plan_digest": "plan-1",
            "observed_state_digest": "observed-1",
            "desired_state_digest": "desired-1",
        })

    def test_lifecycle_planning_preserves_stop_and_remove_operation_kinds(self):
        request = {"project": "demo"}
        with patch.object(
            console_module, "plan_stop_lifecycle", return_value={"execution_kind": "stop"}
        ) as stop_plan, patch.object(
            console_module, "plan_remove_lifecycle", return_value={"execution_kind": "remove"}
        ) as remove_plan:
            self.assertEqual(
                console_module._plan_lifecycle_operation(
                    request, {"plan_action": "stop", "desired_state": {}}
                )["execution_kind"],
                "stop",
            )
            self.assertEqual(
                console_module._plan_lifecycle_operation(
                    request, {"plan_action": "remove", "desired_state": {}}
                )["execution_kind"],
                "remove",
            )

        stop_plan.assert_called_once_with(request)
        remove_plan.assert_called_once_with(request)

    def test_outside_artifact_destination_requires_exact_preview_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brain_dir = root / "brains"
            brain_dir.mkdir()
            config = ConsoleConfig(
                tool_root=ROOT,
                brain_dir=brain_dir,
                capability_token="destination-test-token",
            )
            safe = brain_dir / "demo.snapshot"
            outside = root / "exports" / "demo.snapshot"
            intent = {"source_database": "a" * 64, "redact": True}

            authorized = console_module._authorize_artifact_destinations(
                config, "snapshot-create", [safe], intent, None,
            )
            self.assertEqual(authorized, [safe.resolve()])

            with self.assertRaises(console_module.DestinationConfirmationRequired) as blocked:
                console_module._authorize_artifact_destinations(
                    config, "snapshot-create", [outside], intent, None,
                )
            preview = blocked.exception.preview
            self.assertEqual(preview["operation"], "snapshot-create")
            self.assertEqual(preview["destinations"], [str(outside.resolve())])
            self.assertEqual(preview["intent_digest"], console_module._intent_digest(intent))
            self.assertNotIn("intent", preview)

            authorized = console_module._authorize_artifact_destinations(
                config,
                "snapshot-create",
                [outside],
                intent,
                preview["destination_confirmation"],
            )
            self.assertEqual(authorized, [outside.resolve()])
            with self.assertRaises(console_module.DestinationConfirmationRequired):
                console_module._authorize_artifact_destinations(
                    config,
                    "snapshot-create",
                    [root / "exports" / "different.snapshot"],
                    intent,
                    preview["destination_confirmation"],
                )

    def test_destination_confirmation_is_bound_to_export_intent_and_one_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brain_dir = root / "brains"
            brain_dir.mkdir()
            outside = root / "exports" / "demo.bundle"
            config = ConsoleConfig(
                tool_root=ROOT,
                brain_dir=brain_dir,
                capability_token="one-time-destination-token",
            )
            approved_intent = {
                "source_database": "a" * 64,
                "projects": ["demo"],
                "include": ["memories"],
                "redact": True,
            }

            with self.assertRaises(console_module.DestinationConfirmationRequired) as blocked:
                console_module._authorize_artifact_destinations(
                    config, "bundle-export", [outside], approved_intent, None
                )
            confirmation = blocked.exception.preview["destination_confirmation"]

            changed_intent = {**approved_intent, "redact": False}
            with self.assertRaises(console_module.DestinationConfirmationRequired):
                console_module._authorize_artifact_destinations(
                    config,
                    "bundle-export",
                    [outside],
                    changed_intent,
                    confirmation,
                )

            restarted_config = ConsoleConfig(
                tool_root=ROOT,
                brain_dir=brain_dir,
                capability_token="one-time-destination-token",
            )
            with self.assertRaises(console_module.DestinationConfirmationRequired):
                console_module._authorize_artifact_destinations(
                    restarted_config,
                    "bundle-export",
                    [outside],
                    approved_intent,
                    confirmation,
                )

            self.assertEqual(
                console_module._authorize_artifact_destinations(
                    config,
                    "bundle-export",
                    [outside],
                    approved_intent,
                    confirmation,
                ),
                [outside.resolve()],
            )
            with self.assertRaises(console_module.DestinationConfirmationRequired):
                console_module._authorize_artifact_destinations(
                    config,
                    "bundle-export",
                    [outside],
                    approved_intent,
                    confirmation,
                )

    def test_export_intents_bind_sources_scope_and_key_material_without_disclosure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brain_dir = root / "brains"
            brain_dir.mkdir()
            database = brain_dir / "demo.sqlite"
            other_database = brain_dir / "other.sqlite"
            for selected in (database, other_database):
                conn = connect(selected)
                try:
                    init_project(conn, "demo", str(root / "repo"))
                finally:
                    conn.close()
            config = ConsoleConfig(tool_root=ROOT, brain_dir=brain_dir)
            bundle_payload = {
                "db_path": str(database),
                "projects": ["demo"],
                "include": ["memories", "checkpoints"],
                "redact": True,
            }
            baseline = console_module._bundle_export_intent(config, bundle_payload)
            variants = [
                {**bundle_payload, "db_path": str(other_database)},
                {**bundle_payload, "projects": ["other"]},
                {**bundle_payload, "include": ["policies"]},
                {**bundle_payload, "redact": False},
            ]
            for variant in variants:
                self.assertNotEqual(
                    console_module._intent_digest(baseline),
                    console_module._intent_digest(
                        console_module._bundle_export_intent(config, variant)
                    ),
                )

            snapshot_payload = {
                "db_path": str(database),
                "path": str(root / "snapshot.enc"),
                "passphrase_path": str(root / "private-passphrase.txt"),
                "private_key_path": str(root / "private-signing-key.pem"),
            }
            snapshot = console_module._snapshot_write_intent(
                config, "encrypt", snapshot_payload
            )
            for field in ("db_path", "passphrase_path", "private_key_path"):
                variant = {**snapshot_payload, field: str(root / f"other-{field}")}
                if field == "db_path":
                    variant[field] = str(other_database)
                self.assertNotEqual(
                    console_module._intent_digest(snapshot),
                    console_module._intent_digest(
                        console_module._snapshot_write_intent(
                            config, "encrypt", variant
                        )
                    ),
                )

            rendered = json.dumps({"bundle": baseline, "snapshot": snapshot})
            self.assertNotIn(str(root), rendered)
            self.assertNotIn("private-passphrase", rendered)
            self.assertNotIn("private-signing-key", rendered)

    def test_bundle_import_does_not_evaluate_export_only_intent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            brain_dir = root / "brains"
            brain_dir.mkdir()
            database = brain_dir / "demo.sqlite"
            conn = connect(database)
            try:
                init_project(conn, "demo", str(root / "repo"))
            finally:
                conn.close()
            bundle = root / "incoming.bundle.json"
            bundle.write_text("{}\n", encoding="utf-8")
            server, config, url = create_dashboard_server(
                tool_root=ROOT,
                brain_dir=brain_dir,
                default_db=database,
                host="127.0.0.1",
                port=0,
                capability_token="bundle-import-token",
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            endpoint = url.split("/#", 1)[0] + "/api/bundle"
            request = urllib.request.Request(
                endpoint,
                data=json.dumps(
                    {
                        "action": "import",
                        "db_path": str(database),
                        "path": str(bundle),
                        "include": {"export-only": "invalid-for-export"},
                    }
                ).encode("utf-8"),
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Origin": url.split("/#", 1)[0],
                    "X-Rta-Smriti-Token": config.capability_token,
                },
            )
            try:
                with patch.object(
                    console_module,
                    "_bundle_export_intent",
                    side_effect=AssertionError("import must not evaluate export intent"),
                ), patch.object(
                    console_module,
                    "import_bundle",
                    return_value={"status": "ok"},
                ), urllib.request.urlopen(request, timeout=5) as response:
                    result = json.loads(response.read().decode("utf-8"))
                self.assertEqual(result, {"status": "ok"})
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

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
        self.assertIn("python -m pytest -q", readiness["commands"])
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

    def test_release_surface_checks_fail_closed_on_stale_or_missing_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "launch-site" / "src").mkdir(parents=True)
            (root / "scripts").mkdir()
            (root / "pyproject.toml").write_text(
                '[project]\nname = "rta-smriti-brain"\nversion = "1.1.0a1"\n',
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                json.dumps({"version": "1.1.0-alpha"}), encoding="utf-8"
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "version": "1.1.0-alpha",
                        "packages": {"": {"version": "1.1.0-alpha"}},
                    }
                ),
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "Current release: v1.0.4-alpha\n", encoding="utf-8"
            )
            (root / "launch-site" / "src" / "main.jsx").write_text(
                "v1.0.4-alpha", encoding="utf-8"
            )
            (root / "scripts" / "build_installed_smoke.py").write_text(
                'BASELINE_REF = "v1.0.3-alpha"\n', encoding="utf-8"
            )

            checks = {item["name"]: item for item in _release_surface_checks(root)}

            self.assertFalse(checks["release note for 1.1.0-alpha"]["ok"])
            self.assertFalse(checks["README release version"]["ok"])
            self.assertFalse(checks["launch-site release version"]["ok"])
            self.assertFalse(checks["installed-upgrade baseline"]["ok"])

    def test_release_surface_checks_reject_candidate_only_in_stale_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "launch-site" / "src").mkdir(parents=True)
            (root / "scripts").mkdir()
            (root / "pyproject.toml").write_text(
                '[project]\nname = "rta-smriti-brain"\nversion = "1.1.0a1"\n',
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                json.dumps({"version": "1.1.0-alpha"}), encoding="utf-8"
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "version": "1.1.0-alpha",
                        "packages": {"": {"version": "1.1.0-alpha"}},
                    }
                ),
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "Current release: v1.0.4-alpha\n"
                "Roadmap: v1.1.0-alpha is planned.\n",
                encoding="utf-8",
            )
            (root / "docs" / "RELEASE_NOTES_v1.1.0-alpha.md").write_text(
                "# Rta-Smriti Brain v1.1.0 Alpha\n\n"
                "Previous public release: v1.0.4-alpha\n",
                encoding="utf-8",
            )
            (root / "launch-site" / "src" / "main.jsx").write_text(
                'const releaseUrl = `${repositoryUrl}/releases/tag/v1.0.4-alpha`;\n'
                'const historicalMention = "v1.1.0-alpha";\n',
                encoding="utf-8",
            )
            (root / "scripts" / "build_installed_smoke.py").write_text(
                'BASELINE_REF = "v1.0.4-alpha"\n', encoding="utf-8"
            )

            checks = {item["name"]: item for item in _release_surface_checks(root)}

            self.assertFalse(checks["README release version"]["ok"])
            self.assertFalse(checks["launch-site release version"]["ok"])

    def test_release_surface_checks_accept_consistent_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "launch-site" / "src").mkdir(parents=True)
            (root / "scripts").mkdir()
            (root / "pyproject.toml").write_text(
                '[project]\nname = "rta-smriti-brain"\nversion = "1.1.0a1"\n',
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                json.dumps({"version": "1.1.0-alpha"}), encoding="utf-8"
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "version": "1.1.0-alpha",
                        "packages": {"": {"version": "1.1.0-alpha"}},
                    }
                ),
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "Current release: v1.1.0-alpha\n", encoding="utf-8"
            )
            (root / "docs" / "RELEASE_NOTES_v1.1.0-alpha.md").write_text(
                "# Rta-Smriti Brain v1.1.0 Alpha\n\n"
                "Previous public release: v1.0.4-alpha\n",
                encoding="utf-8",
            )
            (root / "launch-site" / "src" / "main.jsx").write_text(
                'const releaseUrl = `${repositoryUrl}/releases/tag/v1.1.0-alpha`;\n',
                encoding="utf-8",
            )
            (root / "scripts" / "build_installed_smoke.py").write_text(
                'BASELINE_REF = "v1.0.4-alpha"\n', encoding="utf-8"
            )

            checks = _release_surface_checks(root)

            self.assertTrue(checks)
            self.assertTrue(all(item["ok"] for item in checks), checks)

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

    def test_dashboard_server_preserves_an_explicit_sessions_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sessions = root / "sessions"
            sessions.mkdir()
            server, config, _url = create_dashboard_server(
                ROOT,
                root,
                host="127.0.0.1",
                port=0,
                sessions_root=sessions,
            )
        try:
            self.assertEqual(config.sessions_root, sessions.resolve())
        finally:
            server.server_close()

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
