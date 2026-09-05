import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db, project, repository
from rta_brain.binding_guard import McpBindingLease, _paths, _read_owner, rebind_guard
from rta_brain.continuity import operational_readiness
from rta_brain.console import scan_brain_databases
from rta_brain.mcp_server import RtaBrainMcpServer


ROOT = Path(__file__).resolve().parents[1]


class V061IntegrityTests(unittest.TestCase):
    def _git_repo_with_worktree(self, root: Path) -> tuple[Path, Path]:
        primary = root / "primary"
        alternate = root / "alternate"
        primary.mkdir()
        subprocess.run(["git", "init", "-q", str(primary)], check=True)
        subprocess.run(["git", "-C", str(primary), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(primary), "config", "user.name", "Rta-Smriti Test"], check=True)
        (primary / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(primary), "add", "main.py"], check=True)
        subprocess.run(["git", "-C", str(primary), "commit", "-qm", "initial"], check=True)
        subprocess.run(["git", "-C", str(primary), "worktree", "add", "-q", "-b", "alternate", str(alternate)], check=True)
        return primary, alternate

    def test_checkout_identity_distinguishes_worktrees_with_same_repository_lineage(self):
        with tempfile.TemporaryDirectory() as tmp:
            primary, alternate = self._git_repo_with_worktree(Path(tmp))

            self.assertEqual(repository.repository_identity(primary), repository.repository_identity(alternate))
            self.assertNotEqual(repository.checkout_identity(primary), repository.checkout_identity(alternate))
            self.assertEqual(repository.checkout_identity(primary), repository.checkout_identity(primary))

    def test_unverified_git_pointer_cannot_redirect_identity_marker_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_root = root / "project"
            outside = root / "outside-git"
            project_root.mkdir()
            outside.mkdir()
            (project_root / ".git").write_text(f"gitdir: {outside}\n", encoding="utf-8")

            repo_identity = repository.repository_identity(project_root)
            checkout = repository.checkout_identity(project_root)

            self.assertTrue(repo_identity.startswith("local:"))
            self.assertTrue(checkout.startswith("checkout-local:"))
            self.assertFalse((outside / repository.GIT_IDENTITY_FILE).exists())
            self.assertFalse((outside / repository.GIT_CHECKOUT_IDENTITY_FILE).exists())
            self.assertTrue((project_root / repository.IDENTITY_DIR / repository.IDENTITY_FILE).is_file())

    def test_valid_repository_git_pointer_cannot_alias_another_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            victim = root / "victim"
            alias = root / "alias"
            victim.mkdir()
            alias.mkdir()
            subprocess.run(["git", "init", "-q", str(victim)], check=True)
            (alias / ".git").write_text(f"gitdir: {(victim / '.git').resolve()}\n", encoding="utf-8")

            repo_identity = repository.repository_identity(alias)
            checkout = repository.checkout_identity(alias)

            self.assertTrue(repo_identity.startswith("local:"))
            self.assertTrue(checkout.startswith("checkout-local:"))
            self.assertFalse((victim / ".git" / repository.GIT_IDENTITY_FILE).exists())
            self.assertFalse((victim / ".git" / repository.GIT_CHECKOUT_IDENTITY_FILE).exists())

    def test_linked_local_identity_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_root = root / "project"
            outside = root / "outside"
            project_root.mkdir()
            outside.mkdir()
            marker_dir = project_root / repository.IDENTITY_DIR
            try:
                os.symlink(outside, marker_dir, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlink unavailable: {exc}")

            with self.assertRaisesRegex(ValueError, "identity directory"):
                repository.repository_identity(project_root)
            self.assertFalse((outside / repository.IDENTITY_FILE).exists())

    def test_freshness_fails_closed_for_the_wrong_active_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            conn = db.connect(root / "brain.sqlite")
            try:
                db.ingest_repo(conn, primary, project="demo")
                git_dir_value = subprocess.run(
                    ["git", "-C", str(alternate), "rev-parse", "--git-dir"],
                    text=True, capture_output=True, check=True,
                ).stdout.strip()
                git_dir = Path(git_dir_value)
                if not git_dir.is_absolute():
                    git_dir = (alternate / git_dir).resolve()
                alternate_marker = git_dir / repository.GIT_CHECKOUT_IDENTITY_FILE
                self.assertFalse(alternate_marker.exists())
                result = db.stale_check(conn, project="demo", active_root=alternate)
            finally:
                conn.close()

            self.assertEqual(result["state"], "wrong_root")
            self.assertFalse(result["binding"]["ready"])
            self.assertEqual(result["binding"]["state"], "wrong_checkout")
            self.assertEqual(result["fresh"], 0)
            self.assertFalse(alternate_marker.exists())

    def test_failed_rebind_rolls_back_root_identity_and_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            conn = db.connect(root / "brain.sqlite")
            try:
                db.ingest_repo(conn, primary, project="demo")
                before = dict(conn.execute(
                    "SELECT root_path, repository_identity, checkout_identity FROM projects WHERE name = 'demo'"
                ).fetchone())
                backup = root / "before-failed-rebind.sqlite"
                with patch("rta_brain.db.build_file_record", side_effect=RuntimeError("forced parser crash")):
                    with self.assertRaisesRegex(RuntimeError, "forced parser crash"):
                        db.rebind_project_root(
                            conn, alternate, project="demo", backup_path=backup,
                        )
                after = dict(conn.execute(
                    "SELECT root_path, repository_identity, checkout_identity FROM projects WHERE name = 'demo'"
                ).fetchone())
                source_paths = [row[0] for row in conn.execute(
                    "SELECT path FROM sources WHERE kind = 'file' ORDER BY path"
                )]
            finally:
                conn.close()

            self.assertEqual(after, before)
            self.assertTrue(source_paths)
            self.assertTrue(all(str(primary.resolve()) in path for path in source_paths))

    def test_explicit_rebind_creates_backup_and_redacted_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            database = root / "brain.sqlite"
            backup = root / "backup.sqlite"
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, primary, project="demo")
                with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded backup read")):
                    result = db.rebind_project_root(
                        conn, alternate, project="demo", backup_path=backup,
                    )
                current = dict(conn.execute(
                    "SELECT root_path, checkout_identity FROM projects WHERE name = 'demo'"
                ).fetchone())
            finally:
                conn.close()

            self.assertTrue(backup.is_file())
            backup_conn = sqlite3.connect(backup)
            try:
                backed_up_root = backup_conn.execute(
                    "SELECT root_path FROM projects WHERE name = 'demo'"
                ).fetchone()[0]
            finally:
                backup_conn.close()
            self.assertEqual(Path(backed_up_root), primary.resolve())
            self.assertEqual(Path(current["root_path"]), alternate.resolve())
            self.assertEqual(current["checkout_identity"], repository.checkout_identity(alternate))
            self.assertEqual(result["migration"]["status"], "completed")
            self.assertNotIn(str(primary), json.dumps(result["migration"]))
            self.assertNotIn(str(alternate), json.dumps(result["migration"]))

    def test_init_cannot_bypass_the_backed_up_root_rebind_workflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            conn = db.connect(root / "brain.sqlite")
            try:
                db.ingest_repo(conn, primary, project="demo")
                with self.assertRaisesRegex(ValueError, "root-rebind"):
                    db.init_project(conn, "demo", str(alternate), allow_root_rebind=True)
            finally:
                conn.close()

    def test_missing_old_root_requires_explicit_rebind_for_init_and_ingest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary = root / "primary"
            relocated = root / "relocated"
            primary.mkdir()
            (primary / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            database = root / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, primary, project="demo")
                primary.rename(relocated)
                with self.assertRaisesRegex(ValueError, "root-rebind"):
                    db.init_project(conn, "demo", str(relocated))
                with self.assertRaisesRegex(ValueError, "root-rebind"):
                    db.ingest_repo(conn, relocated, project="demo")
                with self.assertRaisesRegex(ValueError, "root-rebind"):
                    db.ingest_repo(conn, relocated, project="demo", allow_root_rebind=True)
                stored = conn.execute(
                    "SELECT root_path FROM projects WHERE name = 'demo'"
                ).fetchone()[0]
            finally:
                conn.close()

            self.assertEqual(Path(stored), primary.resolve())

    def test_ingest_rejects_a_binding_changed_after_its_repository_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            database = root / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, primary, project="demo")
            finally:
                conn.close()

            scanned = threading.Event()
            resume = threading.Event()
            errors = []
            original_manifest = db._repo_stat_manifest

            def delayed_manifest(repo_root, *args, **kwargs):
                result = original_manifest(repo_root, *args, **kwargs)
                if Path(repo_root).resolve() == primary.resolve() and threading.current_thread().name == "stale-ingest":
                    scanned.set()
                    if not resume.wait(timeout=10):
                        raise TimeoutError("test did not release stale ingest")
                return result

            def stale_ingest():
                worker = db.connect(database)
                try:
                    db.ingest_repo(worker, primary, project="demo", force=True)
                except Exception as exc:
                    errors.append(exc)
                finally:
                    worker.close()

            with patch("rta_brain.db._repo_stat_manifest", side_effect=delayed_manifest):
                thread = threading.Thread(target=stale_ingest, name="stale-ingest")
                thread.start()
                self.assertTrue(scanned.wait(timeout=10))
                operator = db.connect(database)
                try:
                    db.rebind_project_root(
                        operator, alternate, project="demo", backup_path=root / "backup.sqlite",
                    )
                finally:
                    operator.close()
                resume.set()
                thread.join(timeout=10)

            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertRegex(str(errors[0]), "binding changed during repository scan")
            verify = db.connect(database)
            try:
                paths = [row[0] for row in verify.execute(
                    "SELECT path FROM sources WHERE kind = 'file' ORDER BY path"
                )]
            finally:
                verify.close()
            self.assertTrue(paths)
            self.assertTrue(all(str(alternate.resolve()) in path for path in paths))

    def test_backup_publication_never_overwrites_a_racing_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "brain.sqlite"
            target = root / "backup.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", str(root))

                def substitute(_source, destination):
                    Path(destination).write_text("attacker-owned\n", encoding="utf-8")
                    raise FileExistsError("destination appeared")

                with patch("rta_brain.db.os.link", side_effect=substitute):
                    with self.assertRaises(FileExistsError):
                        db.backup_brain_database(conn, target)
            finally:
                conn.close()

            self.assertEqual(target.read_text(encoding="utf-8"), "attacker-owned\n")
            self.assertEqual(list(root.glob(f".{target.name}.*.tmp")), [])

    def test_freshness_validates_stored_identity_without_an_active_root_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.ingest_repo(conn, repo, project="demo")
                marker = repo / repository.IDENTITY_DIR / repository.IDENTITY_FILE
                stat_before = marker.stat()
                marker.write_text("f" * 32 + "\n", encoding="ascii")
                os.utime(marker, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))
                result = db.stale_check(conn, project="demo")
            finally:
                conn.close()

            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["state"], "wrong_root")
            self.assertEqual(result["binding"]["state"], "binding_drift")

    def test_integrity_diagnostics_flags_duplicate_root_without_disclosing_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project_root = root / "repo"
            project_root.mkdir()
            (project_root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.ingest_repo(conn, project_root, project="first")
                db.init_project(conn, "second", str(project_root))
                result = db.integrity_diagnostics(conn, project="first", active_root=project_root)
            finally:
                conn.close()

            encoded = json.dumps(result, sort_keys=True)
            self.assertEqual(result["binding"]["state"], "exact")
            self.assertEqual(result["duplicate_root_count"], 1)
            self.assertFalse(result["operationally_ready"])
            self.assertNotIn(str(root), encoded)
            self.assertNotIn(str(Path.home()), encoded)
            self.assertRegex(result["binding"]["root_fingerprint"], r"^[0-9a-f]{16}$")
            self.assertRegex(result["binding"]["repository_fingerprint"], r"^[0-9a-f]{16}$")
            self.assertRegex(result["binding"]["checkout_fingerprint"], r"^[0-9a-f]{16}$")
            self.assertIn("head", result["repository_state"])
            self.assertNotIn("branch", result["repository_state"])
            scanned = next(
                item for item in scan_brain_databases(root)
                if item.get("db_file") == "brain.sqlite" and item.get("project") == "first"
            )
            self.assertEqual(scanned["integrity"]["binding"]["state"], "exact")
            self.assertFalse(scanned["ready"])

    def test_mcp_config_pins_the_bound_checkout_and_rejects_another_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            database = root / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, primary, project="demo")
            finally:
                conn.close()

            config = project.mcp_config_payload(str(database), "demo", "rta-smriti", Path.cwd())
            args = config["config"]["mcpServers"]["rta-smriti"]["args"]
            self.assertIn("--root", args)
            self.assertEqual(Path(args[args.index("--root") + 1]), primary.resolve())
            with self.assertRaisesRegex(ValueError, "active checkout mismatch"):
                RtaBrainMcpServer(database, "demo", expected_root=alternate)

            server = RtaBrainMcpServer(database, "demo", expected_root=primary)
            result = server.call_tool("brain_integrity_diagnostics", {})["structuredContent"]
            self.assertTrue(result["operationally_ready"])
            self.assertEqual(result["binding"]["state"], "exact")
            self.assertNotIn(str(root), json.dumps(result))

    def test_mcp_requires_a_complete_binding_and_derives_the_pin_when_healthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.ensure_project(conn, "unbound")
            finally:
                conn.close()
            with self.assertRaisesRegex(ValueError, "exact canonical project binding"):
                project.mcp_config_payload(str(database), "unbound", "rta-smriti", Path.cwd())
            with self.assertRaisesRegex(ValueError, "active checkout mismatch"):
                RtaBrainMcpServer(database, "unbound")

            repo = root / "repo"
            repo.mkdir()
            (repo / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, repo, project="bound")
            finally:
                conn.close()
            server = RtaBrainMcpServer(database, "bound")
            self.assertEqual(server.expected_root, repo.resolve())

    def test_live_mcp_lease_blocks_root_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            database = root / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, primary, project="demo")
                with McpBindingLease(database, "demo"):
                    with self.assertRaisesRegex(ValueError, "active MCP server"):
                        db.rebind_project_root(
                            conn, alternate, project="demo", backup_path=root / "backup.sqlite",
                        )
            finally:
                conn.close()

    def test_malformed_binding_lease_is_bounded_and_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "brain.sqlite"
            paths = _paths(database, "demo")
            paths["leases"].mkdir(parents=True)
            malformed = paths["leases"] / "malformed.json"
            malformed.write_text('{"pid":"not-a-number"}\n', encoding="utf-8")
            oversized = paths["leases"] / "oversized.json"
            oversized.write_text("x" * 5_000, encoding="utf-8")

            with rebind_guard(database, "demo"):
                self.assertFalse(malformed.exists())
                self.assertFalse(oversized.exists())

    def test_binding_owner_metadata_uses_a_bounded_descriptor_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            owner = Path(tmp) / "owner.json"
            owner.write_text('{"pid": 123}\n', encoding="utf-8")
            real_read = os.read
            requested_sizes = []

            def observed_read(descriptor, size):
                requested_sizes.append(size)
                return real_read(descriptor, size)

            with patch("rta_brain.binding_guard.os.read", side_effect=observed_read):
                self.assertEqual(_read_owner(owner), {"pid": 123})

            self.assertEqual(requested_sizes, [4_097])

    def test_direct_mcp_call_lease_closes_the_rebind_dispatch_race(self):
        entered = threading.Event()
        release = threading.Event()

        class BlockingServer(RtaBrainMcpServer):
            def _call_tool_with_connection(self, conn, name, args, *, db_path, resolved_project):
                entered.set()
                if not release.wait(timeout=10):
                    raise TimeoutError("test did not release MCP call")
                return {"structuredContent": {"status": "ok"}}

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            database = root / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, primary, project="demo")
            finally:
                conn.close()
            server = BlockingServer(database, "demo")
            results = []

            caller = threading.Thread(
                target=lambda: results.append(server.call_tool("brain_search", {"query": "integrity"})),
                name="mcp-call",
            )
            caller.start()
            self.assertTrue(entered.wait(timeout=10))
            operator = db.connect(database)
            try:
                with self.assertRaisesRegex(ValueError, "active MCP server"):
                    db.rebind_project_root(
                        operator, alternate, project="demo", backup_path=root / "backup.sqlite",
                    )
            finally:
                operator.close()
                release.set()
                caller.join(timeout=10)

            self.assertFalse(caller.is_alive())
            self.assertEqual(results, [{"structuredContent": {"status": "ok"}}])

    def test_running_mcp_revalidates_its_checkout_before_every_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            database = root / "brain.sqlite"
            backup = root / "before-rebind.sqlite"
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, primary, project="demo")
            finally:
                conn.close()
            server = RtaBrainMcpServer(database, "demo", expected_root=primary)

            conn = db.connect(database)
            try:
                db.rebind_project_root(conn, alternate, project="demo", backup_path=backup)
            finally:
                conn.close()

            opened = None
            try:
                with self.assertRaisesRegex(ValueError, "active checkout mismatch"):
                    opened = server._open_project("demo")
            finally:
                if opened is not None:
                    opened[0].close()

    def test_rebind_refuses_to_move_a_root_owned_by_running_workers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            database = root / "brain.sqlite"
            backup = root / "before-rebind.sqlite"
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, primary, project="demo")
                with patch("rta_brain.watch_daemon.watcher_status", return_value={"state": "running"}), patch(
                    "rta_brain.continuity_daemon.continuity_status", return_value={"state": "stopped"}
                ):
                    with self.assertRaisesRegex(ValueError, "stop managed workers"):
                        db.rebind_project_root(conn, alternate, project="demo", backup_path=backup)
            finally:
                conn.close()

            self.assertFalse(backup.exists())

    def test_operational_readiness_fails_closed_for_wrong_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            conn = db.connect(root / "brain.sqlite")
            try:
                db.ingest_repo(conn, primary, project="demo")
                db.save_checkpoint(conn, project="demo", objective="Continue safely")
                payload = operational_readiness(
                    conn, "demo", active_root=alternate, include_event_count=False,
                )
            finally:
                conn.close()

            self.assertFalse(payload["continuation_ready"])
            self.assertEqual(payload["operational_state"], "operationally_not_ready")
            self.assertIn("project_integrity", payload["reasons"])
            self.assertEqual(payload["integrity"]["binding"]["state"], "wrong_checkout")

    def test_self_check_carries_active_checkout_integrity_into_readiness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            conn = db.connect(root / "brain.sqlite")
            try:
                db.ingest_repo(conn, primary, project="demo")
                payload = project.self_check(
                    conn, project="demo", check_files=True, active_root=alternate,
                )
                summary = project.self_check(
                    conn, project="demo", check_files=False, active_root=alternate,
                )
            finally:
                conn.close()

            self.assertFalse(payload["ready"])
            self.assertFalse(payload["continuation_ready"])
            self.assertEqual(payload["freshness"]["state"], "wrong_root")
            self.assertIn("project_integrity", payload["operational_reasons"])
            self.assertFalse(summary["ready"])
            self.assertTrue(summary["database_ready"])
            self.assertEqual(summary["integrity"]["binding"]["state"], "wrong_checkout")

    def test_cli_exposes_redacted_integrity_diagnostics_and_backup_rebind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            primary, alternate = self._git_repo_with_worktree(root)
            database = root / "brain.sqlite"
            backup = root / "before-rebind.sqlite"
            conn = db.connect(database)
            try:
                db.ingest_repo(conn, primary, project="demo")
            finally:
                conn.close()

            diagnostics = subprocess.run(
                [
                    sys.executable, str(ROOT / "rta-brain.py"), "--db", str(database), "--json",
                    "integrity-diagnostics", "--project", "demo", "--root", str(primary),
                ],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(diagnostics.returncode, 0, diagnostics.stderr)
            self.assertNotIn(str(root), diagnostics.stdout)
            self.assertTrue(json.loads(diagnostics.stdout)["operationally_ready"], diagnostics.stdout)

            bypass = subprocess.run(
                [
                    sys.executable, str(ROOT / "rta-brain.py"), "--db", str(database), "--json",
                    "ingest-repo", str(alternate), "--project", "demo", "--rebind-root",
                ],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(bypass.returncode, 0)
            self.assertIn("root-rebind", bypass.stderr)

            rebind = subprocess.run(
                [
                    sys.executable, str(ROOT / "rta-brain.py"), "--db", str(database), "--json",
                    "root-rebind", str(alternate), "--project", "demo", "--backup", str(backup),
                ],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(rebind.returncode, 0, rebind.stderr)
            self.assertTrue(backup.is_file())
            self.assertEqual(json.loads(rebind.stdout)["migration"]["status"], "completed")

    def test_denied_checkout_schema_migration_rolls_back_the_new_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legacy.sqlite"
            conn = sqlite3.connect(database)
            conn.row_factory = sqlite3.Row
            conn.executescript("""
                CREATE TABLE projects(
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, root_path TEXT,
                    repository_identity TEXT, created_at TEXT NOT NULL
                );
                CREATE TABLE checkpoints(
                    id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, objective TEXT NOT NULL,
                    verified_evidence TEXT NOT NULL DEFAULT '', remaining_gaps TEXT NOT NULL DEFAULT '',
                    next_action TEXT NOT NULL DEFAULT '', prohibited_repetition TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'operator', trigger TEXT NOT NULL DEFAULT 'manual',
                    session_id TEXT, version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
            """)

            def deny_alter(action, _arg1, _arg2, _database, _trigger):
                return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_ALTER_TABLE else sqlite3.SQLITE_OK

            conn.set_authorizer(deny_alter)
            try:
                with self.assertRaises(sqlite3.DatabaseError):
                    db.init_schema(conn, allow_migration=True)
            finally:
                conn.set_authorizer(None)
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(projects)")}
            conn.close()

            self.assertNotIn("checkout_identity", columns)


if __name__ == "__main__":
    unittest.main()
