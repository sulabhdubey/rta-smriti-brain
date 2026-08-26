import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db
from rta_brain.cli import build_parser
from rta_brain.capture_daemon import stop_capture
from rta_brain.capture_spool import CaptureSpool
from rta_brain.console_daemon import stop_console
from rta_brain.continuity_daemon import stop_continuity
from rta_brain.onboarding import derive_project_name, onboard_project, supervise_brain
from rta_brain.watch_daemon import stop_watcher

ROOT = Path(__file__).resolve().parents[1]


def make_minimal_git_repo(root: Path) -> None:
    git_dir = root / ".git"
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (git_dir / "refs" / "heads" / "main").write_text("a" * 40 + "\n", encoding="ascii")


class OnboardingTests(unittest.TestCase):
    def test_project_name_is_safe_and_deterministic(self):
        self.assertEqual(derive_project_name(Path("My Useful Project!")), "my-useful-project")
        self.assertEqual(derive_project_name(Path("...")), "project")

    def test_cli_omission_preserves_existing_provider_intent(self):
        parser = build_parser()
        start = parser.parse_args(["start", "."])
        bootstrap = parser.parse_args(["bootstrap-project", ".", "--project", "demo"])
        self.assertIsNone(start.embedding_provider)
        self.assertIsNone(bootstrap.embedding_provider)

    def test_repeated_onboarding_preserves_existing_retrieval_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "provider-stable"
            root.mkdir()
            (root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            brain_dir = Path(tmp) / "brains"
            sessions = Path(tmp) / "sessions"
            sessions.mkdir()
            first = onboard_project(
                ROOT, root, brain_dir=brain_dir, project="provider-stable", port=0,
                open_browser=False, watcher_interval=0.2, sessions_root=sessions,
                embedding_provider="none",
            )
            try:
                second = onboard_project(
                    ROOT, root, brain_dir=brain_dir, project="provider-stable", port=0,
                    open_browser=False, watcher_interval=0.2, sessions_root=sessions,
                )
                conn = db.connect(Path(first["db_path"]))
                try:
                    settings = db.get_project_settings(conn, "provider-stable")
                finally:
                    conn.close()
                self.assertEqual(settings["embedding_provider"], "none")
                self.assertEqual(second["bootstrap"]["ingest"]["updated_files"], 0)
            finally:
                stop_console(brain_dir, timeout=8.0)
                stop_continuity(Path(first["db_path"]), first["project"], timeout=8.0)
                stop_capture(Path(first["db_path"]), timeout=8.0)
                stop_watcher(Path(first["db_path"]), first["project"], timeout=8.0)

    def test_one_command_onboarding_uses_git_root_and_proves_runtime_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "My Product"
            nested = root / "src" / "feature"
            nested.mkdir(parents=True)
            make_minimal_git_repo(root)
            (root / "main.py").write_text("def ready():\n    return True\n", encoding="utf-8")
            brain_dir = Path(tmp) / "brains"
            sessions = Path(tmp) / "sessions"
            sessions.mkdir()

            payload = onboard_project(
                ROOT,
                nested,
                brain_dir=brain_dir,
                project=None,
                target_agent="universal",
                write_agents=False,
                port=0,
                open_browser=False,
                watcher_interval=0.2,
                sessions_root=sessions,
            )
            try:
                self.assertEqual(payload["status"], "ok")
                self.assertTrue(payload["ready"])
                self.assertEqual(payload["project"], "my-product")
                self.assertEqual(Path(payload["repo_path"]), root.resolve())
                self.assertTrue(Path(payload["db_path"]).is_file())
                self.assertEqual(payload["watcher"]["state"], "running")
                self.assertEqual(payload["capture"]["state"], "running")
                self.assertEqual(payload["continuity"]["state"], "running")
                self.assertEqual(payload["console"]["state"], "running")
                self.assertTrue(payload["readiness"]["ready"])
                self.assertEqual(CaptureSpool(Path(payload["db_path"])).usage_summary()["total_records"], 0)
                self.assertEqual([stage["state"] for stage in payload["stages"]], ["complete"] * 7)
                self.assertFalse((root / "AGENTS.md").exists())
            finally:
                stop_console(brain_dir, timeout=8.0)
                stop_continuity(Path(payload["db_path"]), payload["project"], timeout=8.0)
                stop_capture(Path(payload["db_path"]), timeout=8.0)
                stop_watcher(Path(payload["db_path"]), payload["project"], timeout=8.0)

    def test_repeated_onboarding_reuses_the_existing_brain_incrementally(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repeatable"
            root.mkdir()
            (root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            brain_dir = Path(tmp) / "brains"
            sessions = Path(tmp) / "sessions"
            sessions.mkdir()
            first = onboard_project(
                ROOT, root, brain_dir=brain_dir, project="repeatable", port=0,
                open_browser=False, watcher_interval=0.2, sessions_root=sessions,
            )
            try:
                second = onboard_project(
                    ROOT, root, brain_dir=brain_dir, project="repeatable", port=0,
                    open_browser=False, watcher_interval=0.2, sessions_root=sessions,
                )
                self.assertTrue(second["ready"])
                self.assertEqual(second["db_path"], first["db_path"])
                self.assertEqual(second["bootstrap"]["ingest"]["updated_files"], 0)
                self.assertEqual(second["console"]["pid"], first["console"]["pid"])
                self.assertEqual(second["continuity"]["pid"], first["continuity"]["pid"])
                self.assertEqual(second["capture"]["pid"], first["capture"]["pid"])
            finally:
                stop_console(brain_dir, timeout=8.0)
                stop_continuity(Path(first["db_path"]), first["project"], timeout=8.0)
                stop_capture(Path(first["db_path"]), timeout=8.0)
                stop_watcher(Path(first["db_path"]), first["project"], timeout=8.0)

    def test_login_supervisor_starts_only_privately_enrolled_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "project"
            root.mkdir()
            (root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            brains = Path(tmp) / "brains"
            sessions = Path(tmp) / "sessions"
            sessions.mkdir()
            enrolled = onboard_project(
                ROOT, root, brain_dir=brains, project="enrolled", port=0,
                open_browser=False, watcher_interval=0.2, sessions_root=sessions,
                manage_console=False,
            )
            other = brains / "not-enrolled.sqlite"
            other.touch()
            try:
                stop_continuity(Path(enrolled["db_path"]), "enrolled", timeout=8.0)
                stop_capture(Path(enrolled["db_path"]), timeout=8.0)
                stop_watcher(Path(enrolled["db_path"]), "enrolled", timeout=8.0)
                with (
                    patch("rta_brain.onboarding.start_watcher", return_value={"state": "running"}) as watcher,
                    patch("rta_brain.onboarding.start_capture", return_value={"state": "running"}) as capture,
                    patch("rta_brain.onboarding.start_continuity", return_value={"state": "running"}) as continuity,
                    patch("rta_brain.console_daemon.start_console", return_value={"state": "running"}) as console,
                ):
                    result = supervise_brain(ROOT, brains, port=0)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(len(result["projects"]), 1)
                watcher.assert_called_once()
                capture.assert_called_once()
                continuity.assert_called_once()
                console.assert_called_once()
                self.assertNotIn(str(other), json.dumps(result))
            finally:
                stop_console(brains, timeout=8.0)
                stop_continuity(Path(enrolled["db_path"]), "enrolled", timeout=8.0)
                stop_capture(Path(enrolled["db_path"]), timeout=8.0)
                stop_watcher(Path(enrolled["db_path"]), "enrolled", timeout=8.0)

    def test_login_supervisor_rejects_enrollment_after_canonical_root_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original"
            rebound = Path(tmp) / "rebound"
            original.mkdir()
            rebound.mkdir()
            (original / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            (rebound / "main.py").write_text("VALUE = 2\n", encoding="utf-8")
            brains = Path(tmp) / "brains"
            sessions = Path(tmp) / "sessions"
            sessions.mkdir()
            enrolled = onboard_project(
                ROOT, original, brain_dir=brains, project="enrolled", port=0,
                open_browser=False, watcher_interval=0.2, sessions_root=sessions,
                manage_console=False,
            )
            database = Path(enrolled["db_path"])
            try:
                stop_continuity(database, "enrolled", timeout=8.0)
                stop_capture(database, timeout=8.0)
                stop_watcher(database, "enrolled", timeout=8.0)
                conn = db.connect(database)
                try:
                    conn.execute(
                        "UPDATE projects SET root_path = ? WHERE name = ?",
                        (str(rebound.resolve()), "enrolled"),
                    )
                    conn.commit()
                finally:
                    conn.close()
                with (
                    patch("rta_brain.onboarding.start_watcher") as watcher,
                    patch("rta_brain.onboarding.start_capture") as capture,
                    patch("rta_brain.onboarding.start_continuity") as continuity,
                    patch("rta_brain.console_daemon.start_console", return_value={"state": "running"}),
                ):
                    result = supervise_brain(ROOT, brains, port=0)
                self.assertEqual(result["status"], "partial")
                self.assertEqual(result["projects"][0]["state"], "error")
                watcher.assert_not_called()
                capture.assert_not_called()
                continuity.assert_not_called()
            finally:
                stop_continuity(database, "enrolled", timeout=8.0)
                stop_capture(database, timeout=8.0)
                stop_watcher(database, "enrolled", timeout=8.0)


if __name__ == "__main__":
    unittest.main()
