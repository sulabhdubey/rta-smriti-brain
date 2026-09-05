import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db
from rta_brain.continuity_daemon import (
    capture_cycle,
    continuity_binding_diagnostics,
    continuity_paths,
    continuity_status,
    discover_codex_sessions,
    public_continuity_status,
    start_continuity,
    stop_continuity,
    validate_codex_session_binding,
)
from rta_brain.runtime_control import process_identity


class ContinuityDaemonTests(unittest.TestCase):
    def test_public_status_removes_local_paths_process_metadata_and_raw_errors(self):
        private = {
            "status": "ok",
            "state": "stale",
            "project": "demo",
            "db_path": r"C:\\Users\\owner\\brain.sqlite",
            "root": r"C:\\private\\project",
            "sessions_root": r"C:\\Users\\owner\\.codex\\sessions",
            "pid": 42,
            "token_hash": "secret-fingerprint",
            "process_identity": "windows:42:123",
            "last_error": r"failed to read C:\\private\\project\\secret.txt",
            "consecutive_errors": 1,
            "sessions_pending": 2,
            "process_alive": True,
            "process_identity_matches": False,
            "binding_diagnostics": {
                "recent_sessions": 9,
                "matching_sessions": 1,
                "foreign_sessions": 8,
                "invalid_sessions": 0,
                "hint": "Foreign sessions exist.",
            },
        }

        public = public_continuity_status(private)

        self.assertEqual(public["state"], "stale")
        self.assertTrue(public["has_error"])
        self.assertEqual(public["sessions_pending"], 2)
        self.assertFalse(public["process_identity_matches"])
        self.assertNotIn("binding_diagnostics", public)
        rendered = json.dumps(public)
        for secret in (
            "db_path", "sessions_root", "token_hash", "process_identity\"",
            r"C:\\Users", r"C:\\private", "secret-fingerprint", "secret.txt",
        ):
            self.assertNotIn(secret, rendered)

    def test_status_rejects_reused_pid_with_mismatched_process_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            database.touch()
            paths = continuity_paths(database, "demo")
            paths["directory"].mkdir()
            paths["state"].write_text(json.dumps({
                "project": "demo", "pid": os.getpid(), "state": "running",
                "process_identity": "windows:reused:identity",
                "interval_seconds": 60,
                "heartbeat_at": "2999-01-01T00:00:00+00:00",
            }), encoding="utf-8")

            with patch("rta_brain.continuity_daemon.process_identity", return_value="windows:actual:identity"):
                status = continuity_status(database, "demo")

        self.assertEqual(status["state"], "stale")
        self.assertTrue(status["process_alive"])
        self.assertFalse(status["process_identity_matches"])
        self.assertEqual(status["process_identity_status"], "mismatched")

    def test_live_process_with_unverifiable_identity_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            database.touch()
            paths = continuity_paths(database, "demo")
            paths["directory"].mkdir()
            paths["state"].write_text(json.dumps({
                "project": "demo", "pid": os.getpid(), "state": "running",
                "process_identity": "windows:expected:identity",
                "interval_seconds": 60,
                "heartbeat_at": "2999-01-01T00:00:00+00:00",
            }), encoding="utf-8")

            with patch("rta_brain.continuity_daemon.process_identity", return_value=None):
                status = continuity_status(database, "demo")

        self.assertEqual(status["state"], "stale")
        self.assertTrue(status["process_alive"])
        self.assertFalse(status["process_identity_matches"])
        self.assertEqual(status["process_identity_status"], "unverifiable")

    def test_stop_waits_for_a_stale_live_process_to_exit(self):
        stale_live = {
            "state": "stale", "process_alive": True,
            "process_identity_matches": True, "pid": 42,
        }
        stopped = {"state": "stopped", "process_alive": False, "pid": 42}
        with patch("rta_brain.continuity_daemon.continuity_paths", return_value={
            "directory": Path("control"), "state": Path("control/state"),
            "stop": Path("control/stop"), "lock": Path("control/lock"), "log": Path("control/log"),
        }), patch("rta_brain.continuity_daemon.continuity_status", side_effect=[stale_live, stale_live, stopped]), patch(
            "rta_brain.continuity_daemon._write_stop_request"
        ):
            result = stop_continuity(Path("brain.sqlite"), "demo", timeout=1)
        self.assertEqual(result["state"], "stopped")
        self.assertFalse(result["process_alive"])

    def test_stop_polling_does_not_scan_session_bindings(self):
        running = {
            "state": "running", "process_alive": True,
            "process_identity_matches": True, "pid": 42,
        }
        stopped = {"state": "stopped", "process_alive": False, "pid": 42}
        with patch("rta_brain.continuity_daemon.continuity_paths", return_value={
            "directory": Path("control"), "state": Path("control/state"),
            "stop": Path("control/stop"), "lock": Path("control/lock"), "log": Path("control/log"),
        }), patch(
            "rta_brain.continuity_daemon.continuity_status",
            side_effect=[running, stopped],
        ) as status, patch("rta_brain.continuity_daemon._write_stop_request"):
            result = stop_continuity(Path("brain.sqlite"), "demo", timeout=1)

        self.assertEqual(result["state"], "stopped")
        self.assertTrue(all(call.kwargs == {"include_binding_diagnostics": False} for call in status.call_args_list))

    @unittest.skipIf(os.name == "nt", "POSIX permission contract")
    def test_control_directory_and_state_are_private_on_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            database.touch()
            paths = continuity_paths(database, "demo")
            from rta_brain.runtime_control import prepare_control_dir, write_json
            prepare_control_dir(paths["directory"], label="continuity")
            write_json(paths["state"], {"state": "stopped"}, label="continuity state")
            self.assertEqual(paths["directory"].stat().st_mode & 0o777, 0o700)
            self.assertEqual(paths["state"].stat().st_mode & 0o777, 0o600)

    def test_status_rejects_live_pid_with_expired_heartbeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            database.touch()
            paths = continuity_paths(database, "demo")
            paths["directory"].mkdir()
            paths["state"].write_text(json.dumps({
                "project": "demo", "pid": os.getpid(), "state": "running",
                "process_identity": process_identity(os.getpid()),
                "interval_seconds": 1, "heartbeat_at": "2000-01-01T00:00:00+00:00",
            }), encoding="utf-8")
            self.assertEqual(continuity_status(database, "demo")["state"], "stale")

    def test_start_refuses_to_duplicate_a_live_process_with_stale_heartbeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); database = base / "brain.sqlite"; project = base / "project"; sessions = base / "sessions"
            project.mkdir(); sessions.mkdir()
            conn = db.connect(database); db.init_project(conn, "demo", str(project)); conn.close()
            paths = continuity_paths(database, "demo"); paths["directory"].mkdir()
            paths["state"].write_text(json.dumps({
                "project": "demo", "pid": os.getpid(), "state": "running",
                "process_identity": process_identity(os.getpid()),
                "interval_seconds": 1, "heartbeat_at": "2000-01-01T00:00:00+00:00",
            }), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "alive but unresponsive"):
                start_continuity(database, project, "demo", sessions)

    def test_start_refuses_to_replace_a_live_process_when_identity_is_unverifiable(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); database = base / "brain.sqlite"; project = base / "project"; sessions = base / "sessions"
            project.mkdir(); sessions.mkdir()
            conn = db.connect(database); db.init_project(conn, "demo", str(project)); conn.close()
            paths = continuity_paths(database, "demo"); paths["directory"].mkdir()
            paths["state"].write_text(json.dumps({
                "project": "demo", "pid": os.getpid(), "state": "running",
                "process_identity": "windows:expected:identity",
                "interval_seconds": 1, "heartbeat_at": "2000-01-01T00:00:00+00:00",
            }), encoding="utf-8")
            with patch("rta_brain.continuity_daemon.process_identity", return_value=None), self.assertRaisesRegex(
                RuntimeError, "identity could not be verified"
            ):
                start_continuity(database, project, "demo", sessions)

    def test_stop_refuses_to_clear_a_live_process_when_identity_is_unverifiable(self):
        stale_live = {
            "state": "stale", "process_alive": True,
            "process_identity_matches": False,
            "process_identity_status": "unverifiable", "pid": 42,
        }
        with patch("rta_brain.continuity_daemon.continuity_paths", return_value={
            "directory": Path("control"), "state": Path("control/state"),
            "stop": Path("control/stop"), "lock": Path("control/lock"), "log": Path("control/log"),
        }), patch("rta_brain.continuity_daemon.continuity_status", return_value=stale_live), patch(
            "rta_brain.continuity_daemon._clear_stale_control"
        ) as clear, patch(
            "rta_brain.continuity_daemon._write_stop_request"
        ) as request_stop, self.assertRaisesRegex(RuntimeError, "identity could not be verified"):
            stop_continuity(Path("brain.sqlite"), "demo", timeout=1)

        clear.assert_not_called()
        request_stop.assert_not_called()

    def test_discovery_only_returns_sessions_bound_to_canonical_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "project"
            other = base / "other"
            sessions = base / "sessions"
            project.mkdir()
            other.mkdir()
            sessions.mkdir()

            matching = sessions / "matching.jsonl"
            nested = sessions / "nested.jsonl"
            foreign = sessions / "foreign.jsonl"
            malformed = sessions / "malformed.jsonl"
            matching.write_text(json.dumps({"type": "session_meta", "payload": {"id": "one", "cwd": str(project)}}) + "\n", encoding="utf-8")
            nested.write_text(json.dumps({"type": "session_meta", "payload": {"id": "two", "cwd": str(project / "src")}}) + "\n", encoding="utf-8")
            foreign.write_text(json.dumps({"type": "session_meta", "payload": {"id": "three", "cwd": str(other)}}) + "\n", encoding="utf-8")
            malformed.write_text("not-json\n", encoding="utf-8")

            found = discover_codex_sessions(sessions, project)
            self.assertEqual([item["session_id"] for item in found], ["one", "two"])
            self.assertEqual({Path(item["path"]).name for item in found}, {"matching.jsonl", "nested.jsonl"})

    def test_continuity_status_explains_recent_sessions_outside_project_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "project"
            other = base / "other"
            sessions = base / "sessions"
            project.mkdir()
            other.mkdir()
            sessions.mkdir()
            (sessions / "foreign.jsonl").write_text(
                json.dumps({"type": "session_meta", "payload": {"id": "foreign", "cwd": str(other)}}) + "\n",
                encoding="utf-8",
            )

            diagnostics = continuity_binding_diagnostics(sessions, project)

        self.assertEqual(diagnostics["recent_sessions"], 1)
        self.assertEqual(diagnostics["matching_sessions"], 0)
        self.assertEqual(diagnostics["foreign_sessions"], 1)
        self.assertIn("outside the canonical project root", diagnostics["hint"])
        self.assertNotIn(str(other), json.dumps(diagnostics))

    def test_discovery_bounds_initial_history_unless_explicitly_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "project"
            sessions = base / "sessions"
            project.mkdir()
            sessions.mkdir()
            old = sessions / "old.jsonl"
            old.write_text(json.dumps({"type": "session_meta", "payload": {"id": "old", "cwd": str(project)}}) + "\n", encoding="utf-8")
            old_time = time.time() - 60 * 86400
            os.utime(old, (old_time, old_time))

            self.assertEqual(discover_codex_sessions(sessions, project), [])
            self.assertEqual([item["session_id"] for item in discover_codex_sessions(sessions, project, lookback_days=0)], ["old"])

    def test_discovery_caps_session_inventory_and_reports_degraded_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "project"
            sessions = base / "sessions"
            project.mkdir()
            sessions.mkdir()
            for index in range(4):
                (sessions / f"{index}.jsonl").write_text(
                    json.dumps(
                        {
                            "type": "session_meta",
                            "payload": {"id": str(index), "cwd": str(project)},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

            found = discover_codex_sessions(
                sessions,
                project,
                lookback_days=0,
                candidate_limit=2,
            )
            diagnostics = continuity_binding_diagnostics(
                sessions,
                project,
                lookback_days=0,
                candidate_limit=2,
            )

        self.assertEqual(len(found), 2)
        self.assertEqual(diagnostics["status"], "degraded")
        self.assertTrue(diagnostics["inventory_limited"])
        self.assertIn("safety limit", diagnostics["hint"])

    def test_discovery_rejects_an_oversized_metadata_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); project = base / "project"; sessions = base / "sessions"
            project.mkdir(); sessions.mkdir()
            transcript = sessions / "oversized.jsonl"
            transcript.write_bytes(b"x" * 300_000 + b"\n" + json.dumps({
                "type": "session_meta", "payload": {"id": "late", "cwd": str(project)},
            }).encode("utf-8") + b"\n")
            self.assertEqual(discover_codex_sessions(sessions, project), [])

    def test_session_binding_rejects_foreign_project_and_outside_session_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "project"
            other = base / "other"
            sessions = base / "sessions"
            project.mkdir(); other.mkdir(); sessions.mkdir()
            foreign = sessions / "foreign.jsonl"
            foreign.write_text(json.dumps({"type": "session_meta", "payload": {"id": "foreign", "cwd": str(other)}}) + "\n", encoding="utf-8")
            outside = base / "outside.jsonl"
            outside.write_text(json.dumps({"type": "session_meta", "payload": {"id": "outside", "cwd": str(project)}}) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "canonical project root"):
                validate_codex_session_binding(foreign, sessions, project)
            with self.assertRaisesRegex(ValueError, "outside the configured session directory"):
                validate_codex_session_binding(outside, sessions, project)

    def test_capture_cycle_creates_conservative_terminal_checkpoint_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "project"
            sessions = base / "sessions"
            project.mkdir()
            sessions.mkdir()
            transcript = sessions / "thread.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-1", "cwd": str(project)}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Finish the release safely"}]}},
                {"type": "event_msg", "payload": {"type": "task_complete", "message": "Done"}},
            ]
            transcript.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            database = base / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", str(project))
                first = capture_cycle(conn, sessions, project, "demo", inactivity_seconds=3600)
                second = capture_cycle(conn, sessions, project, "demo", inactivity_seconds=3600)
                checkpoint = db.latest_checkpoint(conn, "demo")
                self.assertEqual(first["events_inserted"], 3)
                self.assertEqual(first["checkpoints_created"], 1)
                self.assertEqual(second["checkpoints_created"], 0)
                self.assertEqual(checkpoint["source"], "continuity-daemon")
                self.assertEqual(checkpoint["trigger"], "task_complete")
                self.assertEqual(checkpoint["objective"], "Finish the release safely")
                self.assertEqual(checkpoint["verified_evidence"], "")
                self.assertIn("unverified", checkpoint["remaining_gaps"].lower())
            finally:
                conn.close()

    def test_opt_in_local_compaction_is_derived_unverified_and_non_authoritative(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); project = base / "project"; sessions = base / "sessions"
            project.mkdir(); sessions.mkdir(); transcript = sessions / "thread.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-compact", "cwd": str(project)}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "Finish release verification"}},
                {"type": "event_msg", "payload": {"type": "task_complete", "message": "Done"}},
            ]
            transcript.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            conn = db.connect(base / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(project))
                db.update_project_settings(conn, "demo", {"compaction_provider": "ollama"})
                compacted = {
                    "status": "ok", "provider": "ollama", "model": "qwen3:0.6b",
                    "summary": "Objective: finish release verification", "verification_status": "unverified",
                    "input_events": 3, "redactions": 0,
                }
                with patch("rta_brain.continuity_daemon.compact_session_events", return_value=compacted):
                    result = capture_cycle(conn, sessions, project, "demo", inactivity_seconds=3600)
                self.assertEqual(result["checkpoints_created"], 1)
                checkpoint = db.latest_checkpoint(conn, "demo")
                self.assertEqual(checkpoint["verified_evidence"], "")
                self.assertIn("Local-model summary (unverified)", checkpoint["remaining_gaps"])
                event = conn.execute(
                    "SELECT source, verification_status FROM session_events "
                    "WHERE event_type = 'continuity_compaction'"
                ).fetchone()
                self.assertEqual(event["source"], "ollama-local")
                self.assertEqual(event["verification_status"], "unverified")
            finally:
                conn.close()

    def test_resumed_session_uses_new_inactivity_checkpoint_after_old_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); project = base / "project"; sessions = base / "sessions"
            project.mkdir(); sessions.mkdir(); transcript = sessions / "thread.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-1", "cwd": str(project)}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "First task"}},
                {"type": "event_msg", "payload": {"type": "task_complete", "message": "Done"}},
            ]
            transcript.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            conn = db.connect(base / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(project))
                capture_cycle(conn, sessions, project, "demo", inactivity_seconds=3600)
                with transcript.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user", "content": "Resumed task"}}) + "\n")
                result = capture_cycle(conn, sessions, project, "demo", inactivity_seconds=1, now=time.time() + 10)
                self.assertEqual(result["checkpoints_created"], 1)
                self.assertEqual(db.latest_checkpoint(conn, "demo")["trigger"], "inactivity")
                self.assertEqual(db.latest_checkpoint(conn, "demo")["objective"], "Resumed task")
            finally:
                conn.close()

    def test_codex_turn_aborted_control_marker_is_not_promoted_to_objective(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp); project = base / "project"; sessions = base / "sessions"
            project.mkdir(); sessions.mkdir(); transcript = sessions / "thread.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-1", "cwd": str(project)}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "Ship the verified release"}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "<turn_aborted>\nThe user interrupted the previous turn on purpose.\n</turn_aborted>"}},
                {"type": "event_msg", "payload": {"type": "turn_aborted", "message": "Interrupted"}},
            ]
            transcript.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            conn = db.connect(base / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(project))
                capture_cycle(conn, sessions, project, "demo", inactivity_seconds=3600)
                self.assertEqual(db.latest_checkpoint(conn, "demo")["objective"], "Ship the verified release")
            finally:
                conn.close()

    def test_incomplete_backlog_does_not_publish_a_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "project"
            sessions = base / "sessions"
            project.mkdir()
            sessions.mkdir()
            transcript = sessions / "thread.jsonl"
            rows = [{"type": "session_meta", "payload": {"id": "thread-1", "cwd": str(project)}}]
            rows.extend({"type": "response_item", "payload": {"type": "message", "role": "user", "content": f"step {index}"}} for index in range(20))
            transcript.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            conn = db.connect(base / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(project))
                result = capture_cycle(conn, sessions, project, "demo", inactivity_seconds=1, now=time.time() + 10, max_events_per_session=2)
                self.assertEqual(result["checkpoints_created"], 0)
                self.assertIsNone(db.latest_checkpoint(conn, "demo"))
            finally:
                conn.close()

    def test_managed_service_starts_captures_and_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = base / "project"
            sessions = base / "sessions"
            project.mkdir()
            sessions.mkdir()
            transcript = sessions / "thread.jsonl"
            transcript.write_text(
                json.dumps({"type": "session_meta", "payload": {"id": "managed", "cwd": str(project)}}) + "\n"
                + json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user", "content": "Resume safely"}}) + "\n",
                encoding="utf-8",
            )
            database = base / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", str(project))
            finally:
                conn.close()
            started = start_continuity(database, project, "demo", sessions, interval_seconds=0.1, inactivity_seconds=3600)
            try:
                self.assertEqual(started["state"], "running")
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and continuity_status(database, "demo").get("events_inserted", 0) < 2:
                    time.sleep(0.05)
                self.assertGreaterEqual(continuity_status(database, "demo")["events_inserted"], 2)
            finally:
                stopped = stop_continuity(database, "demo")
            self.assertEqual(stopped["state"], "stopped")
            conn = db.connect(database)
            try:
                checkpoint = db.latest_checkpoint(conn, "demo")
                self.assertEqual(checkpoint["trigger"], "service_shutdown")
                self.assertEqual(checkpoint["verified_evidence"], "")
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
