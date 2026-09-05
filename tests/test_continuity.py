import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import continuity as continuity_module
from rta_brain import db
from rta_brain.continuity import (
    append_event,
    ingest_codex_session,
    list_events,
    operational_readiness,
    reconcile_work_items,
    upsert_work_item,
)


class ContinuityTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX permission contract")
    def test_brain_database_is_private_on_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            conn.close()
            self.assertEqual(database.stat().st_mode & 0o777, 0o600)

    def test_events_are_append_only_and_cursor_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                first = append_event(conn, "demo", "thread-1", "1", "decision", {"text": "Use SQLite"})
                duplicate = append_event(conn, "demo", "thread-1", "1", "decision", {"text": "Ignored duplicate"})
                self.assertTrue(first["inserted"])
                self.assertFalse(duplicate["inserted"])
                events = list_events(conn, "demo")["events"]
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["payload"]["text"], "Use SQLite")
            finally:
                conn.close()

    def test_direct_events_are_redacted_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                secret = "gh" + "p_" + "a" * 30
                append_event(conn, "demo", "s", "1", "tool", {
                    "access_token": secret,
                    "refreshToken": secret,
                    "message": f"password={secret}",
                    "output": "z" * 400_000,
                })
                serialized = json.dumps(list_events(conn, "demo")["events"])
                self.assertNotIn(secret, serialized)
                self.assertIn("[REDACTED]", serialized)
                self.assertIn("[TRUNCATED", serialized)
            finally:
                conn.close()

    def test_console_capability_urls_and_cookie_headers_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                capability = "capability-value-that-must-not-persist"
                append_event(conn, "demo", "s", "console", "tool", {
                    "output": (
                        f"Rta-Smriti Operator Console: http://127.0.0.1:8765/#token={capability}\n"
                        f"Cookie: rta_smriti_cap={capability}"
                    )
                })
                serialized = json.dumps(list_events(conn, "demo")["events"])
                self.assertNotIn(capability, serialized)
                self.assertIn("#token=[REDACTED]", serialized)
                self.assertIn("Cookie: [REDACTED]", serialized)
            finally:
                conn.close()

    def test_codex_jsonl_adapter_resumes_from_saved_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Approved"}]}},
            ]
            session.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                first = ingest_codex_session(conn, session, "demo", session_id="thread-1")
                self.assertEqual(first["inserted"], 2)
                second = ingest_codex_session(conn, session, "demo", session_id="thread-1")
                self.assertEqual(second["inserted"], 0)
                with session.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"type": "event_msg", "payload": {"type": "task_complete", "message": "Done"}}) + "\n")
                third = ingest_codex_session(conn, session, "demo", session_id="thread-1")
                self.assertEqual(third["inserted"], 1)
                self.assertEqual(third["cursor"], session.stat().st_size)
                self.assertTrue(third["complete"])
            finally:
                conn.close()

    @unittest.skipIf(os.name == "nt", "open-file replacement semantics differ on Windows")
    def test_codex_jsonl_adapter_rolls_back_if_path_is_replaced_during_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); session = root / "session.jsonl"; replacement = root / "replacement.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "Original objective"}},
            ]
            session.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            replacement.write_text(json.dumps({"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}}) + "\n", encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            original_mapper = continuity_module._codex_event
            replaced = False

            def replace_after_mapping(payload):
                nonlocal replaced
                mapped = original_mapper(payload)
                if not replaced and payload.get("type") == "response_item":
                    os.replace(replacement, session)
                    replaced = True
                return mapped

            try:
                db.init_project(conn, "demo", tmp)
                with patch("rta_brain.continuity._codex_event", side_effect=replace_after_mapping):
                    with self.assertRaisesRegex(ValueError, "changed identity"):
                        ingest_codex_session(conn, session, "demo", session_id="thread-1")
                self.assertEqual(list_events(conn, "demo")["events"], [])
            finally:
                conn.close()

    def test_codex_jsonl_adapter_preserves_partial_final_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session.jsonl"
            complete = json.dumps({"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}}) + "\n"
            partial = json.dumps({"type": "event_msg", "payload": {"type": "task_complete", "message": "Done"}})
            split = len(partial) // 2
            session.write_text(complete + partial[:split], encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                first = ingest_codex_session(conn, session, "demo", session_id="thread-1")
                self.assertEqual(first["cursor"], session.read_bytes().index(b"\n") + 1)
                with session.open("a", encoding="utf-8") as handle:
                    handle.write(partial[split:] + "\n")
                second = ingest_codex_session(conn, session, "demo", session_id="thread-1")
                self.assertEqual(second["inserted"], 1)
                events = list_events(conn, "demo", session_id="thread-1")
                self.assertEqual(events["events"][-1]["payload"]["type"], "task_complete")
            finally:
                conn.close()

    def test_codex_jsonl_adapter_redacts_common_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session.jsonl"
            github_token = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz1234567890"
            api_key = "sk" + "-secret-value"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}},
                {"type": "response_item", "payload": {"type": "message", "role": "user", "content": f"Use token {github_token}"}},
                {"type": "response_item", "payload": {"type": "function_call_output", "output": {"api_key": api_key, "status": "ok"}}},
            ]
            session.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                ingest_codex_session(conn, session, "demo", session_id="thread-1")
                serialized = json.dumps(list_events(conn, "demo"))
                self.assertNotIn(github_token, serialized)
                self.assertNotIn(api_key, serialized)
                self.assertIn("[REDACTED]", serialized)
            finally:
                conn.close()

    def test_codex_jsonl_adapter_bounds_large_tool_outputs_without_stalling_cursor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}},
                {"type": "response_item", "payload": {"type": "function_call_output", "output": "x" * 400_000}},
            ]
            session.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                result = ingest_codex_session(conn, session, "demo", session_id="thread-1")
                self.assertTrue(result["complete"])
                self.assertEqual(result["inserted"], 2)
                events = list_events(conn, "demo", session_id="thread-1")["events"]
                self.assertLess(len(json.dumps(events[-1]["payload"])), 30_000)
                self.assertIn("[TRUNCATED", json.dumps(events[-1]["payload"]))
            finally:
                conn.close()

    def test_codex_jsonl_adapter_bounds_a_single_oversized_jsonl_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); session = root / "session.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}},
                {"type": "response_item", "payload": {"type": "function_call_output", "output": "q" * 1_200_000}},
            ]
            session.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                result = ingest_codex_session(conn, session, "demo", session_id="thread-1")
                events = list_events(conn, "demo", session_id="thread-1")["events"]
                self.assertTrue(result["complete"])
                self.assertEqual(events[-1]["event_type"], "oversized_record")
                self.assertGreater(events[-1]["payload"]["source_bytes"], 1_000_000)
            finally:
                conn.close()

    def test_codex_jsonl_adapter_bootstraps_from_a_bounded_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session.jsonl"
            rows = [{"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}}]
            rows.extend({"type": "response_item", "payload": {"type": "message", "role": "user", "content": "x" * 80}} for _ in range(100))
            session.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                result = ingest_codex_session(conn, session, "demo", session_id="thread-1", backlog_tail_bytes=500)
                events = list_events(conn, "demo", session_id="thread-1", limit=500)["events"]
                self.assertTrue(result["complete"])
                self.assertLess(len(events), 20)
                self.assertEqual(events[0]["event_type"], "history_truncated")
                self.assertGreater(events[0]["payload"]["skipped_bytes"], 0)
            finally:
                conn.close()

    def test_codex_jsonl_adapter_bounds_a_resumed_backlog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            session = root / "session.jsonl"
            first = {"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}}
            session.write_text(json.dumps(first) + "\n", encoding="utf-8")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                ingest_codex_session(conn, session, "demo", session_id="thread-1")
                with session.open("a", encoding="utf-8") as stream:
                    for _ in range(100):
                        stream.write(json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user", "content": "y" * 80}}) + "\n")
                result = ingest_codex_session(conn, session, "demo", session_id="thread-1", backlog_tail_bytes=500)
                events = list_events(conn, "demo", session_id="thread-1", limit=500)["events"]
                marker = next(event for event in events if event["event_type"] == "history_truncated")
                self.assertTrue(result["complete"])
                self.assertGreater(marker["payload"]["from_cursor"], 0)
                self.assertGreater(marker["payload"]["skipped_bytes"], 0)
            finally:
                conn.close()

    def test_reconciliation_blocks_operational_readiness_until_checkpoint_and_qa_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asset = root / "M23.mp4"
            asset.write_bytes(b"video")
            conn = db.connect(root / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                upsert_work_item(
                    conn, "demo", "asset", "M23", local_path="M23.mp4",
                    qa_state="unknown", decision="pending",
                )
                before = operational_readiness(conn, "demo")
                self.assertEqual(before["operational_state"], "operationally_not_ready")
                self.assertIn("no_structured_checkpoint", before["reasons"])
                self.assertIn("work_state_conflicts", before["reasons"])
                self.assertEqual(reconcile_work_items(conn, "demo")["conflicts"][0]["type"], "file_exists_without_passed_qa")

                upsert_work_item(
                    conn, "demo", "asset", "M23", local_path="M23.mp4",
                    qa_state="passed", decision="accepted",
                )
                db.save_checkpoint(conn, "demo", "Finish Week 3", verified_evidence="M23 independently QA passed", next_action="Export")
                after = operational_readiness(conn, "demo")
                self.assertTrue(after["continuation_ready"])
                self.assertEqual(after["reasons"], [])
            finally:
                conn.close()

    def test_work_item_path_cannot_escape_the_canonical_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                with self.assertRaisesRegex(ValueError, "escapes the canonical project root"):
                    upsert_work_item(conn, "demo", "asset", "outside", local_path="../outside.txt")
            finally:
                conn.close()

    def test_lifecycle_backlog_and_errors_fail_operational_readiness_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                db.save_checkpoint(conn, "demo", "Continue safely")
                payload = operational_readiness(conn, "demo", lifecycle={
                    "state": "running", "sessions_pending": 2, "errors": 1,
                    "last_error": "malformed transcript",
                })
                self.assertFalse(payload["continuation_ready"])
                self.assertIn("continuity_capture_backlog", payload["reasons"])
                self.assertIn("continuity_capture_errors", payload["reasons"])
                compact = operational_readiness(conn, "demo", include_event_count=False)
                self.assertIsNone(compact["event_count"])
            finally:
                conn.close()

    def test_historical_error_count_does_not_block_a_recovered_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                db.save_checkpoint(conn, "demo", "Continue safely")
                payload = operational_readiness(conn, "demo", lifecycle={
                    "state": "running", "sessions_pending": 0, "errors": 12,
                    "consecutive_errors": 0, "last_error": None,
                })
                self.assertTrue(payload["continuation_ready"])
                self.assertNotIn("continuity_capture_errors", payload["reasons"])
            finally:
                conn.close()

    def test_running_worker_without_discovered_sessions_is_not_continuation_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                db.save_checkpoint(conn, "demo", "Continue from the reviewed checkpoint")

                payload = operational_readiness(conn, "demo", lifecycle={
                    "state": "running",
                    "sessions_discovered": 0,
                    "sessions_pending": 0,
                    "events_inserted": 0,
                    "consecutive_errors": 0,
                    "last_error": None,
                })

                self.assertFalse(payload["continuation_ready"])
                self.assertTrue(payload["manual_continuation_ready"])
                self.assertFalse(payload["automatic_capture_ready"])
                self.assertEqual(
                    payload["continuation_health"]["state"],
                    "awaiting_first_session",
                )
                self.assertIn(
                    "continuity_awaiting_first_session",
                    payload["reasons"],
                )
            finally:
                conn.close()

    def test_truncated_history_requires_a_manual_acknowledgement_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                append_event(conn, "demo", "s", "truncated:0:100", "history_truncated", {"skipped_bytes": 100})
                db.save_checkpoint(conn, "demo", "Auto", source="continuity-daemon", trigger="inactivity", session_id="s")
                blocked = operational_readiness(conn, "demo")
                self.assertIn("continuity_history_truncated", blocked["reasons"])
                db.save_checkpoint(conn, "demo", "Reviewed continuation", verified_evidence="Operator reviewed the retained tail.")
                self.assertNotIn("continuity_history_truncated", operational_readiness(conn, "demo")["reasons"])
            finally:
                conn.close()

    def test_codex_jsonl_adapter_rejects_a_foreign_declared_project_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project_root = base / "selected-project"
            foreign_root = base / "foreign-project"
            project_root.mkdir()
            foreign_root.mkdir()
            session = base / "session.jsonl"
            session.write_text(
                json.dumps({
                    "type": "session_meta",
                    "payload": {"id": "thread-foreign", "cwd": str(foreign_root)},
                }) + "\n",
                encoding="utf-8",
            )
            conn = db.connect(base / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(project_root))
                with self.assertRaisesRegex(ValueError, "canonical project root"):
                    ingest_codex_session(
                        conn,
                        session,
                        "demo",
                        session_id="thread-foreign",
                    )
                self.assertEqual(list_events(conn, "demo")["events"], [])
            finally:
                conn.close()

    @unittest.skipUnless(os.name == "nt", "Windows ancestor handle contract")
    def test_codex_jsonl_adapter_blocks_temporary_ancestor_swap_and_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sessions = root / "sessions"
            sessions.mkdir()
            session = sessions / "session.jsonl"
            rows = [
                {"type": "session_meta", "payload": {"id": "thread-1", "cwd": tmp}},
                {
                    "type": "response_item",
                    "payload": {
                        "type": "message",
                        "role": "user",
                        "content": "Original objective",
                    },
                },
            ]
            session.write_text(
                "\n".join(json.dumps(row) for row in rows) + "\n",
                encoding="utf-8",
            )
            replacement_sessions = root / "replacement-sessions"
            replacement_sessions.mkdir()
            (replacement_sessions / "session.jsonl").write_text(
                "\n".join(
                    json.dumps(row)
                    for row in (
                        {
                            "type": "session_meta",
                            "payload": {"id": "thread-1", "cwd": tmp},
                        },
                        {
                            "type": "response_item",
                            "payload": {
                                "type": "message",
                                "role": "user",
                                "content": "Replacement objective",
                            },
                        },
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            conn = db.connect(root / "brain.sqlite")
            parked = root / "parked-sessions"
            original_ensure_project = continuity_module.ensure_project

            def swap_before_open(*args, **kwargs):
                os.replace(sessions, parked)
                os.replace(replacement_sessions, sessions)
                return original_ensure_project(*args, **kwargs)

            try:
                db.init_project(conn, "demo", tmp)
                with patch(
                    "rta_brain.continuity.ensure_project", side_effect=swap_before_open
                ):
                    with self.assertRaises(OSError):
                        ingest_codex_session(
                            conn,
                            session,
                            "demo",
                            session_id="thread-1",
                            expected_sessions_root=sessions,
                        )
                self.assertEqual(list_events(conn, "demo")["events"], [])
            finally:
                conn.close()

    def test_checkpoint_write_rolls_back_on_keyboard_interrupt(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", tmp)
                with (
                    patch("rta_brain.db.now_iso", side_effect=KeyboardInterrupt),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    db.save_checkpoint(conn, "demo", "Interrupted checkpoint")

                self.assertFalse(conn.in_transaction)
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0],
                    0,
                )
            finally:
                if conn.in_transaction:
                    conn.rollback()
                conn.close()


if __name__ == "__main__":
    unittest.main()
