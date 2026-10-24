import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db
from rta_brain.capture import register_policy, register_source
from rta_brain.capture_daemon import (
    CAPTURE_INGRESS_FIELDS,
    prepare_capture_spool_record,
)
from rta_brain.capture_spool import (
    CaptureSpool,
    SpoolLimits,
    SpoolUnsafeError,
    source_token,
)
from rta_brain.capture_types import CapturePolicy, CaptureSource


class CaptureDaemonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        self.database = self.base / "brain.sqlite"
        self.conn = db.connect(self.database)
        db.init_project(self.conn, "demo", str(self.root))
        self.policy = CapturePolicy.continuity()
        register_policy(
            self.conn,
            project="demo",
            active_root=self.root,
            policy_id="continuity",
            policy_version=1,
            policy=self.policy,
        )
        self.sources = []
        for source_id in ("source-a", "source-b"):
            source = CaptureSource(
                source_id=source_id,
                adapter="generic",
                adapter_version="1",
                installation_scope="api",
                config_fingerprint=hashlib.sha256(
                    source_id.encode("ascii")
                ).hexdigest(),
            )
            register_source(
                self.conn,
                project="demo",
                active_root=self.root,
                source=source,
                policy_digest=self.policy.digest,
            )
            self.sources.append(source)
        self.spool = CaptureSpool(self.database)

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    @staticmethod
    def record(sequence: int, *, text: str = "synthetic event") -> dict:
        return {
            "source_cursor": str(sequence),
            "cursor_kind": "sequence",
            "session_id": "session-fixture",
            "observed_at": "2026-08-22T12:00:00+00:00",
            "vendor_event": "agent.message",
            "payload": {"event": "agent.message", "message": {"content": text}},
        }

    def publish(self, source_id: str, sequence: int, *, text: str = "synthetic event"):
        record = self.record(sequence, text=text)
        prepared = prepare_capture_spool_record(
            self.conn,
            project="demo",
            active_root=self.root,
            source_id=source_id,
            record=record,
            original_bytes=len(json.dumps(record).encode("utf-8")),
        )
        return self.spool.publish(
            source_id,
            prepared,
            project="demo",
            allowed_fields=CAPTURE_INGRESS_FIELDS,
        )

    def test_project_status_excludes_other_project_queue_and_daemon_counters(self):
        from rta_brain.capture_control import capture_status_report

        expected = self.publish("source-a", 1)
        self.spool.publish(
            "other-source",
            {"cursor": "other"},
            project="other-project",
            allowed_fields={"cursor"},
        )
        daemon_state = {
            "status": "ok",
            "state": "running",
            "process_alive": True,
            "process_identity_matches": True,
            "events_inserted": 99,
            "failures": 7,
            "queue_depth": 42,
            "queue_bytes": 4_096,
        }

        with patch(
            "rta_brain.capture_control.capture_status",
            return_value=daemon_state,
        ):
            report = capture_status_report(
                self.conn,
                database=self.database,
                project="demo",
            )

        self.assertEqual(report["queue"], {
            "state": "verified",
            "records": 1,
            "bytes": expected.stored_bytes,
            "sources": 1,
        })
        self.assertEqual(report["daemon"], {
            "status": "ok",
            "state": "running",
            "process_alive": True,
            "process_identity_matches": True,
        })

    def test_cycle_consumes_sources_round_robin_and_reports_content_free_counters(self):
        from rta_brain.capture_daemon import capture_cycle

        for sequence in range(1, 4):
            self.assertEqual(self.publish("source-a", sequence).status, "stored")
        self.assertEqual(self.publish("source-b", 1).status, "stored")

        result = capture_cycle(self.conn, self.database, max_events=2, max_seconds=2)

        self.assertEqual(result["events_inserted"], 2)
        self.assertEqual(result["sources_visited"], 2)
        self.assertEqual(result["queue_depth"], 2)
        self.assertNotIn("synthetic event", json.dumps(result))
        rows = self.conn.execute(
            "SELECT source_id FROM capture_events ORDER BY project_sequence"
        ).fetchall()
        self.assertEqual([row[0] for row in rows], ["source-a", "source-b"])
        health = self.conn.execute(
            "SELECT last_heartbeat_at, last_event_at, consecutive_errors FROM capture_sources "
            "WHERE source_id = 'source-a'"
        ).fetchone()
        self.assertTrue(health["last_heartbeat_at"])
        self.assertTrue(health["last_event_at"])
        self.assertEqual(health["consecutive_errors"], 0)

    def test_queue_metrics_use_the_usage_ledger_and_bounded_directory_sampling(self):
        from rta_brain.capture_daemon import _queue_metrics

        for sequence in range(1, 4):
            self.publish("source-a", sequence)
        sources = [{"source_id": "source-a", "project": "demo"}]

        with patch("pathlib.Path.glob", side_effect=AssertionError("unbounded glob")):
            depth, oldest_age, age_is_estimate = _queue_metrics(self.spool, sources)

        self.assertEqual(depth, 3)
        self.assertIsNotNone(oldest_age)
        self.assertFalse(age_is_estimate)

    def test_invalid_source_is_quarantined_without_blocking_another_source(self):
        from rta_brain.capture_daemon import capture_cycle

        self.spool.publish(
            "source-a",
            {"source_cursor": "1", "payload": {"event": "unknown"}},
            project="demo",
            allowed_fields={"source_cursor", "payload"},
        )
        self.publish("source-b", 1)

        result = capture_cycle(self.conn, self.database, max_events=10, max_seconds=2)

        self.assertEqual(result["events_inserted"], 1)
        self.assertEqual(result["quarantined"], 1)

    def test_full_quarantine_isolated_to_bad_source_even_in_crash_propagation_mode(self):
        from rta_brain.capture_daemon import capture_cycle

        invalid = {
            "normalized_event": "invalid",
            "cursor_kind": "sequence",
            "original_bytes": 10,
            "source_binding": source_token("source-a", project="demo"),
        }
        self.spool.publish(
            "source-a",
            invalid,
            project="demo",
            allowed_fields=CAPTURE_INGRESS_FIELDS,
        )
        self.publish("source-b", 1)

        with patch.object(
            CaptureSpool,
            "quarantine",
            side_effect=SpoolUnsafeError("capture quarantine budget is full"),
        ):
            result = capture_cycle(
                self.conn,
                self.database,
                max_events=10,
                max_seconds=2,
                propagate_crash=True,
            )

        self.assertEqual(result["events_inserted"], 1)
        self.assertGreaterEqual(result["failures"], 1)
        self.assertEqual(result["failures"], 1)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0], 1
        )

    def test_malformed_spool_record_is_counted_and_valid_record_still_runs(self):
        from rta_brain.capture_daemon import capture_cycle

        paths = self.spool.ensure_source("source-a", project="demo")
        (paths["inbox"] / ("f" * 32 + ".json")).write_bytes(b"not-json")
        self.publish("source-a", 2)

        result = capture_cycle(self.conn, self.database, max_events=2, max_seconds=2)

        self.assertEqual(result["events_inserted"], 1)
        self.assertEqual(result["quarantined"], 1)
        self.assertEqual(result["failures"], 1)

    def test_restart_after_database_commit_is_idempotent_and_completes_receipt(self):
        from rta_brain import capture_daemon

        self.publish("source-a", 1)
        with (
            patch.object(
                capture_daemon,
                "_crash_point",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(RuntimeError("crash"))
                    if point == "after_commit"
                    else None
                ),
            ),
            self.assertRaisesRegex(RuntimeError, "crash"),
        ):
            capture_daemon.capture_cycle(
                self.conn,
                self.database,
                max_events=1,
                max_seconds=2,
                propagate_crash=True,
            )
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0], 1
        )

        claim = next(
            self.spool.ensure_source("source-a", project="demo")["processing"].glob(
                "*.json"
            )
        )
        old = claim.stat().st_mtime - 600
        os.utime(claim, (old, old))
        result = capture_daemon.capture_cycle(
            self.conn,
            self.database,
            max_events=1,
            max_seconds=2,
            abandoned_after_seconds=0,
        )
        self.assertEqual(result["duplicates"], 1)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0], 1
        )
        self.assertFalse(
            list(
                self.spool.ensure_source("source-a", project="demo")[
                    "processing"
                ].glob("*.json")
            )
        )

    def test_failure_before_commit_recovers_to_exactly_one_event(self):
        from rta_brain import capture_daemon

        self.publish("source-a", 1)
        with (
            patch.object(
                capture_daemon,
                "_crash_point",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(RuntimeError("crash"))
                    if point == "before_commit"
                    else None
                ),
            ),
            self.assertRaisesRegex(RuntimeError, "crash"),
        ):
            capture_daemon.capture_cycle(
                self.conn,
                self.database,
                max_events=1,
                max_seconds=2,
                propagate_crash=True,
            )
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0], 0
        )
        processing = next(
            self.spool.ensure_source("source-a", project="demo")["processing"].glob(
                "*.json"
            )
        )
        old = processing.stat().st_mtime - 600
        os.utime(processing, (old, old))
        result = capture_daemon.capture_cycle(
            self.conn,
            self.database,
            max_events=1,
            max_seconds=2,
            abandoned_after_seconds=0,
        )
        self.assertEqual(result["events_inserted"], 1)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0], 1
        )

    def test_every_noncommitted_crash_boundary_recovers_without_a_gap(self):
        from rta_brain import capture_daemon

        for sequence, point in enumerate(("before_claim", "after_claim"), start=10):
            with self.subTest(point=point):
                self.publish("source-a", sequence)
                with (
                    patch.object(
                        capture_daemon,
                        "_crash_point",
                        side_effect=lambda current, selected=point: (
                            (_ for _ in ()).throw(RuntimeError("crash"))
                            if current == selected
                            else None
                        ),
                    ),
                    self.assertRaisesRegex(RuntimeError, "crash"),
                ):
                    capture_daemon.capture_cycle(
                        self.conn,
                        self.database,
                        max_events=1,
                        max_seconds=2,
                        propagate_crash=True,
                    )
                for processing in self.spool.ensure_source("source-a", project="demo")[
                    "processing"
                ].glob("*.json"):
                    old = processing.stat().st_mtime - 600
                    os.utime(processing, (old, old))
                recovered = capture_daemon.capture_cycle(
                    self.conn,
                    self.database,
                    max_events=1,
                    max_seconds=2,
                    abandoned_after_seconds=0,
                )
                self.assertEqual(recovered["events_inserted"], 1)

    def test_crash_before_receipt_replays_as_one_duplicate(self):
        from rta_brain import capture_daemon

        self.publish("source-a", 20)
        with (
            patch.object(
                capture_daemon,
                "_crash_point",
                side_effect=lambda point: (
                    (_ for _ in ()).throw(RuntimeError("crash"))
                    if point == "before_receipt"
                    else None
                ),
            ),
            self.assertRaisesRegex(RuntimeError, "crash"),
        ):
            capture_daemon.capture_cycle(
                self.conn,
                self.database,
                max_events=1,
                max_seconds=2,
                propagate_crash=True,
            )
        processing = next(
            self.spool.ensure_source("source-a", project="demo")["processing"].glob(
                "*.json"
            )
        )
        old = processing.stat().st_mtime - 600
        os.utime(processing, (old, old))
        recovered = capture_daemon.capture_cycle(
            self.conn,
            self.database,
            max_events=1,
            max_seconds=2,
            abandoned_after_seconds=0,
        )
        self.assertEqual(recovered["duplicates"], 1)
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM capture_events WHERE source_cursor = '20'"
            ).fetchone()[0],
            1,
        )

    def test_backpressure_uses_bounded_queue_counts_without_payload_content(self):
        from rta_brain import capture_daemon

        constrained = CaptureSpool(
            self.database,
            limits=SpoolLimits(
                max_source_records=2,
                max_total_records=2,
                max_source_bytes=2_000_000,
                max_total_bytes=2_000_000,
            ),
        )
        for sequence in (30, 31):
            record = self.record(sequence, text="private synthetic marker")
            prepared = prepare_capture_spool_record(
                self.conn,
                project="demo",
                active_root=self.root,
                source_id="source-a",
                record=record,
                original_bytes=len(json.dumps(record).encode("utf-8")),
            )
            constrained.publish(
                "source-a",
                prepared,
                project="demo",
                allowed_fields=CAPTURE_INGRESS_FIELDS,
            )
        with patch.object(capture_daemon, "CaptureSpool", return_value=constrained):
            result = capture_daemon.capture_cycle(
                self.conn,
                self.database,
                max_events=1,
                max_seconds=2,
            )
        self.assertTrue(result["backpressure"])
        self.assertEqual(result["queue_depth"], 1)
        self.assertNotIn("private synthetic marker", json.dumps(result))

    def test_status_rejects_pid_reuse_and_malformed_state(self):
        from rta_brain.capture_daemon import capture_paths, capture_status

        paths = capture_paths(self.database)
        paths["directory"].mkdir()
        paths["state"].write_text("not-json\n", encoding="utf-8")
        self.assertEqual(capture_status(self.database)["state"], "error")

        paths["state"].write_text(
            json.dumps(
                {
                    "state": "running",
                    "pid": os.getpid(),
                    "process_identity": "old-process",
                    "interval_seconds": 1,
                    "heartbeat_at": "2099-01-01T00:00:00+00:00",
                }
            ),
            encoding="utf-8",
        )
        with patch(
            "rta_brain.capture_daemon.process_identity", return_value="new-process"
        ):
            status = capture_status(self.database)
        self.assertEqual(status["state"], "stale")
        self.assertFalse(status["process_identity_matches"])

    def test_worker_requires_exact_private_launch_token(self):
        from rta_brain.capture_daemon import capture_paths, run_capture_worker
        from rta_brain.runtime_control import prepare_control_dir, write_secret

        paths = capture_paths(self.database)
        prepare_control_dir(paths["directory"], label="capture")
        write_secret(paths["lock"], "expected-hash", label="capture launch lock")
        with (
            patch.dict(
                os.environ,
                {"RTA_SMIRTI_CAPTURE_TOKEN": "wrong"},
                clear=False,
            ),
            self.assertRaisesRegex(RuntimeError, "launch lock"),
        ):
            run_capture_worker(
                self.database,
                paths["state"],
                paths["stop"],
                paths["lock"],
                interval_seconds=0.1,
                batch_size=10,
            )

    @unittest.skipUnless(os.name == "nt", "Windows ACL contract")
    def test_windows_capture_control_directory_and_files_have_private_acls(self):
        from rta_brain.capture_daemon import capture_paths
        from rta_brain.capture_spool import windows_path_is_private
        from rta_brain.runtime_control import (
            open_log,
            prepare_control_dir,
            write_json,
            write_secret,
            write_stop_request,
        )

        original_paths = capture_paths(self.database)
        paths = {
            key: self.base / "standalone-control" / path.name
            for key, path in original_paths.items()
            if key != "directory"
        } | {"directory": self.base / "standalone-control"}
        paths["directory"].mkdir()
        widened = subprocess.run(
            [
                "icacls.exe",
                str(paths["directory"]),
                "/grant",
                "*S-1-5-32-545:(OI)(CI)RX",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=0x08000000,
        )
        self.assertEqual(widened.returncode, 0, widened.stderr)
        self.assertFalse(windows_path_is_private(paths["directory"]))
        prepare_control_dir(paths["directory"], label="capture")
        write_json(paths["state"], {"state": "stopped"}, label="capture state")
        write_secret(paths["lock"], "synthetic-lock", label="capture launch lock")
        write_stop_request(paths["stop"], label="capture")
        with open_log(paths["log"], label="capture") as stream:
            stream.write("synthetic\n")

        for path in (
            paths["directory"],
            paths["state"],
            paths["lock"],
            paths["stop"],
            paths["log"],
        ):
            with self.subTest(path=path.name):
                self.assertTrue(windows_path_is_private(path))

    def test_start_is_one_per_brain_and_refuses_unresponsive_live_worker(self):
        from rta_brain.capture_daemon import start_capture

        running = {"status": "ok", "state": "running", "pid": 41}
        with patch("rta_brain.capture_daemon.capture_status", return_value=running):
            self.assertEqual(start_capture(self.database), running)

        stale = {"status": "ok", "state": "stale", "pid": 41, "process_alive": True}
        with (
            patch(
                "rta_brain.capture_daemon.capture_status",
                return_value=stale,
            ),
            self.assertRaisesRegex(RuntimeError, "alive but unresponsive"),
        ):
            start_capture(self.database)

    def test_frozen_worker_command_uses_internal_cli_without_shell_interpolation(self):
        from rta_brain.capture_daemon import _worker_command, capture_paths

        paths = capture_paths(self.database)
        with patch("rta_brain.capture_daemon.sys.frozen", True, create=True):
            command = _worker_command(self.database, paths, 0.5, 20)
        self.assertEqual(Path(command[0]), Path(__import__("sys").executable).resolve())
        self.assertEqual(command[1], "_capture-worker")
        self.assertIn("--db", command)
        self.assertNotIn("&", command)
        self.assertNotIn("|", command)

    def test_atomic_launch_claim_rejects_a_simultaneous_second_start(self):
        from rta_brain.capture_daemon import capture_paths, start_capture
        from rta_brain.runtime_control import create_secret, prepare_control_dir

        paths = capture_paths(self.database)
        prepare_control_dir(paths["directory"], label="capture")
        create_secret(paths["lock"], "other-launch", label="capture launch lock")
        with (
            patch(
                "rta_brain.capture_daemon.capture_status",
                return_value={"status": "ok", "state": "stopped"},
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "another capture start",
            ),
        ):
            start_capture(self.database)

    def test_stop_requests_final_drain_for_stale_live_worker(self):
        from rta_brain.capture_daemon import stop_capture

        stale = {"state": "stale", "process_alive": True, "pid": 42}
        stopped = {"state": "stopped", "process_alive": False, "pid": 42}
        with (
            patch(
                "rta_brain.capture_daemon.capture_status", side_effect=[stale, stopped]
            ),
            patch("rta_brain.capture_daemon.write_stop_request") as stop,
        ):
            result = stop_capture(self.database, timeout=1)
        self.assertEqual(result["state"], "stopped")
        stop.assert_called_once()

    def test_real_worker_starts_heartbeats_and_finally_drains(self):
        from rta_brain.capture_daemon import capture_status, start_capture, stop_capture

        self.publish("source-a", 40)
        started = start_capture(
            self.database,
            interval_seconds=0.1,
            batch_size=1,
            startup_timeout=8,
        )
        try:
            self.assertEqual(started["state"], "running")
            self.assertTrue(started["process_identity_matches"])
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                current = capture_status(self.database)
                if current.get("events_inserted", 0) >= 1:
                    break
                time.sleep(0.05)
            self.assertGreaterEqual(current["events_inserted"], 1)
            stopped = stop_capture(self.database, timeout=8)
            self.assertEqual(stopped["state"], "stopped")
            self.assertTrue(stopped["final_drain_complete"])
            self.assertEqual(stopped["queue_depth"], 0)
        finally:
            current = capture_status(self.database)
            if current["state"] not in {"stopped", "error"}:
                stop_capture(self.database, timeout=8)

    def test_stop_file_interrupts_long_idle_wait(self):
        from rta_brain.capture_daemon import capture_status, start_capture, stop_capture

        start_capture(self.database, interval_seconds=12, startup_timeout=10)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                current = capture_status(self.database)
                if current.get("cycles", 0) >= 1:
                    break
                time.sleep(0.05)
            self.assertGreaterEqual(current.get("cycles", 0), 1)
            self.assertGreaterEqual(current["effective_poll_interval_seconds"], 12)
            stopped = stop_capture(self.database, timeout=4)
            self.assertEqual(stopped["state"], "stopped")
            self.assertTrue(stopped["final_drain_complete"])
        finally:
            stop_capture(self.database, timeout=20)


if __name__ == "__main__":
    unittest.main()
