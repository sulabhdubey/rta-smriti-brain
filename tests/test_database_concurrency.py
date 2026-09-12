import ast
import errno
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from rta_brain import db
from rta_brain import runtime_control
from rta_brain.runtime_control import database_writer_lease


class DatabaseConcurrencyTests(unittest.TestCase):
    def test_all_background_writers_use_serialized_maintenance(self):
        root = Path(__file__).resolve().parents[1] / "rta_brain"
        for name in ("watch_daemon.py", "capture_daemon.py", "continuity_daemon.py"):
            tree = ast.parse((root / name).read_text(encoding="utf-8"))
            calls = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            self.assertIn("database_writer_lease", calls, name)
            self.assertIn("bounded_wal_checkpoint", calls, name)

    def test_managed_writer_waits_are_bounded_or_cancellable(self):
        root = Path(__file__).resolve().parents[1] / "rta_brain"
        for name in ("capture_daemon.py", "continuity_daemon.py"):
            tree = ast.parse((root / name).read_text(encoding="utf-8"))
            lease_calls = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "database_writer_lease"
            ]
            self.assertTrue(lease_calls, name)
            for call in lease_calls:
                keywords = {item.arg for item in call.keywords}
                self.assertTrue(
                    {"timeout_seconds", "stop_requested"} & keywords,
                    f"unbounded writer wait in {name}:{call.lineno}",
                )

    def test_continuity_discovers_sessions_before_requesting_writer_turn(self):
        source = (
            Path(__file__).resolve().parents[1] / "rta_brain" / "continuity_daemon.py"
        ).read_text(encoding="utf-8")
        worker = source.split("def run_continuity_worker", 1)[1]
        loop = worker.split("while not stopping_requested():", 1)[1].split(
            "stop_event.wait", 1
        )[0]
        self.assertLess(
            loop.index("discover_codex_sessions("),
            loop.index("with database_writer_lease("),
        )

    def test_watcher_defers_writer_turn_until_ingest_commit(self):
        source = Path(__file__).resolve().parents[1] / "rta_brain" / "watch_daemon.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        ingest_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ingest_repo"
        ]

        self.assertEqual(len(ingest_calls), 1)
        keywords = {item.arg: item.value for item in ingest_calls[0].keywords}
        self.assertIn("_writer_lease_factory", keywords)
        self.assertIn("_initialize_schema", keywords)
        self.assertIsInstance(keywords["_initialize_schema"], ast.Constant)
        self.assertFalse(keywords["_initialize_schema"].value)

    def test_writer_connections_bound_automatic_wal_growth(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            try:
                self.assertEqual(int(conn.execute("PRAGMA wal_autocheckpoint").fetchone()[0]), 4_096)
                self.assertEqual(int(conn.execute("PRAGMA journal_size_limit").fetchone()[0]), 64 * 1024 * 1024)
            finally:
                conn.close()

    def test_ingest_acquires_writer_lease_after_repository_preparation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            db.ensure_project(conn, "demo", str(root))
            events = []
            original_manifest = db._repo_stat_manifest

            def observed_manifest(*args, **kwargs):
                events.append("manifest")
                return original_manifest(*args, **kwargs)

            @contextmanager
            def observed_lease():
                events.append("lease-enter")
                try:
                    yield {"wait_seconds": 0.0}
                finally:
                    events.append("lease-exit")

            try:
                with patch.object(db, "_repo_stat_manifest", side_effect=observed_manifest):
                    result = db.ingest_repo(
                        conn,
                        root,
                        project="demo",
                        _writer_lease_factory=observed_lease,
                        _initialize_schema=False,
                    )
            finally:
                conn.close()

            self.assertEqual(result["updated_files"], 1)
            self.assertEqual(events, ["manifest", "lease-enter", "lease-exit"])

    def test_unchanged_ingest_does_not_acquire_writer_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            events = []

            @contextmanager
            def observed_lease():
                events.append("lease-enter")
                try:
                    yield {"wait_seconds": 0.0}
                finally:
                    events.append("lease-exit")

            try:
                db.ingest_repo(conn, root, project="demo")
                result = db.ingest_repo(
                    conn,
                    root,
                    project="demo",
                    _writer_lease_factory=observed_lease,
                    _initialize_schema=False,
                )
            finally:
                conn.close()

            self.assertTrue(result["manifest_unchanged"])
            self.assertEqual(events, [])

    def test_bounded_wal_checkpoint_is_passive_and_reports_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            try:
                conn.execute("CREATE TABLE checkpoint_probe(value TEXT NOT NULL)")
                conn.execute("INSERT INTO checkpoint_probe(value) VALUES ('ready')")
                conn.commit()
                result = db.bounded_wal_checkpoint(conn, database, threshold_bytes=0)
            finally:
                conn.close()
            self.assertEqual(result["mode"], "passive+truncate")
            self.assertTrue(result["attempted"])
            self.assertGreaterEqual(result["checkpointed_frames"], 0)
            self.assertEqual(result["remaining_bytes"], 0)
            self.assertTrue(result["bounded"])

    def test_database_writer_lease_serializes_background_writers(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            database.write_bytes(b"database-placeholder")
            first_entered = threading.Event()
            release_first = threading.Event()
            second_entered = threading.Event()
            order = []

            def first_writer():
                with database_writer_lease(database, timeout_seconds=2):
                    order.append("first-enter")
                    first_entered.set()
                    release_first.wait(timeout=2)
                    order.append("first-exit")

            def second_writer():
                first_entered.wait(timeout=2)
                with database_writer_lease(database, timeout_seconds=2):
                    order.append("second-enter")
                    second_entered.set()

            first = threading.Thread(target=first_writer)
            second = threading.Thread(target=second_writer)
            first.start()
            second.start()
            self.assertTrue(first_entered.wait(timeout=2))
            time.sleep(0.1)
            self.assertFalse(second_entered.is_set())
            release_first.set()
            first.join(timeout=2)
            second.join(timeout=2)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(order, ["first-enter", "first-exit", "second-enter"])

    def test_database_writer_lease_serves_waiters_in_fifo_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            database.write_bytes(b"database-placeholder")
            holder_entered = threading.Event()
            release_holder = threading.Event()
            waiter_waiting = [threading.Event() for _ in range(3)]
            entered = []

            def holder():
                with database_writer_lease(database, timeout_seconds=3):
                    holder_entered.set()
                    release_holder.wait(timeout=3)

            def waiter(index: int):
                with database_writer_lease(
                    database,
                    timeout_seconds=3,
                    on_wait=lambda _waited: waiter_waiting[index].set(),
                ):
                    entered.append(index)
                    time.sleep(0.05)

            holder_thread = threading.Thread(target=holder)
            holder_thread.start()
            self.assertTrue(holder_entered.wait(timeout=2))
            waiter_threads = []
            for index in range(3):
                thread = threading.Thread(target=waiter, args=(index,))
                waiter_threads.append(thread)
                thread.start()
                self.assertTrue(waiter_waiting[index].wait(timeout=2))

            control_dir = database.parent / ".rta-smriti-daemons"
            queued_tickets = list(control_dir.glob("*.writer.*.ticket"))
            release_holder.set()
            holder_thread.join(timeout=3)
            for thread in waiter_threads:
                thread.join(timeout=3)

            self.assertFalse(holder_thread.is_alive())
            self.assertTrue(all(not thread.is_alive() for thread in waiter_threads))
            # The active holder keeps its ticket published for the full
            # critical section, so same-process Windows waiters cannot
            # overtake it through process-scoped file-lock semantics.
            self.assertEqual(len(queued_tickets), 4)
            self.assertEqual(entered, [0, 1, 2])
            self.assertEqual(list(control_dir.glob("*.writer.*.ticket")), [])

    def test_writer_ticket_cleanup_retries_windows_sharing_violation(self):
        sharing_violation = PermissionError(errno.EACCES, "sharing violation")
        sharing_violation.winerror = 32
        ticket_path = Path("writer.ticket")

        with (
            patch.object(Path, "exists", return_value=True),
            patch.object(runtime_control, "is_safe_regular_file", return_value=True),
            patch.object(
                Path,
                "unlink",
                side_effect=[sharing_violation, None],
            ) as unlink,
            patch.object(runtime_control.time, "sleep") as sleep,
        ):
            runtime_control._remove_writer_ticket(ticket_path)

        self.assertEqual(unlink.call_count, 2)
        sleep.assert_called_once_with(0.025)

    def test_writer_ticket_read_retries_windows_sharing_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            ticket_path = Path(tmp) / "writer.ticket"
            ticket_path.write_text(
                '{"pid":1,"process_identity":"pid:1"}',
                encoding="utf-8",
            )
            original_open = runtime_control.os.open
            sharing_violation = PermissionError(errno.EACCES, "sharing violation")
            sharing_violation.winerror = 32
            attempts = 0

            def flaky_open(*args, **kwargs):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise sharing_violation
                return original_open(*args, **kwargs)

            with (
                patch.object(runtime_control.os, "open", side_effect=flaky_open),
                patch.object(runtime_control.time, "sleep") as sleep,
            ):
                payload = runtime_control._read_writer_ticket(ticket_path)

        self.assertEqual(payload["process_identity"], "pid:1")
        self.assertEqual(attempts, 2)
        sleep.assert_called_once_with(0.025)

    def test_writer_ticket_enrollment_orders_equal_clock_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            control_dir = Path(tmp)
            with (
                patch.object(runtime_control, "process_identity", return_value="pid:1"),
                patch.object(runtime_control.time, "monotonic_ns", return_value=123),
            ):
                first = runtime_control._create_writer_ticket(control_dir, "brain", "key")
                second = runtime_control._create_writer_ticket(control_dir, "brain", "key")

            def sequence(ticket_path: Path) -> int:
                suffix = ticket_path.name.split(".writer.", 1)[1]
                return int(suffix.split("-", 1)[0])

            self.assertEqual(sequence(first), 123)
            self.assertEqual(sequence(second), 124)

    def test_database_writer_lease_is_released_after_a_crash_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            database.write_bytes(b"database-placeholder")
            with (
                self.assertRaisesRegex(RuntimeError, "simulated crash"),
                database_writer_lease(database, timeout_seconds=1),
            ):
                raise RuntimeError("simulated crash")
            with database_writer_lease(database, timeout_seconds=1) as receipt:
                self.assertGreaterEqual(receipt["wait_seconds"], 0)

    def test_database_writer_lease_is_released_after_process_termination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(__file__).resolve().parents[1]
            database = Path(tmp) / "brain.sqlite"
            marker = Path(tmp) / "locked"
            database.write_bytes(b"database-placeholder")
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import time; from pathlib import Path; "
                        "from rta_brain.runtime_control import database_writer_lease; "
                        f"database=Path({str(database)!r}); marker=Path({str(marker)!r}); "
                        "lease=database_writer_lease(database, timeout_seconds=2); "
                        "lease.__enter__(); marker.write_text('ready', encoding='ascii'); "
                        "time.sleep(30)"
                    ),
                ],
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 5
                while not marker.is_file() and time.monotonic() < deadline:
                    time.sleep(0.025)
                self.assertTrue(marker.is_file())
                with (
                    self.assertRaisesRegex(TimeoutError, "writer lease timed out"),
                    database_writer_lease(database, timeout_seconds=0.1),
                ):
                    pass
                control_dir = database.parent / ".rta-smriti-daemons"
                self.assertEqual(len(list(control_dir.glob("*.writer.*.ticket"))), 1)
            finally:
                child.kill()
                child.wait(timeout=5)
            with database_writer_lease(database, timeout_seconds=1) as receipt:
                self.assertGreaterEqual(receipt["wait_seconds"], 0)

    def test_database_writer_lease_removes_a_crashed_waiter_ticket(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(__file__).resolve().parents[1]
            database = Path(tmp) / "brain.sqlite"
            marker = Path(tmp) / "waiting"
            database.write_bytes(b"database-placeholder")
            holder_entered = threading.Event()
            release_holder = threading.Event()

            def holder():
                with database_writer_lease(database, timeout_seconds=3):
                    holder_entered.set()
                    release_holder.wait(timeout=3)

            holder_thread = threading.Thread(target=holder)
            holder_thread.start()
            self.assertTrue(holder_entered.wait(timeout=2))
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        "from rta_brain.runtime_control import database_writer_lease; "
                        f"database=Path({str(database)!r}); marker=Path({str(marker)!r}); "
                        "lease=database_writer_lease(database, timeout_seconds=30, "
                        "on_wait=lambda _waited: marker.write_text('ready', encoding='ascii')); "
                        "lease.__enter__()"
                    ),
                ],
                cwd=root,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            control_dir = database.parent / ".rta-smriti-daemons"
            try:
                deadline = time.monotonic() + 5
                while not marker.is_file() and time.monotonic() < deadline:
                    time.sleep(0.025)
                self.assertTrue(marker.is_file())
                self.assertEqual(len(list(control_dir.glob("*.writer.*.ticket"))), 2)
                child.kill()
                child.wait(timeout=5)
                self.assertEqual(len(list(control_dir.glob("*.writer.*.ticket"))), 2)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                release_holder.set()
                holder_thread.join(timeout=3)

            with database_writer_lease(database, timeout_seconds=1):
                pass
            self.assertEqual(list(control_dir.glob("*.writer.*.ticket")), [])

    def test_writer_ticket_is_not_visible_until_payload_is_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            control_dir = Path(tmp)
            with (
                patch.object(runtime_control, "process_identity", return_value="pid:1"),
                patch.object(os, "replace", side_effect=OSError("simulated crash")),
                self.assertRaisesRegex(OSError, "simulated crash"),
            ):
                runtime_control._create_writer_ticket(control_dir, "brain", "key")
            self.assertEqual(list(control_dir.glob("*.ticket")), [])

    def test_expired_writer_lease_never_attempts_the_os_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            database.write_bytes(b"database-placeholder")
            with (
                patch.object(runtime_control, "_try_lock_descriptor") as try_lock,
                self.assertRaisesRegex(TimeoutError, "writer lease timed out"),
                database_writer_lease(database, timeout_seconds=0),
            ):
                pass
            try_lock.assert_not_called()

    def test_writer_lease_wait_can_be_cancelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            database.write_bytes(b"database-placeholder")
            with (
                self.assertRaisesRegex(InterruptedError, "writer lease was cancelled"),
                database_writer_lease(database, stop_requested=lambda: True),
            ):
                pass


if __name__ == "__main__":
    unittest.main()
