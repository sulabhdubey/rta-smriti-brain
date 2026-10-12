import hashlib
import json
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from urllib.parse import urlencode
from pathlib import Path
from unittest.mock import patch

from rta_brain import console, db, trusted_lifecycle


class HealthScanBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.brains = self.base / "brains"
        self.database = self.brains / "demo.sqlite"
        self.repo = self.base / "repo"
        self.repo.mkdir()
        connection = db.connect(self.database)
        try:
            db.init_project(connection, "demo", self.repo)
        finally:
            connection.close()

    def check_lock(self):
        key = str(self.database.resolve()).casefold()
        index = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16)
        locks = trusted_lifecycle._database_check_locks
        return locks[index % len(locks)]

    def test_scan_returns_deferred_while_another_check_holds_the_lock(self):
        results = []
        errors = []
        lock = self.check_lock()

        def scan():
            try:
                results.extend(console.scan_brain_databases(self.brains))
            except (sqlite3.Error, ValueError, OSError) as error:
                errors.append(error)

        lock.acquire()
        with patch.object(console, "HEALTH_SCAN_BUDGET_SECONDS", 0.25), patch.object(
            console, "_verified_quick_check", wraps=trusted_lifecycle._verified_quick_check
        ) as check:
            worker = threading.Thread(target=scan)
            try:
                worker.start()
                worker.join(timeout=0.75)
                returned_with_lock_held = not worker.is_alive()
            finally:
                lock.release()
                worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(check.call_count, 1)
        self.assertTrue(returned_with_lock_held, "client timeout must not leave a lock waiter running")
        self.assertEqual(results[0]["scan_state"], "deferred")
        self.assertFalse(results[0]["ready"])
        self.assertEqual(results[0]["integrity"]["database_verification"], "deferred")

    def test_expensive_sql_is_interrupted_without_caching_and_retry_still_works(self):
        original_open = console._open_db_read_only
        connections = []
        interrupted = []

        class SlowIntegrityConnection:
            def __init__(self, connection):
                self.connection = connection

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def execute(self, statement, *args):
                if statement == "PRAGMA quick_check":
                    try:
                        return self.connection.execute(
                            "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL "
                            "SELECT x+1 FROM n WHERE x<50000000) "
                            "SELECT CASE WHEN sum(x)>0 THEN 'ok' END FROM n"
                        )
                    except sqlite3.OperationalError as error:
                        interrupted.append(error.sqlite_errorcode)
                        raise
                return self.connection.execute(statement, *args)

        def slow_open(*args, **kwargs):
            connection = original_open(*args, **kwargs)
            connections.append(connection)
            return SlowIntegrityConnection(connection)

        before = hashlib.sha256(self.database.read_bytes()).hexdigest()
        started = time.monotonic()
        with patch.object(console, "HEALTH_SCAN_BUDGET_SECONDS", 0.25), patch.object(
            console, "_open_db_read_only", side_effect=slow_open
        ):
            result = console.scan_brain_databases(self.brains)[0]
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(interrupted, [sqlite3.SQLITE_INTERRUPT])
        self.assertEqual(result["scan_state"], "deferred")
        self.assertFalse(result["ready"])
        self.assertEqual(result["integrity"]["binding"]["state"], "exact")
        self.assertTrue(result["integrity"]["schema_current"])
        self.assertIn("database_verification_deferred", result["health_reasons"])
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), before)
        for connection in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")
        key = str(self.database.resolve()).casefold()
        self.assertNotIn(key, trusted_lifecycle._database_check_cache)
        self.assertTrue(self.check_lock().acquire(blocking=False))
        self.check_lock().release()
        retry = console.scan_brain_databases(self.brains)[0]
        self.assertEqual(retry["integrity"]["sqlite_quick_check"], "ok")
        self.assertEqual(retry["integrity"]["database_verification_evidence"]["source"], "live")

    def test_one_budget_covers_all_banks_and_retains_known_project_identities(self):
        other = db.connect(self.brains / "other.sqlite")
        try:
            db.init_project(other, "second", self.repo)
            db.init_project(other, "third", self.repo)
        finally:
            other.close()

        deadlines = []

        def exhaust_budget(*args, **kwargs):
            deadlines.append(kwargs["deadline"])
            time.sleep(max(0, kwargs["deadline"] - time.monotonic()) + 0.01)
            raise trusted_lifecycle.DatabaseCheckTimeout("fixture budget")

        started = time.monotonic()
        with patch.object(console, "HEALTH_SCAN_BUDGET_SECONDS", 0.25), patch.object(
            console, "_verified_quick_check", side_effect=exhaust_budget
        ) as check:
            results = console.scan_brain_databases(self.brains)
        self.assertEqual(check.call_count, 2)
        self.assertLess(deadlines[0], deadlines[1])
        self.assertLessEqual(deadlines[-1] - started, 0.27)
        self.assertEqual({item["project"] for item in results}, {"demo", "second", "third"})
        self.assertTrue(all(item["scan_state"] == "deferred" for item in results))
        self.assertTrue(all(not item["ready"] for item in results))
        self.assertTrue(all(item["root_duplicate"] for item in results))

    def test_expensive_preferred_bank_does_not_starve_an_independent_bank(self):
        other_path = self.brains / "z-small.sqlite"
        other_root = self.base / "other-repo"
        other_root.mkdir()
        other = db.connect(other_path)
        try:
            db.init_project(other, "small", other_root)
        finally:
            other.close()
        original_open = console._open_db_read_only
        connections = []
        interrupted = []

        class SlowPreferredCheck:
            def __init__(self, connection):
                self.connection = connection

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def execute(self, statement, *args):
                if statement == "PRAGMA quick_check":
                    try:
                        return self.connection.execute(
                            "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL "
                            "SELECT x+1 FROM n WHERE x<50000000) "
                            "SELECT CASE WHEN sum(x)>0 THEN 'ok' END FROM n"
                        )
                    except sqlite3.OperationalError as error:
                        interrupted.append(error.sqlite_errorcode)
                        raise
                return self.connection.execute(statement, *args)

        def open_bank(path, **kwargs):
            connection = original_open(path, **kwargs)
            connections.append(connection)
            return SlowPreferredCheck(connection) if Path(path) == self.database else connection

        before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.database, other_path)]
        started = time.monotonic()
        with patch.object(console, "HEALTH_SCAN_BUDGET_SECONDS", 0.5), patch.object(
            console, "_open_db_read_only", side_effect=open_bank,
        ):
            results = console.scan_brain_databases(
                self.brains, preferred_database=self.database, preferred_project="demo",
            )
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual([row["project"] for row in results], ["demo", "small"])
        self.assertEqual(interrupted, [sqlite3.SQLITE_INTERRUPT])
        self.assertEqual(results[0]["scan_state"], "deferred")
        self.assertFalse(results[0]["ready"])
        self.assertEqual(results[1]["scan_state"], "ready", "a slow bank must not consume every bank's turn")
        self.assertEqual(results[1]["integrity"]["sqlite_quick_check"], "ok")
        self.assertEqual(results[1]["integrity"]["database_verification_evidence"]["source"], "live")
        self.assertTrue(results[1]["registry_complete"])
        self.assertNotIn(str(self.database.resolve()).casefold(), trusted_lifecycle._database_check_cache)
        self.assertEqual(before, [hashlib.sha256(path.read_bytes()).hexdigest() for path in (self.database, other_path)])
        for connection in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")
        self.assertTrue(self.check_lock().acquire(blocking=False))
        self.check_lock().release()
        retry = console.scan_brain_databases(self.brains, database=self.database, project="demo")
        self.assertEqual(retry[0]["integrity"]["sqlite_quick_check"], "ok")

    def test_corrupt_database_remains_an_error_not_a_timeout(self):
        corrupt = self.brains / "corrupt.sqlite"
        corrupt.write_bytes(b"not a SQLite database")
        results = console.scan_brain_databases(self.brains)
        failed = next(item for item in results if item["db_file"] == corrupt.name)
        self.assertEqual(failed["status"], "error")
        self.assertIn("not a database", failed["error"])
        self.assertFalse(failed["ready"])
        good = next(item for item in results if item["project"] == "demo")
        self.assertFalse(good["registry_complete"])
        self.assertFalse(good["ready"])

    def test_deferred_check_retains_completed_metadata_failures(self):
        connection = db.connect(self.database)
        try:
            connection.execute("UPDATE projects SET checkout_identity = 'different-checkout'")
            connection.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION + 1}")
            connection.commit()
        finally:
            connection.close()
        before = hashlib.sha256(self.database.read_bytes()).hexdigest()
        with patch.object(
            console, "_verified_quick_check",
            side_effect=trusted_lifecycle.DatabaseCheckTimeout("fixture budget"),
        ):
            result = console.scan_brain_databases(self.brains)[0]
        self.assertEqual(result["scan_state"], "deferred")
        self.assertFalse(result["ready"])
        self.assertEqual(result["integrity"].get("schema_version"), db.SCHEMA_VERSION + 1)
        self.assertEqual(result["integrity"]["binding"]["state"], "binding_drift")
        self.assertEqual(result["integrity"]["database_verification"], "deferred")
        self.assertEqual(result["integrity"]["status"], "attention_required")
        self.assertEqual(set(result["health_reasons"]), {
            "schema_mismatch", "binding_drift", "no_indexed_content", "database_verification_deferred",
        })
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), before)

    def test_metadata_only_cannot_claim_operational_readiness(self):
        connection = console._open_db_read_only(self.database)
        try:
            project = console._readonly_projects_list(connection)["projects"][0]
            result = console._readonly_project_health(
                connection, project, console.inspect_repository(self.repo),
                database=self.database, verify_database=False,
            )
        finally:
            connection.close()
        self.assertFalse(result["integrity"]["operationally_ready"])
        self.assertFalse(result["ready"])
        self.assertEqual(result["integrity"]["database_verification"], "deferred")

    def test_unbounded_inspection_does_not_misclassify_an_interrupt(self):
        error = sqlite3.OperationalError("interrupted")
        error.sqlite_errorcode = sqlite3.SQLITE_INTERRUPT
        connection = console._open_db_read_only(self.database)
        try:
            project = console._readonly_projects_list(connection)["projects"][0]
            with patch.object(console, "_verified_quick_check", side_effect=error):
                with self.assertRaisesRegex(sqlite3.OperationalError, "interrupted"):
                    console._readonly_project_health(
                        connection, project, console.inspect_repository(self.repo),
                        database=self.database,
                    )
        finally:
            connection.close()

    def test_completed_empty_project_explains_why_it_is_not_ready(self):
        result = console.scan_brain_databases(self.brains)[0]
        self.assertEqual(result["scan_state"], "ready")
        self.assertEqual(result["integrity"]["database_verification"], "verified")
        self.assertFalse(result["ready"])
        self.assertEqual(result["health_reasons"], ["no_indexed_content"])

    def test_deferred_check_retains_missing_root(self):
        connection = db.connect(self.database)
        try:
            connection.execute("UPDATE projects SET root_path = ?", (str(self.base / "missing-repo"),))
            connection.commit()
        finally:
            connection.close()
        with patch.object(
            console, "_verified_quick_check",
            side_effect=trusted_lifecycle.DatabaseCheckTimeout("fixture budget"),
        ):
            result = console.scan_brain_databases(self.brains)[0]
        self.assertEqual(result["scan_state"], "deferred")
        self.assertFalse(result["ready"])
        self.assertEqual(result["integrity"]["binding"]["state"], "bound_root_missing")
        self.assertIn("bound_root_missing", result["health_reasons"])

    def test_changed_database_discards_partial_metadata(self):
        def change_then_defer(*args, **kwargs):
            connection = sqlite3.connect(self.database)
            try:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                connection.execute(f"PRAGMA user_version = {version + 1}")
                connection.commit()
            finally:
                connection.close()
            raise trusted_lifecycle.DatabaseCheckTimeout("fixture mutation")

        with patch.object(console, "_verified_quick_check", side_effect=change_then_defer):
            result = console.scan_brain_databases(self.brains)[0]
        self.assertEqual(result["status"], "error")
        self.assertIn("database changed", result["error"])
        self.assertFalse(result["ready"])
        self.assertNotIn("schema_version", result.get("integrity", {}))

    def test_preferred_project_gets_the_shared_budget_without_repeating_discovery(self):
        other_path = self.brains / "z-last.sqlite"
        other = db.connect(other_path)
        try:
            db.init_project(other, "earlier", self.repo)
            db.init_project(other, "preferred", self.repo)
        finally:
            other.close()
        observed = []
        clock = [100.0]

        def exhaust_budget(connection, project_row, inspection, **kwargs):
            observed.append((kwargs["database"], project_row["name"]))
            clock[0] = kwargs["deadline"] + 0.01
            raise trusted_lifecycle.DatabaseCheckTimeout("fixture budget")

        with (
            patch.object(console, "HEALTH_SCAN_BUDGET_SECONDS", 0.25),
            patch.object(console.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(console, "scan_brain_registry", wraps=console.scan_brain_registry) as registry,
            patch.object(console, "_readonly_project_health", side_effect=exhaust_budget),
        ):
            results = console.scan_brain_databases(
                self.brains, preferred_database=other_path, preferred_project="preferred",
            )
        self.assertEqual(observed, [(other_path, "preferred"), (self.database, "demo")])
        self.assertEqual(registry.call_count, 1)
        self.assertEqual({item["project"] for item in results}, {"demo", "earlier", "preferred"})
        self.assertTrue(all(item["scan_state"] == "deferred" for item in results))
        self.assertTrue(all(item["root_duplicate"] and not item["ready"] for item in results))

    def test_duplicate_aggregate_http_refresh_defers_without_starting_another_scan(self):
        server, config, url = console.create_dashboard_server(
            Path(__file__).resolve().parents[1], self.brains, port=0,
        )
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.start()
        entered = threading.Event()
        release = threading.Event()
        responses = []
        errors = []
        original_scan = console.scan_brain_databases

        def blocked_scan(*args, **kwargs):
            if entered.is_set():
                raise AssertionError("duplicate scan started")
            entered.set()
            if not release.wait(3):
                raise AssertionError("fixture release missing")
            return original_scan(*args, **kwargs)

        def request():
            query = urlencode({"db_path": str(self.database), "project": "demo"})
            request = urllib.request.Request(
                url.split("/#", 1)[0] + "/api/projects?" + query,
                headers={"X-Rta-Smriti-Token": config.capability_token},
            )
            with urllib.request.urlopen(request, timeout=4) as response:
                return json.load(response)

        def first_request():
            try:
                responses.append(request())
            except Exception as error:
                errors.append(str(error))

        first = threading.Thread(target=first_request)
        try:
            with patch.object(console, "scan_brain_databases", side_effect=blocked_scan) as scan:
                first.start()
                self.assertTrue(entered.wait(2))
                try:
                    duplicate = request()
                    self.assertEqual(duplicate["status"], "partial")
                    self.assertEqual(duplicate["project_scan_state"], "deferred")
                    self.assertEqual(duplicate["projects"], [])
                    self.assertEqual(scan.call_count, 1)
                finally:
                    release.set()
                    first.join(timeout=4)
            self.assertFalse(first.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(len(responses[0]["projects"]), 1)
            self.assertEqual(len(request()["projects"]), 1)
            scan.assert_called_once_with(
                self.brains.resolve(), preferred_database=self.database.resolve(), preferred_project="demo",
            )
        finally:
            release.set()
            first.join(timeout=4)
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

    def test_aggregate_refresh_validates_access_and_releases_admission_after_failure(self):
        server, config, url = console.create_dashboard_server(
            Path(__file__).resolve().parents[1], self.brains, port=0,
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        base = url.split("/#", 1)[0] + "/api/projects"
        headers = {"X-Rta-Smriti-Token": config.capability_token}
        outside = db.connect(self.base / "outside.sqlite")
        outside.close()
        try:
            with patch.object(console, "scan_brain_databases") as scan:
                with self.assertRaises(urllib.error.HTTPError) as missing_auth:
                    urllib.request.urlopen(base, timeout=2)
                self.assertEqual(missing_auth.exception.code, 403)
                query = urlencode({"db_path": str(self.base / "outside.sqlite"), "project": "demo"})
                with self.assertRaises(urllib.error.HTTPError) as outside_root:
                    urllib.request.urlopen(urllib.request.Request(base + "?" + query, headers=headers), timeout=2)
                self.assertEqual(outside_root.exception.code, 400)
                scan.assert_not_called()
            with patch.object(console, "scan_brain_databases", side_effect=ValueError("fixture scan failed")):
                with self.assertRaises(urllib.error.HTTPError) as failed:
                    urllib.request.urlopen(urllib.request.Request(base, headers=headers), timeout=2)
                self.assertEqual(failed.exception.code, 400)
            with urllib.request.urlopen(urllib.request.Request(base, headers=headers), timeout=2) as response:
                recovered = json.load(response)
            self.assertEqual(len(recovered["projects"]), 1)
            self.assertNotEqual(recovered["project_scan_state"], "deferred")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_sqlite_busy_is_deferred_and_all_readers_are_closed(self):
        writer = sqlite3.connect(self.database)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=DELETE")
        writer.execute("BEGIN EXCLUSIVE")
        started = time.monotonic()
        try:
            results = console.scan_brain_databases(self.brains)
        finally:
            writer.rollback()
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(results[0]["status"], "deferred")
        self.assertFalse(results[0]["ready"])
        self.assertEqual(console.scan_brain_databases(self.brains)[0]["status"], "ok")

    def test_expired_budget_does_not_hide_identity_failure(self):
        with patch.object(console, "_verified_quick_check", side_effect=ValueError("identity changed")):
            result = console.scan_brain_databases(self.brains)[0]
        self.assertEqual(result["status"], "error")
        self.assertIn("identity changed", result["error"])

    def test_original_full_health_http_contract_finishes_and_releases_worker(self):
        server, config, url = console.create_dashboard_server(
            Path(__file__).resolve().parents[1], self.brains, port=0,
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        lock = self.check_lock()
        lock.acquire()
        try:
            request = urllib.request.Request(
                url.split("/#", 1)[0] + "/api/health",
                headers={"X-Rta-Smriti-Token": config.capability_token},
            )
            with (
                patch.object(console, "HEALTH_SCAN_BUDGET_SECONDS", 0.05),
                urllib.request.urlopen(request, timeout=2) as response,
            ):
                payload = json.load(response)
            self.assertEqual(payload["projects"][0]["scan_state"], "deferred")
            self.assertEqual(payload["project_scan_state"], "partial")
            self.assertFalse(payload["projects"][0]["ready"])
        finally:
            lock.release()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_automatic_lifecycle_is_read_only_and_defers_a_blocked_check(self):
        server, config, url = console.create_dashboard_server(
            Path(__file__).resolve().parents[1], self.brains, port=0,
        )
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        lock = self.check_lock()
        lock.acquire()
        try:
            query = urlencode({"db_path": str(self.database), "project": "demo"})
            request = urllib.request.Request(
                url.split("/#", 1)[0] + "/api/lifecycle?" + query,
                headers={"X-Rta-Smriti-Token": config.capability_token},
            )
            with (
                patch.object(console, "HEALTH_SCAN_BUDGET_SECONDS", 0.25),
                patch.object(console, "_open_db", side_effect=AssertionError("write bootstrap forbidden")),
                urllib.request.urlopen(request, timeout=1) as response,
            ):
                payload = json.load(response)
            self.assertEqual(payload["status"], "partial")
            self.assertEqual(payload["health_axes"]["database_health"]["state"], "deferred")
            self.assertFalse(payload["continuation_ready"])
            self.assertNotIn(str(self.repo), json.dumps(payload))
        finally:
            lock.release()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_lifecycle_sql_is_cancelled_without_cache_or_source_mutation(self):
        original_connect = sqlite3.connect
        connections = []
        interrupted = []

        class SlowConnection(sqlite3.Connection):
            def execute(self, statement, *args):
                if statement == "PRAGMA quick_check":
                    try:
                        return super().execute(
                            "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL "
                            "SELECT x+1 FROM n WHERE x<50000000) "
                            "SELECT CASE WHEN sum(x)>0 THEN 'ok' END FROM n"
                        )
                    except sqlite3.OperationalError as error:
                        interrupted.append(error.sqlite_errorcode)
                        raise
                return super().execute(statement, *args)

        def slow_connect(*args, **kwargs):
            connection = original_connect(*args, factory=SlowConnection, **kwargs)
            connections.append(connection)
            return connection

        before = hashlib.sha256(self.database.read_bytes()).hexdigest()
        started = time.monotonic()
        with patch.object(trusted_lifecycle.sqlite3, "connect", side_effect=slow_connect):
            with self.assertRaises(trusted_lifecycle.DatabaseCheckTimeout):
                trusted_lifecycle._read_only_database_state(
                    self.database, "demo", self.repo, deadline=started + 0.25,
                )
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(interrupted, [sqlite3.SQLITE_INTERRUPT])
        self.assertEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), before)
        for connection in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")
        self.assertNotIn(str(self.database.resolve()).casefold(), trusted_lifecycle._database_check_cache)
        self.assertTrue(self.check_lock().acquire(blocking=False))
        self.check_lock().release()
        retry = trusted_lifecycle._read_only_database_state(self.database, "demo", self.repo)
        self.assertTrue(retry["healthy"])

    def test_interactive_legacy_readiness_never_copies_the_database(self):
        original_connect = sqlite3.connect

        class NoBackupConnection(sqlite3.Connection):
            def backup(self, *args, **kwargs):
                raise AssertionError("automatic inspection must not copy a whole brain")

        def no_backup_connect(*args, **kwargs):
            return original_connect(*args, factory=NoBackupConnection, **kwargs)

        with (
            patch.object(trusted_lifecycle.sqlite3, "connect", side_effect=no_backup_connect),
            patch("rta_brain.continuity.operational_readiness", side_effect=sqlite3.OperationalError("no such table: legacy")),
        ):
            with self.assertRaisesRegex(trusted_lifecycle.DatabaseCheckTimeout, "explicit full verification"):
                trusted_lifecycle._read_only_operational_readiness(
                    self.database, "demo", self.repo, {},
                    expected_signature=trusted_lifecycle._database_stat_signature(self.database),
                    deadline=time.monotonic() + 0.5,
                )


if __name__ == "__main__":
    unittest.main()
