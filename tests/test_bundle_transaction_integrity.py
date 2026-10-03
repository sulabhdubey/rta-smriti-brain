import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import portability
from rta_brain.db import connect, init_project, init_schema, remember


class BundleTransactionIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle.json"
        source = connect(self.root / "source.sqlite")
        try:
            init_project(source, "atlas", str(self.root / "atlas"))
            remember(source, "Atlas decision one", project="atlas")
            remember(source, "Atlas decision two", project="atlas")
            portability.export_bundle(source, self.bundle, projects=["atlas"])
        finally:
            source.close()
        self.database = self.root / "target.sqlite"
        self.target = connect(self.database)
        init_schema(self.target)
        self.target.execute("CREATE TABLE other_writer_notes (text TEXT NOT NULL)")
        self.target.commit()

    def tearDown(self):
        self.target.close()
        self.temp.cleanup()

    def test_import_preserves_a_concurrent_writer_commit(self):
        attempted = threading.Event()
        finished = threading.Event()
        errors = []
        workers = []
        original = portability.remember

        def other_writer():
            try:
                with sqlite3.connect(self.database, timeout=5) as connection:
                    attempted.set()
                    connection.execute("INSERT INTO other_writer_notes VALUES ('concurrent note')")
                connection.close()
            except Exception as exc:
                errors.append(exc)
            finally:
                finished.set()

        def import_memory(*args, **kwargs):
            result = original(*args, **kwargs)
            if not workers:
                worker = threading.Thread(target=other_writer)
                workers.append(worker)
                worker.start()
                self.assertTrue(attempted.wait(2))
                # A snapshot-copy importer permits this commit, then overwrites it.
                # A transactional importer holds the writer until import commits.
                finished.wait(0.5)
            return result

        try:
            with patch.object(portability, "remember", side_effect=import_memory):
                result = portability.import_bundle(self.target, self.bundle)
        finally:
            for worker in workers:
                worker.join(timeout=7)
        self.assertTrue(finished.is_set())
        self.assertEqual(errors, [])
        self.assertEqual(result["memories"], 2)
        self.assertEqual(
            [row[0] for row in self.target.execute("SELECT text FROM other_writer_notes")],
            ["concurrent note"],
        )

    def test_interrupted_import_rolls_back_the_entire_bundle(self):
        original = portability.remember
        count = 0

        def interrupt_second_memory(*args, **kwargs):
            nonlocal count
            count += 1
            result = original(*args, **kwargs)
            if count == 2:
                raise KeyboardInterrupt("synthetic interrupted import")
            return result

        with patch.object(portability, "remember", side_effect=interrupt_second_memory):
            with self.assertRaises(KeyboardInterrupt):
                portability.import_bundle(self.target, self.bundle)
        self.assertFalse(self.target.in_transaction)
        self.assertEqual(self.target.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 0)
        self.assertEqual(self.target.execute("SELECT COUNT(*) FROM projects").fetchone()[0], 0)

    def test_import_leaves_callers_transaction_uncommitted(self):
        self.target.execute("INSERT INTO other_writer_notes VALUES ('pending note')")
        portability.import_bundle(self.target, self.bundle)
        self.assertTrue(self.target.in_transaction)
        with sqlite3.connect(self.database) as observer:
            self.assertEqual(observer.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 0)
            self.assertEqual(observer.execute("SELECT COUNT(*) FROM other_writer_notes").fetchone()[0], 0)
        observer.close()
        self.target.rollback()
        self.assertEqual(self.target.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 0)
        self.assertEqual(self.target.execute("SELECT COUNT(*) FROM other_writer_notes").fetchone()[0], 0)

    def test_failed_import_preserves_callers_pending_changes(self):
        self.target.execute("INSERT INTO other_writer_notes VALUES ('pending note')")
        with patch.object(portability, "remember", side_effect=RuntimeError("synthetic failure")):
            with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                portability.import_bundle(self.target, self.bundle)
        self.assertTrue(self.target.in_transaction)
        self.assertEqual(self.target.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 0)
        self.assertEqual(self.target.execute("SELECT COUNT(*) FROM projects").fetchone()[0], 0)
        self.assertEqual(self.target.execute("SELECT COUNT(*) FROM other_writer_notes").fetchone()[0], 1)
        self.target.commit()

    def test_conflict_failure_releases_writer_without_partial_import(self):
        portability.import_bundle(self.target, self.bundle)
        with self.assertRaisesRegex(ValueError, "project already exists"):
            portability.import_bundle(self.target, self.bundle, conflict="fail")
        self.assertFalse(self.target.in_transaction)
        self.assertEqual(self.target.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 2)
        with sqlite3.connect(self.database, timeout=1) as writer:
            writer.execute("INSERT INTO other_writer_notes VALUES ('after conflict')")
        writer.close()


if __name__ == "__main__":
    unittest.main()
