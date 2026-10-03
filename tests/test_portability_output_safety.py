import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain.db import connect, init_project, remember
from rta_brain.portability import export_bundle, snapshot_create, snapshot_create_encrypted, snapshot_keygen


class PortabilityOutputSafetyTests(unittest.TestCase):
    def test_snapshot_output_cannot_replace_its_source_database(self):
        for encrypted in (False, True):
            with self.subTest(encrypted=encrypted), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                database = root / "brain.sqlite"
                connection = connect(database)
                init_project(connection, "atlas", str(root / "atlas"))
                remember(connection, "Preserve the source brain", project="atlas")
                connection.close()
                before = hashlib.sha256(database.read_bytes()).hexdigest()
                key = root / "key.txt"
                key.write_text("synthetic-passphrase-not-for-use", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "overlap"):
                    if encrypted:
                        snapshot_create_encrypted(database, database, passphrase_path=key)
                    else:
                        snapshot_create(database, database, key_path=key)
                self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)

    def test_key_pair_outputs_must_be_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "key.pem"
            with self.assertRaisesRegex(ValueError, "overlap"):
                snapshot_keygen(key, key)
            self.assertFalse(key.exists())

    def test_snapshot_sidecar_and_auth_collisions_fail_before_database_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "brain.sqlite"
            key = root / "key.txt"
            key.write_text("synthetic-passphrase-not-for-use", encoding="utf-8")
            for encrypted in (False, True):
                for output in (key, *(Path(f"{database}{suffix}") for suffix in ("-wal", "-shm", "-journal"))):
                    with self.subTest(encrypted=encrypted, output=output.name):
                        with patch("rta_brain.portability.sqlite3.connect") as connection:
                            with self.assertRaisesRegex(ValueError, "overlap"):
                                if encrypted:
                                    snapshot_create_encrypted(database, output, passphrase_path=key)
                                else:
                                    snapshot_create(database, output, key_path=key)
                            connection.assert_not_called()
                        self.assertEqual(key.read_text(encoding="utf-8"), "synthetic-passphrase-not-for-use")
                        if output != key:
                            self.assertFalse(output.exists())

    def test_auto_created_hmac_key_cannot_be_a_database_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "brain.sqlite"
            key = Path(f"{database}-wal")
            with self.assertRaisesRegex(ValueError, "overlap"):
                snapshot_create(database, root / "snapshot.rta", key_path=key)
            self.assertFalse(key.exists())

    def test_bundle_export_preserves_open_database_and_sidecars(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "brain.sqlite"
            connection = connect(database)
            try:
                init_project(connection, "atlas", str(root / "atlas"))
                remember(connection, "Preserve the source brain", project="atlas")
                for suffix in ("", "-wal", "-shm", "-journal"):
                    with self.subTest(suffix=suffix):
                        with self.assertRaisesRegex(ValueError, "overlap"):
                            export_bundle(connection, Path(f"{database}{suffix}"))
                self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 1)
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
