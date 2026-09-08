import sqlite3
import unittest

from rta_brain import db
from rta_brain.federation_schema import (
    FEDERATION_INDEXES,
    FEDERATION_TABLES,
    FEDERATION_TRIGGERS,
    migrate_federation_schema_v12,
    validate_federation_schema_v12,
)


def memory_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


class FederationSchemaTests(unittest.TestCase):
    def test_schema_version_is_v12(self):
        self.assertEqual(db.SCHEMA_VERSION, 12)

    def test_federation_schema_creates_and_validates_every_object(self):
        conn = memory_connection()
        self.addCleanup(conn.close)
        conn.execute(
            "CREATE TABLE projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)"
        )

        migrate_federation_schema_v12(conn)
        validate_federation_schema_v12(conn)

        objects = {
            (str(row["type"]), str(row["name"]))
            for row in conn.execute(
                "SELECT type, name FROM sqlite_master"
            )
        }
        for name in FEDERATION_TABLES:
            self.assertIn(("table", name), objects)
        for name in FEDERATION_INDEXES:
            self.assertIn(("index", name), objects)
        for name in FEDERATION_TRIGGERS:
            self.assertIn(("trigger", name), objects)

    def test_immutable_event_envelopes_cannot_be_updated_or_deleted(self):
        conn = memory_connection()
        self.addCleanup(conn.close)
        conn.execute(
            "CREATE TABLE projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)"
        )
        conn.execute("INSERT INTO projects(id, name) VALUES (1, 'atlas')")
        migrate_federation_schema_v12(conn)
        conn.execute(
            """
            INSERT INTO federation_events(
                project_id, space_id, scope_id, epoch, event_id,
                author_peer_id, author_sequence, capability_event_id, parents_json, nonce,
                ciphertext, ciphertext_sha256, signature, received_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "a" * 64,
                "b" * 64,
                1,
                "c" * 64,
                "d" * 64,
                1,
                "1" * 64,
                "[]",
                b"n" * 12,
                b"ciphertext",
                "e" * 64,
                b"s" * 64,
                "2026-09-07T00:00:00+00:00",
            ),
        )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            conn.execute(
                "UPDATE federation_events SET ciphertext = ? WHERE event_id = ?",
                (b"changed", "c" * 64),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            conn.execute("DELETE FROM federation_events WHERE event_id = ?", ("c" * 64,))

    def test_existing_v11_brain_requires_explicit_migration(self):
        conn = memory_connection()
        self.addCleanup(conn.close)
        db.init_schema(conn)
        federation_objects = sorted(FEDERATION_TRIGGERS) + sorted(FEDERATION_INDEXES)
        for name in federation_objects:
            object_type = "TRIGGER" if name in FEDERATION_TRIGGERS else "INDEX"
            conn.execute(f'DROP {object_type} "{name}"')
        for name in sorted(FEDERATION_TABLES, reverse=True):
            conn.execute(f'DROP TABLE "{name}"')
        conn.execute("PRAGMA user_version = 11")

        with self.assertRaises(db.SchemaMigrationRequiredError):
            db.init_schema(conn)

        db.init_schema(conn, allow_migration=True)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 12)
        validate_federation_schema_v12(conn)

    def test_validation_rejects_incomplete_schema(self):
        conn = memory_connection()
        self.addCleanup(conn.close)
        conn.execute(
            "CREATE TABLE projects(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)"
        )
        migrate_federation_schema_v12(conn)
        conn.execute("DROP TRIGGER federation_events_no_update")

        with self.assertRaisesRegex(ValueError, "federation schema v12 is incomplete"):
            validate_federation_schema_v12(conn)


if __name__ == "__main__":
    unittest.main()
