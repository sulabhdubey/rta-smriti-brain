import hashlib
import sqlite3
import unittest
from dataclasses import replace
from unittest.mock import patch

from rta_brain.db import init_schema
from rta_brain.federation import (
    FederationEventCollision,
    deterministic_event_order,
    record_projection_state,
    store_event,
)
from rta_brain.federation_types import (
    FederationEventEnvelope,
    canonical_json_bytes,
    parse_canonical_json,
)


def memory_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_schema(conn)
    conn.execute(
        "INSERT INTO projects(id, name, created_at) VALUES (1, 'atlas', '2026-09-07T00:00:00+00:00')"
    )
    return conn


def event(
    token: str,
    *,
    sequence: int,
    parents: tuple[str, ...] = (),
    author: str = "d",
) -> FederationEventEnvelope:
    ciphertext = f"ciphertext-{token}".encode("ascii")
    return FederationEventEnvelope(
        space_id="a" * 64,
        scope_id="b" * 64,
        epoch=1,
        event_id=token * 64,
        author_peer_id=author * 64,
        author_sequence=sequence,
        capability_event_id="1" * 64,
        parents=parents,
        nonce=bytes([ord(token)]) * 12,
        ciphertext=ciphertext,
        ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
        signature=b"s" * 64,
        received_at="2026-09-07T00:00:00+00:00",
    )


class FederationTypesTests(unittest.TestCase):
    def test_canonical_json_is_stable_and_ascii(self):
        left = canonical_json_bytes({"z": 1, "a": ["memory", True]})
        right = canonical_json_bytes({"a": ["memory", True], "z": 1})

        self.assertEqual(left, right)
        self.assertEqual(left, b'{"a":["memory",true],"z":1}')

    def test_parser_rejects_duplicate_keys_and_excessive_nesting(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            parse_canonical_json(b'{"scope":"a","scope":"b"}')
        with self.assertRaisesRegex(ValueError, "nesting"):
            canonical_json_bytes([[[[[[[[[0]]]]]]]]], max_depth=4)

    def test_envelope_rejects_digest_mismatch_and_self_parent(self):
        with self.assertRaisesRegex(ValueError, "ciphertext digest"):
            replace(event("c", sequence=1), ciphertext_sha256="f" * 64)
        with self.assertRaisesRegex(ValueError, "must not reference itself"):
            replace(event("c", sequence=1), parents=("c" * 64,))


class FederationStoreTests(unittest.TestCase):
    def setUp(self):
        self.conn = memory_connection()

    def tearDown(self):
        self.conn.close()

    def test_identical_event_is_idempotent_but_changed_same_id_is_collision(self):
        original = event("c", sequence=1)

        first = store_event(self.conn, project_id=1, envelope=original)
        second = store_event(self.conn, project_id=1, envelope=original)

        self.assertEqual(first["state"], "inserted")
        self.assertEqual(second["state"], "duplicate")
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM federation_events").fetchone()[0],
            1,
        )

        changed = replace(
            original,
            ciphertext=b"changed",
            ciphertext_sha256=hashlib.sha256(b"changed").hexdigest(),
        )
        with self.assertRaisesRegex(FederationEventCollision, "event id collision"):
            store_event(self.conn, project_id=1, envelope=changed)

    def test_per_space_event_count_is_bounded_before_persistent_storage(self):
        with patch("rta_brain.federation.MAX_EVENTS_PER_SPACE", 1, create=True):
            store_event(self.conn, project_id=1, envelope=event("c", sequence=1))
            with self.assertRaisesRegex(ValueError, "event count limit"):
                store_event(self.conn, project_id=1, envelope=event("e", sequence=2))

    def test_per_space_ciphertext_bytes_are_bounded_before_persistent_storage(self):
        with patch(
            "rta_brain.federation.MAX_EVENT_BYTES_PER_SPACE", 20, create=True
        ):
            store_event(self.conn, project_id=1, envelope=event("c", sequence=1))
            with self.assertRaisesRegex(ValueError, "byte limit"):
                store_event(self.conn, project_id=1, envelope=event("e", sequence=2))

    def test_missing_parent_is_explicit_and_becomes_ready_after_parent_arrives(self):
        parent = event("c", sequence=1)
        child = event("e", sequence=2, parents=(parent.event_id,))

        result = store_event(self.conn, project_id=1, envelope=child)
        self.assertEqual(result["validation_state"], "pending_parent")
        self.assertEqual(result["missing_parent_count"], 1)

        store_event(self.conn, project_id=1, envelope=parent)
        ordered = deterministic_event_order(self.conn, project_id=1, space_id=parent.space_id)

        self.assertEqual([item["event_id"] for item in ordered], [parent.event_id, child.event_id])

    def test_author_sequence_collision_is_rejected_and_recorded_without_payload(self):
        store_event(self.conn, project_id=1, envelope=event("c", sequence=1))

        with self.assertRaisesRegex(FederationEventCollision, "author sequence collision"):
            store_event(self.conn, project_id=1, envelope=event("e", sequence=1))

        receipt = self.conn.execute(
            "SELECT reason_code, encoded_bytes FROM federation_quarantine"
        ).fetchone()
        self.assertEqual(receipt["reason_code"], "author_sequence_collision")
        self.assertGreater(receipt["encoded_bytes"], 0)
        columns = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(federation_quarantine)")
        }
        self.assertNotIn("payload", columns)
        self.assertNotIn("ciphertext", columns)

    def test_deterministic_order_preserves_concurrent_events(self):
        root = event("c", sequence=1)
        left = event("e", sequence=2, parents=(root.event_id,))
        right = event("f", sequence=1, parents=(root.event_id,), author="9")
        for item in (right, root, left):
            store_event(self.conn, project_id=1, envelope=item)

        ordered = deterministic_event_order(self.conn, project_id=1, space_id=root.space_id)

        self.assertEqual(ordered[0]["event_id"], root.event_id)
        self.assertEqual(
            {item["event_id"] for item in ordered[1:]},
            {left.event_id, right.event_id},
        )

    def test_projection_state_is_rebuildable_and_digest_bound(self):
        first = record_projection_state(
            self.conn,
            project_id=1,
            space_id="a" * 64,
            projection_name="truth",
            accepted_event_count=2,
            head_digest="c" * 64,
            state="partial",
        )
        second = record_projection_state(
            self.conn,
            project_id=1,
            space_id="a" * 64,
            projection_name="truth",
            accepted_event_count=3,
            head_digest="e" * 64,
            state="ready",
        )

        self.assertEqual(first["state"], "partial")
        self.assertEqual(second["state"], "ready")
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM federation_projections").fetchone()[0],
            1,
        )


if __name__ == "__main__":
    unittest.main()
