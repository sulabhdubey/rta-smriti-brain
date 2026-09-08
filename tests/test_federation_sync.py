import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain.db import init_schema
from rta_brain.federation import store_event
from rta_brain.federation_crypto import (
    create_encrypted_event,
    create_identity,
    generate_scope_key,
)
from rta_brain.federation_governance import (
    FederationAuthorizationError,
    add_peer,
    create_scope,
    create_space,
    grant_capabilities,
    rotate_scope_key,
    validate_and_accept_event,
)
from rta_brain.federation_transport import (
    FederationTransportError,
    FilesystemFederationRelay,
    apply_sync_operation,
    preview_sync_operation,
    pull_and_validate_from_relay,
    pull_from_relay,
    push_to_relay,
)

PASSPHRASE = b"correct horse battery staple"


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_schema(conn)
    conn.execute(
        "INSERT INTO projects(id, name, created_at) VALUES (1, 'atlas', '2026-09-07T00:00:00+00:00')"
    )
    return conn


class FederationSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.owner = create_identity(root / "owner", passphrase=PASSPHRASE)
        self.reader = create_identity(root / "reader", passphrase=PASSPHRASE)
        self.source = connection()
        self.addCleanup(self.source.close)
        self.space = create_space(
            self.source, project_id=1, owner=self.owner, owner_key_reference="identity/owner"
        )
        self.scope = create_scope(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            owner=self.owner,
            kind="team",
            label="Team",
        )
        add_peer(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            author=self.owner,
            peer=self.reader,
            label="Reader",
        )
        grant_capabilities(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.reader.identity_id,
            capabilities=("read",),
        )
        self.key = generate_scope_key()
        rotate_scope_key(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            scope_key=self.key,
        )
        self.destination = sqlite3.connect(":memory:")
        self.destination.row_factory = sqlite3.Row
        self.destination.execute("PRAGMA foreign_keys = ON")
        self.addCleanup(self.destination.close)
        self.source.backup(self.destination)
        self.relay = FilesystemFederationRelay(root / "relay")

    def _add_source_event(self, sequence: int, *, parents=()):
        event = create_encrypted_event(
            {
                "event_type": "memory.asserted",
                "object_id": f"memory-{sequence}",
                "text": f"memory {sequence}",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
            identity=self.owner,
            scope_key=self.key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=sequence,
            capability_event_id=self.space["bootstrap"]["event_id"],
            parents=parents,
            received_at=f"2026-09-07T00:{sequence:02d}:00+00:00",
        )
        store_event(self.source, project_id=1, envelope=event)
        validate_and_accept_event(
            self.source,
            project_id=1,
            envelope=event,
            author_signing_public_key=self.owner.signing_public_bytes,
            scope_key=self.key,
        )
        return event

    def test_unavailable_epoch_is_quarantined_and_cursor_advances(self):
        event = self._add_source_event(1)
        push_to_relay(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
        )
        with patch(
            "rta_brain.federation_transport.open_scope_key_for_epoch",
            side_effect=FederationAuthorizationError("scope key unavailable"),
        ):
            result = pull_and_validate_from_relay(
                self.destination,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                actor=self.owner,
                relay=self.relay,
                transport_id="fixture-relay",
            )

        self.assertEqual(result["accepted"], 0)
        self.assertEqual(result["quarantined"], 1)
        validation = self.destination.execute(
            "SELECT v.validation_state, v.reason_code FROM federation_events e "
            "JOIN federation_event_validation v ON v.event_row_id = e.id "
            "WHERE e.event_id = ?",
            (event.event_id,),
        ).fetchone()
        self.assertEqual(tuple(validation), ("quarantined", "key_epoch_unavailable"))
        self.assertIsNotNone(
            self.destination.execute(
                "SELECT 1 FROM federation_sync_cursors WHERE transport_id = 'fixture-relay'"
            ).fetchone()
        )

    def test_reordered_child_is_accepted_after_parent_arrives(self):
        parent = self._add_source_event(1)
        child = None
        for _attempt in range(128):
            candidate = create_encrypted_event(
                {
                    "event_type": "memory.asserted",
                    "object_id": "memory-child",
                    "text": "memory child",
                    "valid_from": "2026-09-07T00:00:00+00:00",
                    "privacy_class": "internal",
                    "epistemic_state": "observed",
                },
                identity=self.owner,
                scope_key=self.key,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                epoch=1,
                author_sequence=2,
                capability_event_id=self.space["bootstrap"]["event_id"],
                parents=(parent.event_id,),
                received_at="2026-09-07T00:02:00+00:00",
            )
            if candidate.event_id < parent.event_id:
                child = candidate
                break
        self.assertIsNotNone(child)
        store_event(self.source, project_id=1, envelope=child)
        validate_and_accept_event(
            self.source,
            project_id=1,
            envelope=child,
            author_signing_public_key=self.owner.signing_public_bytes,
            scope_key=self.key,
        )
        push_to_relay(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
        )

        first = pull_and_validate_from_relay(
            self.destination,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor=self.owner,
            relay=self.relay,
            transport_id="fixture-relay",
            limit=1,
        )
        second = pull_and_validate_from_relay(
            self.destination,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor=self.owner,
            relay=self.relay,
            transport_id="fixture-relay",
            limit=1,
        )

        self.assertEqual(first["pending_parent"], 1)
        self.assertEqual(second["accepted"], 2)
        states = {
            row[0]: row[1]
            for row in self.destination.execute(
                "SELECT e.event_id, v.validation_state FROM federation_events e "
                "JOIN federation_event_validation v ON v.event_row_id = e.id "
                "WHERE e.event_id IN (?, ?)",
                (parent.event_id, child.event_id),
            )
        }
        self.assertEqual(states, {parent.event_id: "accepted", child.event_id: "accepted"})

    def test_unknown_author_is_quarantined_without_blocking_the_batch(self):
        outsider = create_identity(Path(self.temp.name) / "outsider", passphrase=PASSPHRASE)
        event = create_encrypted_event(
            {
                "event_type": "memory.asserted",
                "object_id": "unknown-author",
                "text": "untrusted payload",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
            identity=outsider,
            scope_key=self.key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=1,
            capability_event_id=self.space["bootstrap"]["event_id"],
            parents=(),
            received_at="2026-09-07T00:03:00+00:00",
        )
        self.relay.put_event(event)

        result = pull_and_validate_from_relay(
            self.destination,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor=self.owner,
            relay=self.relay,
            transport_id="fixture-relay",
        )

        self.assertEqual(result["accepted"], 0)
        self.assertEqual(result["quarantined"], 1)
        validation = self.destination.execute(
            "SELECT v.validation_state, v.reason_code FROM federation_events e "
            "JOIN federation_event_validation v ON v.event_row_id = e.id "
            "WHERE e.event_id = ?",
            (event.event_id,),
        ).fetchone()
        self.assertEqual(tuple(validation), ("quarantined", "peer_unknown"))

    def test_unknown_key_epoch_is_quarantined_without_blocking_the_batch(self):
        event = create_encrypted_event(
            {
                "event_type": "memory.asserted",
                "object_id": "unknown-epoch",
                "text": "future encrypted payload",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
            identity=self.owner,
            scope_key=generate_scope_key(),
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=2,
            author_sequence=1,
            capability_event_id=self.space["bootstrap"]["event_id"],
            parents=(),
            received_at="2026-09-07T00:04:00+00:00",
        )
        self.relay.put_event(event)

        result = pull_and_validate_from_relay(
            self.destination,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor=self.owner,
            relay=self.relay,
            transport_id="fixture-relay",
        )

        self.assertEqual(result["accepted"], 0)
        self.assertEqual(result["quarantined"], 1)
        validation = self.destination.execute(
            "SELECT v.validation_state, v.reason_code FROM federation_events e "
            "JOIN federation_event_validation v ON v.event_row_id = e.id "
            "WHERE e.event_id = ?",
            (event.event_id,),
        ).fetchone()
        self.assertEqual(tuple(validation), ("quarantined", "key_epoch_unavailable"))

    def test_interrupted_push_is_idempotently_repairable(self):
        events = [self._add_source_event(index) for index in range(1, 4)]

        class InterruptingRelay:
            def __init__(self, delegate):
                self.delegate = delegate
                self.calls = 0

            def put_event(self, envelope):
                self.calls += 1
                if self.calls == 2:
                    raise FederationTransportError("simulated interruption")
                return self.delegate.put_event(envelope)

        with self.assertRaisesRegex(FederationTransportError, "interruption"):
            push_to_relay(
                self.source,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                actor_peer_id=self.owner.identity_id,
                relay=InterruptingRelay(self.relay),
            )
        self.assertEqual(len(self.relay.inventory(self.space["space_id"])), 1)

        repaired = push_to_relay(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
        )
        self.assertEqual(repaired["stored"], 2)
        self.assertEqual(repaired["already_present"], 1)
        self.assertEqual(self.relay.inventory(self.space["space_id"]), sorted(event.event_id for event in events))

    def test_corrupted_cursor_receipt_is_reconciled_from_relay_inventory(self):
        event = self._add_source_event(1)
        push_to_relay(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
        )
        self.destination.execute(
            "INSERT INTO federation_sync_cursors("
            "project_id, space_id, transport_id, cursor, inventory_digest, state, updated_at"
            ") VALUES (1, ?, 'fixture-relay', ?, ?, 'error', datetime('now'))",
            (self.space["space_id"], "f" * 64, "0" * 64),
        )
        self.destination.commit()

        result = pull_and_validate_from_relay(
            self.destination,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor=self.owner,
            relay=self.relay,
            transport_id="fixture-relay",
        )

        receipt = self.destination.execute(
            "SELECT cursor, inventory_digest, state FROM federation_sync_cursors "
            "WHERE project_id = 1 AND space_id = ? AND transport_id = 'fixture-relay'",
            (self.space["space_id"],),
        ).fetchone()
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(receipt["cursor"], event.event_id)
        self.assertEqual(len(receipt["inventory_digest"]), 64)
        self.assertEqual(receipt["state"], "complete")

    def test_preview_push_and_resumable_pull_converge_without_plaintext_relay(self):
        events = [self._add_source_event(index) for index in range(1, 4)]
        preview = push_to_relay(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
            preview=True,
        )
        self.assertEqual(preview["state"], "preview")
        self.assertEqual(preview["event_count"], 3)
        self.assertEqual(self.relay.inventory(self.space["space_id"]), [])

        pushed = push_to_relay(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
        )
        self.assertEqual(pushed["state"], "complete")
        relay_bytes = b"".join(
            self.relay.get_event(self.space["space_id"], event.event_id).encoded
            for event in events
        )
        self.assertNotIn(b"memory 1", relay_bytes)

        partial = pull_from_relay(
            self.destination,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
            transport_id="fixture-relay",
            limit=1,
        )
        self.assertEqual(partial["state"], "partial")
        self.assertEqual(partial["received"], 1)
        complete = pull_from_relay(
            self.destination,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
            transport_id="fixture-relay",
        )
        self.assertEqual(complete["state"], "complete")
        self.assertEqual(complete["received"], 2)
        source_ids = {
            row[0] for row in self.source.execute("SELECT event_id FROM federation_events")
        }
        destination_ids = {
            row[0] for row in self.destination.execute("SELECT event_id FROM federation_events")
        }
        self.assertEqual(source_ids, destination_ids)

    def test_pull_limit_is_applied_before_event_downloads(self):
        for index in range(1, 4):
            self._add_source_event(index)
        push_to_relay(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
        )

        class CountingRelay:
            def __init__(self, delegate):
                self.delegate = delegate
                self.get_calls = 0

            def inventory(self, space_id, scope_id=None):
                return self.delegate.inventory(space_id, scope_id=scope_id)

            def get_event(self, space_id, event_id):
                self.get_calls += 1
                return self.delegate.get_event(space_id, event_id)

        counting = CountingRelay(self.relay)
        result = pull_from_relay(
            self.destination,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=counting,
            transport_id="counting-relay",
            limit=1,
        )

        self.assertEqual(result["received"], 1)
        self.assertEqual(result["available"], 3)
        self.assertEqual(counting.get_calls, 1)

    def test_sync_requires_explicit_scope_capability(self):
        with self.assertRaisesRegex(FederationAuthorizationError, "sync"):
            pull_from_relay(
                self.destination,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                actor_peer_id=self.reader.identity_id,
                relay=self.relay,
                transport_id="fixture-relay",
            )

    def test_pull_rolls_back_events_when_cursor_receipt_cannot_be_written(self):
        event = self._add_source_event(1)
        push_to_relay(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor_peer_id=self.owner.identity_id,
            relay=self.relay,
        )
        self.destination.execute(
            """
            CREATE TEMP TRIGGER fail_federation_cursor
            BEFORE INSERT ON federation_sync_cursors
            BEGIN
                SELECT RAISE(ABORT, 'cursor unavailable');
            END
            """
        )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "cursor unavailable"):
            pull_from_relay(
                self.destination,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                actor_peer_id=self.owner.identity_id,
                relay=self.relay,
                transport_id="fixture-relay",
            )

        self.assertIsNone(
            self.destination.execute(
                "SELECT 1 FROM federation_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
        )

    def test_sync_apply_rejects_local_or_relay_drift_after_preview(self):
        first = self._add_source_event(1)
        plan = preview_sync_operation(
            self.source,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            actor=self.owner,
            relay=self.relay,
            action="push",
            transport_id="fixture-relay",
        )
        self._add_source_event(2)

        with self.assertRaisesRegex(FederationTransportError, "changed after preview"):
            apply_sync_operation(
                self.source,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                actor=self.owner,
                relay=self.relay,
                action="push",
                transport_id="fixture-relay",
                confirmation_digest=plan["confirmation_digest"],
            )

        self.assertEqual(self.relay.inventory(self.space["space_id"]), [])
        self.assertNotEqual(first.event_id, plan["confirmation_digest"])


if __name__ == "__main__":
    unittest.main()
