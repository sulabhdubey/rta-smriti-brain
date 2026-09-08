import sqlite3
import tempfile
import unittest
from pathlib import Path

from rta_brain.db import init_schema
from rta_brain.federation import store_event
from rta_brain.federation_crypto import (
    FederationIdentity,
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
    revoke_capabilities,
    rotate_scope_key,
    validate_and_accept_event,
)
from rta_brain.federation_operator import (
    apply_federation_operation,
    federation_inventory,
    preview_federation_operation,
)
from rta_brain.federation_quarantine import (
    promote_quarantined_event,
    reject_quarantined_event,
)

PASSPHRASE = b"correct horse battery staple"


class FederationQuarantineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.owner = create_identity(root / "owner", passphrase=PASSPHRASE)
        self.writer = create_identity(root / "writer", passphrase=PASSPHRASE)
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.addCleanup(self.conn.close)
        init_schema(self.conn)
        self.conn.execute(
            "INSERT INTO projects(id, name, created_at) VALUES "
            "(1, 'atlas', '2026-09-07T00:00:00+00:00')"
        )
        self.space = create_space(
            self.conn,
            project_id=1,
            owner=self.owner,
            owner_key_reference="identity/owner",
        )
        self.scope = create_scope(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            owner=self.owner,
            kind="team",
            label="Team",
        )
        add_peer(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            author=self.owner,
            peer=self.writer,
            label="Writer",
        )

    def _quarantine_after_revocation(self):
        grant = grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
            capabilities=("read", "write"),
        )
        key = generate_scope_key()
        rotate_scope_key(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            scope_key=key,
        )
        event = create_encrypted_event(
            {"event_type": "memory.asserted", "text": "requires operator review"},
            identity=self.writer,
            scope_key=key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=1,
            capability_event_id=grant["event_id"],
            parents=(),
            received_at="2026-09-07T00:00:00+00:00",
        )
        revoke_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
        )
        store_event(self.conn, project_id=1, envelope=event)
        with self.assertRaises(FederationAuthorizationError):
            validate_and_accept_event(
                self.conn,
                project_id=1,
                envelope=event,
                author_signing_public_key=self.writer.signing_public_bytes,
                scope_key=key,
            )
        quarantine = self.conn.execute(
            "SELECT id FROM federation_quarantine WHERE claimed_event_id = ?",
            (event.event_id,),
        ).fetchone()
        self.assertIsNotNone(quarantine)
        return event, key, int(quarantine["id"])

    def test_admin_rejection_is_append_only_and_does_not_delete_evidence(self):
        event, _, quarantine_id = self._quarantine_after_revocation()
        receipt = reject_quarantined_event(
            self.conn,
            project_id=1,
            quarantine_id=quarantine_id,
            actor=self.owner,
            reason="Rejected after explicit review",
        )
        self.assertEqual(receipt["state"], "rejected")
        self.assertIsNotNone(
            self.conn.execute(
                "SELECT 1 FROM federation_events WHERE event_id = ?", (event.event_id,)
            ).fetchone()
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.conn.execute(
                "DELETE FROM federation_quarantine_receipts WHERE disposition_id = ?",
                (receipt["disposition_id"],),
            )
        self.conn.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            reject_quarantined_event(
                self.conn,
                project_id=1,
                quarantine_id=quarantine_id,
                actor=self.owner,
                reason="A quarantine record cannot receive two final dispositions",
            )
        counts = federation_inventory(self.conn, project_id=1)["counts"]
        self.assertEqual(counts["quarantine_pending"], 0)
        self.assertEqual(counts["quarantine_rejected"], 1)
        self.assertEqual(counts["quarantine_promoted"], 0)

    def test_quarantine_rejection_uses_preview_bound_operator_receipt(self):
        _, _, quarantine_id = self._quarantine_after_revocation()
        parameters = {
            "quarantine_id": quarantine_id,
            "reason": "Explicit security review rejected the event",
        }
        plan = preview_federation_operation(
            self.conn,
            project_id=1,
            action="quarantine-reject",
            actor_peer_id=self.owner.identity_id,
            parameters=parameters,
        )
        result = apply_federation_operation(
            self.conn,
            project_id=1,
            action="quarantine-reject",
            actor=self.owner,
            parameters=parameters,
            confirmation_digest=plan["confirmation_digest"],
        )

        self.assertEqual(result["state"], "applied")
        self.assertEqual(result["result"]["state"], "rejected")
        self.assertEqual(
            federation_inventory(self.conn, project_id=1)["counts"]["quarantine_pending"],
            0,
        )

    def test_promotion_requires_successful_revalidation_and_records_receipt(self):
        event, key, quarantine_id = self._quarantine_after_revocation()
        grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
            capabilities=("read", "write"),
        )
        result = promote_quarantined_event(
            self.conn,
            project_id=1,
            quarantine_id=quarantine_id,
            actor=self.owner,
            envelope=event,
            author_signing_public_key=self.writer.signing_public_bytes,
            scope_key=key,
            reason="Author was explicitly readmitted and evidence was revalidated",
        )
        self.assertEqual(result["state"], "promoted")
        state = self.conn.execute(
            "SELECT validation_state FROM federation_event_validation "
            "WHERE event_row_id = (SELECT id FROM federation_events WHERE event_id = ?)",
            (event.event_id,),
        ).fetchone()
        self.assertEqual(state["validation_state"], "accepted")
        counts = federation_inventory(self.conn, project_id=1)["counts"]
        self.assertEqual(counts["quarantine_pending"], 0)
        self.assertEqual(counts["quarantine_rejected"], 0)
        self.assertEqual(counts["quarantine_promoted"], 1)

    def test_direct_promotion_binds_signature_key_to_claimed_author(self):
        grant = grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
            capabilities=("read", "write"),
        )
        key = generate_scope_key()
        rotate_scope_key(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            scope_key=key,
        )
        substituted = FederationIdentity(
            identity_id=self.writer.identity_id,
            signing_private_key=self.owner.signing_private_key,
            envelope_private_key=self.owner.envelope_private_key,
        )
        event = create_encrypted_event(
            {"event_type": "memory.asserted", "text": "forged attribution"},
            identity=substituted,
            scope_key=key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=1,
            capability_event_id=grant["event_id"],
            parents=(),
            received_at="2026-09-07T00:00:00+00:00",
        )
        store_event(self.conn, project_id=1, envelope=event)
        self.conn.execute(
            "UPDATE federation_event_validation SET validation_state = 'quarantined', "
            "reason_code = 'signature_invalid' WHERE event_row_id = "
            "(SELECT id FROM federation_events WHERE event_id = ?)",
            (event.event_id,),
        )
        self.conn.execute(
            "INSERT INTO federation_quarantine(project_id, space_id, claimed_event_id, "
            "reason_code, envelope_sha256, encoded_bytes, state, recorded_at) "
            "VALUES (1, ?, ?, 'signature_invalid', ?, ?, 'pending', datetime('now'))",
            (
                event.space_id,
                event.event_id,
                event.envelope_sha256,
                len(event.encoded),
            ),
        )
        quarantine_id = int(
            self.conn.execute(
                "SELECT id FROM federation_quarantine WHERE claimed_event_id = ?",
                (event.event_id,),
            ).fetchone()[0]
        )

        with self.assertRaisesRegex(FederationAuthorizationError, "author key"):
            promote_quarantined_event(
                self.conn,
                project_id=1,
                quarantine_id=quarantine_id,
                actor=self.owner,
                envelope=event,
                author_signing_public_key=self.owner.signing_public_bytes,
                scope_key=key,
                reason="must not substitute the claimed author key",
            )

    def test_quarantine_promotion_uses_preview_bound_operator_receipt(self):
        _, _, quarantine_id = self._quarantine_after_revocation()
        grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
            capabilities=("read", "write"),
        )
        parameters = {
            "quarantine_id": quarantine_id,
            "reason": "Author was readmitted and evidence passed cryptographic review",
        }
        plan = preview_federation_operation(
            self.conn,
            project_id=1,
            action="quarantine-promote",
            actor_peer_id=self.owner.identity_id,
            parameters=parameters,
        )
        result = apply_federation_operation(
            self.conn,
            project_id=1,
            action="quarantine-promote",
            actor=self.owner,
            parameters=parameters,
            confirmation_digest=plan["confirmation_digest"],
        )

        self.assertEqual(result["state"], "applied")
        self.assertEqual(result["result"]["state"], "promoted")
        counts = federation_inventory(self.conn, project_id=1)["counts"]
        self.assertEqual(counts["quarantine_pending"], 0)
        self.assertEqual(counts["quarantine_promoted"], 1)


if __name__ == "__main__":
    unittest.main()
