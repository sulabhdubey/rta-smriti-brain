import sqlite3
import tempfile
import unittest
from pathlib import Path

from rta_brain.db import init_schema
from rta_brain.federation_crypto import (
    create_identity,
    export_public_identity,
    import_public_identity,
)
from rta_brain.federation_governance import create_space
from rta_brain.federation_operator import (
    FederationPlanConflict,
    apply_federation_operation,
    federation_inventory,
    preview_federation_operation,
)

PASSPHRASE = b"correct horse battery staple"


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_schema(conn)
    conn.execute(
        "INSERT INTO projects(id, name, created_at) VALUES "
        "(1, 'atlas', '2026-09-07T00:00:00+00:00')"
    )
    return conn


class FederationOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.owner = create_identity(root / "owner", passphrase=PASSPHRASE)
        self.peer = create_identity(root / "peer", passphrase=PASSPHRASE)
        self.conn = connection()
        self.addCleanup(self.conn.close)
        self.space = create_space(
            self.conn,
            project_id=1,
            owner=self.owner,
            owner_key_reference="managed-local-identity:owner",
        )

    def test_preview_is_write_free_and_apply_records_immutable_receipt(self):
        before = self.conn.total_changes
        plan = preview_federation_operation(
            self.conn,
            project_id=1,
            action="scope-create",
            actor_peer_id=self.owner.identity_id,
            parameters={
                "space_id": self.space["space_id"],
                "kind": "team",
                "label": "Engineering memory",
            },
        )
        self.assertEqual(self.conn.total_changes, before)
        self.assertEqual(plan["state"], "preview")
        self.assertTrue(plan["confirmation_digest"])

        result = apply_federation_operation(
            self.conn,
            project_id=1,
            action="scope-create",
            actor=self.owner,
            parameters=plan["parameters"],
            confirmation_digest=plan["confirmation_digest"],
        )
        self.assertEqual(result["state"], "applied")
        self.assertEqual(result["result"]["kind"], "team")
        receipt = self.conn.execute(
            "SELECT * FROM federation_operation_receipts"
        ).fetchone()
        self.assertEqual(receipt["operation_id"], result["operation_id"])
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.conn.execute(
                "UPDATE federation_operation_receipts SET action = 'changed'"
            )

    def test_space_creation_uses_the_same_preview_and_atomic_receipt_contract(self):
        isolated = connection()
        self.addCleanup(isolated.close)
        plan = preview_federation_operation(
            isolated,
            project_id=1,
            action="space-create",
            actor_peer_id=self.owner.identity_id,
            parameters={},
        )
        self.assertEqual(plan["parameters"], {})
        self.assertEqual(
            isolated.execute("SELECT COUNT(*) FROM federation_spaces").fetchone()[0],
            0,
        )

        result = apply_federation_operation(
            isolated,
            project_id=1,
            action="space-create",
            actor=self.owner,
            parameters={},
            confirmation_digest=plan["confirmation_digest"],
        )

        self.assertEqual(result["state"], "applied")
        self.assertEqual(
            isolated.execute("SELECT COUNT(*) FROM federation_spaces").fetchone()[0],
            1,
        )
        self.assertEqual(
            isolated.execute(
                "SELECT COUNT(*) FROM federation_operation_receipts"
            ).fetchone()[0],
            1,
        )

    def test_stale_preview_is_rejected_before_mutation(self):
        plan = preview_federation_operation(
            self.conn,
            project_id=1,
            action="scope-create",
            actor_peer_id=self.owner.identity_id,
            parameters={
                "space_id": self.space["space_id"],
                "kind": "team",
                "label": "First",
            },
        )
        other = preview_federation_operation(
            self.conn,
            project_id=1,
            action="scope-create",
            actor_peer_id=self.owner.identity_id,
            parameters={
                "space_id": self.space["space_id"],
                "kind": "review",
                "label": "Other",
            },
        )
        apply_federation_operation(
            self.conn,
            project_id=1,
            action="scope-create",
            actor=self.owner,
            parameters=other["parameters"],
            confirmation_digest=other["confirmation_digest"],
        )
        with self.assertRaisesRegex(FederationPlanConflict, "changed after preview"):
            apply_federation_operation(
                self.conn,
                project_id=1,
                action="scope-create",
                actor=self.owner,
                parameters=plan["parameters"],
                confirmation_digest=plan["confirmation_digest"],
            )
        self.assertIsNone(
            self.conn.execute(
                "SELECT 1 FROM federation_scopes WHERE label = 'First'"
            ).fetchone()
        )

    def test_mutation_rolls_back_when_receipt_cannot_be_recorded(self):
        plan = preview_federation_operation(
            self.conn,
            project_id=1,
            action="scope-create",
            actor_peer_id=self.owner.identity_id,
            parameters={
                "space_id": self.space["space_id"],
                "kind": "team",
                "label": "Must roll back",
            },
        )
        self.conn.execute(
            """
            CREATE TEMP TRIGGER fail_federation_receipt
            BEFORE INSERT ON federation_operation_receipts
            BEGIN
                SELECT RAISE(ABORT, 'receipt unavailable');
            END
            """
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "receipt unavailable"):
            apply_federation_operation(
                self.conn,
                project_id=1,
                action="scope-create",
                actor=self.owner,
                parameters=plan["parameters"],
                confirmation_digest=plan["confirmation_digest"],
            )
        self.assertIsNone(
            self.conn.execute(
                "SELECT 1 FROM federation_scopes WHERE label = 'Must roll back'"
            ).fetchone()
        )

    def test_management_actions_share_one_bounded_operator_contract(self):
        scope = self._apply(
            "scope-create",
            {"space_id": self.space["space_id"], "kind": "team", "label": "Team"},
        )["result"]
        public_peer = import_public_identity(export_public_identity(self.peer))
        peer = self._apply(
            "peer-add",
            {
                "space_id": self.space["space_id"],
                "peer_id": public_peer.identity_id,
                "label": "Reviewer",
            },
            public_peer=public_peer,
        )["result"]
        self.assertEqual(peer["peer_id"], self.peer.identity_id)
        grant = self._apply(
            "capability-grant",
            {
                "space_id": self.space["space_id"],
                "scope_id": scope["scope_id"],
                "subject_peer_id": self.peer.identity_id,
                "capabilities": ["read", "review", "sync"],
            },
        )["result"]
        self.assertEqual(grant["action"], "grant")
        rotation = self._apply(
            "scope-rotate",
            {"space_id": self.space["space_id"], "scope_id": scope["scope_id"]},
        )["result"]
        self.assertEqual(rotation["epoch"], 1)
        revoked = self._apply(
            "capability-revoke",
            {
                "space_id": self.space["space_id"],
                "scope_id": scope["scope_id"],
                "subject_peer_id": self.peer.identity_id,
            },
        )["result"]
        self.assertTrue(revoked["prior_plaintext_may_remain"])
        inventory = federation_inventory(self.conn, project_id=1)
        self.assertEqual(inventory["counts"]["operation_receipts"], 5)
        self.assertNotIn(str(Path(self.temp.name)), str(inventory))

    def _apply(self, action, parameters, *, public_peer=None):
        plan = preview_federation_operation(
            self.conn,
            project_id=1,
            action=action,
            actor_peer_id=self.owner.identity_id,
            parameters=parameters,
        )
        return apply_federation_operation(
            self.conn,
            project_id=1,
            action=action,
            actor=self.owner,
            parameters=plan["parameters"],
            confirmation_digest=plan["confirmation_digest"],
            public_peer=public_peer,
        )


if __name__ == "__main__":
    unittest.main()
