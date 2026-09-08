import sqlite3
import tempfile
import unittest
from pathlib import Path

from rta_brain.db import init_schema
from rta_brain.federation import store_event
from rta_brain.federation_crypto import (
    create_encrypted_event,
    create_identity,
    generate_scope_key,
)
from rta_brain.federation_governance import (
    ALL_CAPABILITIES,
    FederationAuthorizationError,
    add_peer,
    authorize_operation,
    create_scope,
    create_space,
    export_capability_event,
    federation_status,
    grant_capabilities,
    import_capability_event,
    open_current_scope_key,
    resolve_capability_conflict,
    revoke_capabilities,
    rotate_scope_key,
    validate_and_accept_event,
)

PASSPHRASE = b"correct horse battery staple"


def memory_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_schema(conn)
    conn.execute(
        "INSERT INTO projects(id, name, created_at) VALUES (1, 'atlas', '2026-09-07T00:00:00+00:00')"
    )
    return conn


class FederationGovernanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.owner = create_identity(root / "owner", passphrase=PASSPHRASE)
        self.writer = create_identity(root / "writer", passphrase=PASSPHRASE)
        self.reviewer = create_identity(root / "reviewer", passphrase=PASSPHRASE)
        self.conn = memory_connection()
        self.addCleanup(self.conn.close)
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
            label="Team memory",
        )
        add_peer(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            author=self.owner,
            peer=self.writer,
            label="Writer",
        )
        add_peer(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            author=self.owner,
            peer=self.reviewer,
            label="Reviewer",
        )

    def test_owner_bootstrap_has_every_capability(self):
        for capability in ALL_CAPABILITIES:
            result = authorize_operation(
                self.conn,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                peer_id=self.owner.identity_id,
                operation=capability,
            )
            self.assertTrue(result["allowed"], capability)

    def test_status_uses_explicit_health_axes_without_private_paths(self):
        rotate_scope_key(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            scope_key=generate_scope_key(),
        )
        status = federation_status(
            self.conn,
            project_id=1,
            actor_peer_id=self.owner.identity_id,
        )
        self.assertEqual(status["state"], "healthy")
        self.assertEqual(status["axes"]["federation"], "healthy")
        self.assertEqual(status["axes"]["relay"], "not_configured")
        self.assertEqual(status["space_count"], 1)
        self.assertEqual(status["scope_count"], 1)
        self.assertNotIn(str(Path(self.temp.name)), str(status))

    def test_status_distinguishes_recorded_transport_failure_from_idle_sync(self):
        rotate_scope_key(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            scope_key=generate_scope_key(),
        )
        self.conn.execute(
            "INSERT INTO federation_sync_cursors(project_id, space_id, transport_id, "
            "cursor, inventory_digest, state, updated_at) "
            "VALUES (1, ?, 'primary-relay', 'cursor-1', ?, 'error', ?)",
            (self.space["space_id"], "a" * 64, "2026-09-07T00:00:00+00:00"),
        )
        self.conn.commit()

        status = federation_status(self.conn, project_id=1)

        self.assertEqual(status["state"], "offline")
        self.assertEqual(status["axes"]["sync"], "offline")
        self.assertEqual(status["axes"]["relay"], "relay_down")
        self.assertFalse(status["operationally_ready"])

    def test_concurrent_incompatible_capability_events_fail_closed_until_resolution(self):
        for peer in (self.writer, self.reviewer):
            grant_capabilities(
                self.conn,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=None,
                author=self.owner,
                subject_peer_id=peer.identity_id,
                capabilities=("admin",),
            )
        target = create_identity(Path(self.temp.name) / "target", passphrase=PASSPHRASE)
        add_peer(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            author=self.owner,
            peer=target,
            label="Target",
        )
        grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=target.identity_id,
            capabilities=("read",),
        )
        branch = sqlite3.connect(":memory:")
        branch.row_factory = sqlite3.Row
        branch.execute("PRAGMA foreign_keys = ON")
        self.conn.backup(branch)
        self.addCleanup(branch.close)

        left = grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.writer,
            subject_peer_id=target.identity_id,
            capabilities=("read", "review"),
        )
        right = revoke_capabilities(
            branch,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.reviewer,
            subject_peer_id=target.identity_id,
        )
        wire = export_capability_event(
            branch,
            project_id=1,
            space_id=self.space["space_id"],
            event_id=right["event_id"],
        )
        imported = import_capability_event(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            encoded=wire,
        )
        self.assertEqual(imported["state"], "imported")

        blocked = authorize_operation(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            peer_id=target.identity_id,
            operation="read",
        )
        self.assertFalse(blocked["allowed"])
        self.assertEqual(blocked["reason"], "governance_conflict")
        self.assertEqual(set(blocked["conflicting_event_ids"]), {left["event_id"], right["event_id"]})
        status = federation_status(self.conn, project_id=1)
        self.assertEqual(status["state"], "conflict")
        self.assertEqual(status["axes"]["governance"], "conflict")
        self.assertEqual(status["governance_conflict_count"], 2)
        self.assertEqual(
            set(status["governance_conflicting_event_ids"]),
            {left["event_id"], right["event_id"]},
        )

        resolution = resolve_capability_conflict(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=target.identity_id,
            capabilities=("read", "review"),
        )
        self.assertTrue({left["event_id"], right["event_id"]}.issubset(resolution["parents"]))
        allowed = authorize_operation(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            peer_id=target.identity_id,
            operation="review",
        )
        self.assertTrue(allowed["allowed"])
        resolved_status = federation_status(self.conn, project_id=1)
        self.assertEqual(resolved_status["axes"]["governance"], "healthy")
        self.assertEqual(resolved_status["governance_conflict_count"], 0)

    def test_revoked_administrator_cannot_grant_from_a_stale_frontier(self):
        grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=None,
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
            capabilities=("admin",),
        )
        branch = sqlite3.connect(":memory:")
        branch.row_factory = sqlite3.Row
        branch.execute("PRAGMA foreign_keys = ON")
        self.conn.backup(branch)
        self.addCleanup(branch.close)

        revoke_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=None,
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
        )
        stale_grant = grant_capabilities(
            branch,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=None,
            author=self.writer,
            subject_peer_id=self.reviewer.identity_id,
            capabilities=("admin",),
        )
        encoded = export_capability_event(
            branch,
            project_id=1,
            space_id=self.space["space_id"],
            event_id=stale_grant["event_id"],
        )

        with self.assertRaisesRegex(FederationAuthorizationError, "current frontier"):
            import_capability_event(
                self.conn,
                project_id=1,
                space_id=self.space["space_id"],
                encoded=encoded,
            )

    def test_revocation_rotates_scope_keys_before_future_relay_events(self):
        grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
            capabilities=("read", "sync"),
        )
        rotate_scope_key(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            scope_key=generate_scope_key(),
        )

        result = revoke_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
        )

        self.assertEqual(result["rotated_scope_count"], 1)
        self.assertEqual(
            self.conn.execute(
                "SELECT MAX(epoch) FROM federation_scope_epochs WHERE scope_id = ?",
                (self.scope["scope_id"],),
            ).fetchone()[0],
            2,
        )
        self.assertIsNone(
            self.conn.execute(
                "SELECT 1 FROM federation_key_envelopes WHERE scope_id = ? "
                "AND epoch = 2 AND recipient_peer_id = ?",
                (self.scope["scope_id"], self.writer.identity_id),
            ).fetchone()
        )

    def test_scope_grant_is_least_privilege_and_all_six_surfaces_fail_closed(self):
        grant = grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.reviewer.identity_id,
            capabilities=("read", "review", "diagnose"),
        )
        self.assertEqual(grant["action"], "grant")

        for operation in ("read", "diagnose"):
            self.assertTrue(
                authorize_operation(
                    self.conn,
                    project_id=1,
                    space_id=self.space["space_id"],
                    scope_id=self.scope["scope_id"],
                    peer_id=self.reviewer.identity_id,
                    operation=operation,
                )["allowed"]
            )
        for operation in ("index", "context", "sync", "export"):
            result = authorize_operation(
                self.conn,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                peer_id=self.reviewer.identity_id,
                operation=operation,
            )
            self.assertFalse(result["allowed"], operation)
            self.assertEqual(result["reason"], "capability_missing")

    def test_revoked_peer_cannot_submit_new_event_from_old_frontier(self):
        grant = grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
            capabilities=("read", "write", "index", "sync"),
        )
        scope_key = generate_scope_key()
        accepted = create_encrypted_event(
            {"event_type": "memory.asserted", "text": "accepted before revocation"},
            identity=self.writer,
            scope_key=scope_key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=1,
            capability_event_id=grant["event_id"],
            parents=(),
            received_at="2026-09-07T00:00:00+00:00",
        )
        store_event(self.conn, project_id=1, envelope=accepted)
        result = validate_and_accept_event(
            self.conn,
            project_id=1,
            envelope=accepted,
            author_signing_public_key=self.writer.signing_public_bytes,
            scope_key=scope_key,
        )
        self.assertEqual(result["state"], "accepted")

        revoke_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
        )
        after = create_encrypted_event(
            {"event_type": "memory.asserted", "text": "must not be accepted"},
            identity=self.writer,
            scope_key=scope_key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=2,
            capability_event_id=grant["event_id"],
            parents=(accepted.event_id,),
            received_at="2026-09-07T00:01:00+00:00",
        )
        store_event(self.conn, project_id=1, envelope=after)

        with self.assertRaisesRegex(FederationAuthorizationError, "revoked"):
            validate_and_accept_event(
                self.conn,
                project_id=1,
                envelope=after,
                author_signing_public_key=self.writer.signing_public_bytes,
                scope_key=scope_key,
            )
        state = self.conn.execute(
            "SELECT validation_state, reason_code FROM federation_event_validation "
            "WHERE event_row_id = (SELECT id FROM federation_events WHERE event_id = ?)",
            (after.event_id,),
        ).fetchone()
        self.assertEqual(dict(state), {"validation_state": "quarantined", "reason_code": "peer_revoked"})

    def test_unknown_author_and_unknown_frontier_are_denied(self):
        result = authorize_operation(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            peer_id="f" * 64,
            operation="read",
        )
        self.assertEqual(result, {"allowed": False, "reason": "peer_unknown", "capabilities": []})

        grant = grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
            capabilities=("write",),
        )
        self.assertNotEqual(grant["event_id"], "f" * 64)

    def test_validation_requires_exact_storage_and_every_parent(self):
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
        missing_parent_id = "d" * 64
        child = create_encrypted_event(
            {"event_type": "memory.asserted", "object_id": "child", "text": "child"},
            identity=self.writer,
            scope_key=key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=1,
            capability_event_id=grant["event_id"],
            parents=(missing_parent_id,),
            received_at="2026-09-07T00:00:00+00:00",
        )
        pending = store_event(self.conn, project_id=1, envelope=child)
        self.assertEqual(pending["validation_state"], "pending_parent")
        result = validate_and_accept_event(
            self.conn,
            project_id=1,
            envelope=child,
            author_signing_public_key=self.writer.signing_public_bytes,
            scope_key=key,
        )
        self.assertEqual(result["state"], "pending_parent")

        unstored = create_encrypted_event(
            {"event_type": "memory.asserted", "object_id": "unstored", "text": "unstored"},
            identity=self.writer,
            scope_key=key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=2,
            capability_event_id=grant["event_id"],
            parents=(),
            received_at="2026-09-07T00:01:00+00:00",
        )
        with self.assertRaisesRegex(ValueError, "stored"):
            validate_and_accept_event(
                self.conn,
                project_id=1,
                envelope=unstored,
                author_signing_public_key=self.writer.signing_public_bytes,
                scope_key=key,
            )

    def test_rotation_excludes_revoked_peer_but_states_historical_limit(self):
        grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
            capabilities=("read", "write", "sync"),
        )
        first_key = generate_scope_key()
        first = rotate_scope_key(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            scope_key=first_key,
        )
        self.assertEqual(first["epoch"], 1)
        self.assertEqual(set(first["recipient_peer_ids"]), {self.owner.identity_id, self.writer.identity_id})
        self.assertEqual(
            open_current_scope_key(
                self.conn,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                recipient=self.writer,
            ),
            first_key,
        )

        revoke = revoke_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.writer.identity_id,
        )
        self.assertTrue(revoke["prior_plaintext_may_remain"])
        self.assertEqual(revoke["rotated_scope_count"], 1)
        self.assertEqual(len(revoke["rotation_event_ids"]), 1)
        automatic_epoch = self.conn.execute(
            "SELECT MAX(epoch) FROM federation_scope_epochs "
            "WHERE project_id = 1 AND space_id = ? AND scope_id = ?",
            (self.space["space_id"], self.scope["scope_id"]),
        ).fetchone()[0]
        self.assertEqual(automatic_epoch, 2)
        second_key = generate_scope_key()
        second = rotate_scope_key(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            scope_key=second_key,
        )
        self.assertEqual(second["epoch"], 3)
        self.assertEqual(second["recipient_peer_ids"], [self.owner.identity_id])
        self.assertTrue(second["prior_plaintext_may_remain"])

        with self.assertRaisesRegex(FederationAuthorizationError, "no scope key envelope"):
            open_current_scope_key(
                self.conn,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                recipient=self.writer,
            )

        status = federation_status(
            self.conn,
            project_id=1,
            actor_peer_id=self.writer.identity_id,
        )
        self.assertEqual(status["state"], "revoked")
        self.assertEqual(status["actor_access"]["state"], "revoked")
        self.assertEqual(status["actor_access"]["authorized_scope_count"], 0)
        self.assertEqual(status["axes"]["encryption"], "revoked")


if __name__ == "__main__":
    unittest.main()
