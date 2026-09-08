import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from rta_brain.db import init_schema
from rta_brain.federation import store_event
from rta_brain.federation_crypto import (
    create_encrypted_event,
    create_identity,
    export_public_identity,
    generate_scope_key,
    import_public_identity,
)
from rta_brain.federation_governance import (
    add_public_peer,
    create_scope,
    create_space,
    export_capability_event,
    federation_status,
    grant_capabilities,
    import_capability_event,
    open_current_scope_key,
    revoke_capabilities,
    rotate_scope_key,
    validate_and_accept_event,
)
from rta_brain.federation_invitation import (
    FederationInvitationError,
    accept_invitation_bundle,
    create_invitation_bundle,
    expire_invitation_bundle,
    preview_invitation_bundle,
    refresh_enrollment_bundle,
    reject_invitation_bundle,
)
from rta_brain.federation_projection import rebuild_domain_projection
from rta_brain.federation_transport import (
    FilesystemFederationRelay,
    pull_and_validate_from_relay,
    push_to_relay,
)

PASSPHRASE = b"correct horse battery staple"


def database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_schema(conn)
    conn.execute(
        "INSERT INTO projects(id, name, created_at) VALUES (1, 'atlas', '2026-09-07T00:00:00+00:00')"
    )
    return conn


class FederationInvitationTests(unittest.TestCase):
    def test_refresh_rejects_a_bundle_signed_before_owner_revocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = create_identity(root / "owner", passphrase=PASSPHRASE)
            admin = create_identity(root / "admin", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            owner_db = database()
            recipient_db = database()
            self.addCleanup(owner_db.close)
            self.addCleanup(recipient_db.close)
            space = create_space(
                owner_db,
                project_id=1,
                owner=owner,
                owner_key_reference="identity/owner",
            )
            for identity, label in ((admin, "Admin"), (recipient, "Recipient")):
                add_public_peer(
                    owner_db,
                    project_id=1,
                    space_id=space["space_id"],
                    author=owner,
                    peer=import_public_identity(export_public_identity(identity)),
                    label=label,
                )
            grant_capabilities(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=None,
                author=owner,
                subject_peer_id=admin.identity_id,
                capabilities=("admin",),
            )
            scope = create_scope(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="team",
                label="Team",
            )
            grant_capabilities(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                subject_peer_id=recipient.identity_id,
                capabilities=("read",),
            )
            rotate_scope_key(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                scope_key=generate_scope_key(),
            )
            recipient_public = import_public_identity(export_public_identity(recipient))
            initial = create_invitation_bundle(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                recipient=recipient_public,
                scope_ids=(scope["scope_id"],),
                expires_at=(datetime.now(UTC) + timedelta(hours=1)).replace(
                    microsecond=0
                ).isoformat(),
            )
            accept_invitation_bundle(
                recipient_db,
                project_id=1,
                encoded=initial,
                recipient=recipient,
                recipient_key_reference="identity/recipient",
            )

            rotate_scope_key(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                scope_key=generate_scope_key(),
            )
            stale_refresh = create_invitation_bundle(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                recipient=recipient_public,
                scope_ids=(scope["scope_id"],),
                expires_at=(datetime.now(UTC) + timedelta(hours=1)).replace(
                    microsecond=0
                ).isoformat(),
            )
            revocation = revoke_capabilities(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=None,
                author=admin,
                subject_peer_id=owner.identity_id,
            )
            import_capability_event(
                recipient_db,
                project_id=1,
                space_id=space["space_id"],
                encoded=export_capability_event(
                    owner_db,
                    project_id=1,
                    space_id=space["space_id"],
                    event_id=revocation["event_id"],
                ),
            )

            with self.assertRaisesRegex(FederationInvitationError, "owner.*authorized"):
                refresh_enrollment_bundle(
                    recipient_db,
                    project_id=1,
                    encoded=stale_refresh,
                    recipient=recipient,
                    recipient_key_reference="identity/recipient",
                )

    def test_invitation_epoch_requires_its_authorized_rotation_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = create_identity(root / "owner", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            owner_db = database()
            recipient_db = database()
            self.addCleanup(owner_db.close)
            self.addCleanup(recipient_db.close)
            space = create_space(
                owner_db,
                project_id=1,
                owner=owner,
                owner_key_reference="identity/owner",
            )
            recipient_public = import_public_identity(export_public_identity(recipient))
            add_public_peer(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                peer=recipient_public,
                label="Recipient",
            )
            scope = create_scope(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="team",
                label="Team",
            )
            grant_capabilities(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                subject_peer_id=recipient.identity_id,
                capabilities=("read",),
            )
            rotation = rotate_scope_key(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                scope_key=generate_scope_key(),
            )
            trigger_names = [
                str(row["name"])
                for row in owner_db.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND tbl_name = 'federation_capability_events'"
                )
            ]
            for name in trigger_names:
                owner_db.execute(f'DROP TRIGGER "{name}"')  # nosec B608 - names come from SQLite schema
            owner_db.execute(
                "DELETE FROM federation_capability_events WHERE event_id = ?",
                (rotation["rotation_event_id"],),
            )
            malicious = create_invitation_bundle(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                recipient=recipient_public,
                scope_ids=(scope["scope_id"],),
                expires_at=(datetime.now(UTC) + timedelta(hours=1)).replace(
                    microsecond=0
                ).isoformat(),
            )

            with self.assertRaisesRegex(FederationInvitationError, "rotation event"):
                accept_invitation_bundle(
                    recipient_db,
                    project_id=1,
                    encoded=malicious,
                    recipient=recipient,
                    recipient_key_reference="identity/recipient",
                )

    def test_reject_and_expire_are_verified_immutable_local_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = create_identity(root / "owner", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            owner_db = database()
            recipient_db = database()
            self.addCleanup(owner_db.close)
            self.addCleanup(recipient_db.close)
            space = create_space(
                owner_db,
                project_id=1,
                owner=owner,
                owner_key_reference="identity/owner",
            )
            recipient_public = import_public_identity(export_public_identity(recipient))
            add_public_peer(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                peer=recipient_public,
                label="Reviewer device",
            )
            scope = create_scope(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="review",
                label="Review",
            )
            grant_capabilities(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                subject_peer_id=recipient.identity_id,
                capabilities=("read",),
            )
            rotate_scope_key(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                scope_key=generate_scope_key(),
            )
            valid = create_invitation_bundle(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                recipient=recipient_public,
                scope_ids=(scope["scope_id"],),
                expires_at=(datetime.now(UTC) + timedelta(hours=1)).replace(microsecond=0).isoformat(),
            )
            rejected = reject_invitation_bundle(
                recipient_db,
                project_id=1,
                encoded=valid,
                recipient=recipient,
            )
            self.assertEqual(rejected["state"], "rejected")
            self.assertIsNone(
                recipient_db.execute(
                    "SELECT 1 FROM federation_spaces WHERE project_id = 1"
                ).fetchone()
            )
            with self.assertRaisesRegex(FederationInvitationError, "not expired"):
                expire_invitation_bundle(
                    recipient_db,
                    project_id=1,
                    encoded=valid,
                    recipient=recipient,
                )

            expired = create_invitation_bundle(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                recipient=recipient_public,
                scope_ids=(scope["scope_id"],),
                expires_at=(datetime.now(UTC) + timedelta(seconds=1)).replace(microsecond=0).isoformat(),
            )
            import time
            time.sleep(1.1)
            expiry = expire_invitation_bundle(
                recipient_db,
                project_id=1,
                encoded=expired,
                recipient=recipient,
            )
            self.assertEqual(expiry["state"], "expired")
            actions = {
                row["action"]
                for row in recipient_db.execute(
                    "SELECT action FROM federation_invitation_receipts"
                )
            }
            self.assertEqual(actions, {"rejected", "expired"})

    def test_independent_peer_accepts_signed_encrypted_selective_invitation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = create_identity(root / "owner", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            outsider = create_identity(root / "outsider", passphrase=PASSPHRASE)
            owner_db = database()
            recipient_db = database()
            self.addCleanup(owner_db.close)
            self.addCleanup(recipient_db.close)
            space = create_space(
                owner_db,
                project_id=1,
                owner=owner,
                owner_key_reference="identity/owner",
            )
            scope = create_scope(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="review",
                label="Internal Atlas review",
            )
            recipient_public = import_public_identity(export_public_identity(recipient))
            add_public_peer(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                peer=recipient_public,
                label="Reviewer device",
            )
            grant_capabilities(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                subject_peer_id=recipient.identity_id,
                capabilities=("read", "review", "sync", "index"),
            )
            scope_key = generate_scope_key()
            rotate_scope_key(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                scope_key=scope_key,
            )
            omitted_scope = create_scope(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="custom",
                label="Omitted private scope",
            )
            grant_capabilities(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=omitted_scope["scope_id"],
                author=owner,
                subject_peer_id=recipient.identity_id,
                capabilities=("read",),
            )
            expires_at = (datetime.now(UTC) + timedelta(hours=1)).replace(
                microsecond=0
            ).isoformat()
            encoded = create_invitation_bundle(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                recipient=recipient_public,
                scope_ids=(scope["scope_id"],),
                expires_at=expires_at,
            )

            self.assertNotIn(b"Internal Atlas review", encoded)
            preview = preview_invitation_bundle(encoded, recipient=recipient)
            self.assertEqual(preview["space_id"], space["space_id"])
            self.assertEqual(preview["scope_count"], 1)
            self.assertEqual(preview["recipient_peer_id"], recipient.identity_id)
            self.assertTrue(preview["requires_fingerprint_verification"])
            self.assertNotIn("payload", preview)

            accepted = accept_invitation_bundle(
                recipient_db,
                project_id=1,
                encoded=encoded,
                recipient=recipient,
                recipient_key_reference="identity/recipient",
            )
            self.assertEqual(accepted["state"], "accepted")
            self.assertEqual(
                open_current_scope_key(
                    recipient_db,
                    project_id=1,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    recipient=recipient,
                ),
                scope_key,
            )
            status = federation_status(
                recipient_db, project_id=1, actor_peer_id=recipient.identity_id
            )
            self.assertEqual(status["state"], "healthy")
            self.assertEqual(status["peer_count"], 2)
            self.assertIsNone(
                recipient_db.execute(
                    "SELECT 1 FROM federation_scopes WHERE scope_id = ?",
                    (omitted_scope["scope_id"],),
                ).fetchone()
            )
            self.assertIsNone(
                recipient_db.execute(
                    "SELECT 1 FROM federation_capability_events WHERE scope_id = ?",
                    (omitted_scope["scope_id"],),
                ).fetchone()
            )
            receipt = recipient_db.execute(
                "SELECT action FROM federation_invitation_receipts WHERE direction = 'inbound'"
            ).fetchone()
            self.assertEqual(receipt["action"], "accepted")

            refreshed_scope_key = generate_scope_key()
            rotate_scope_key(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                scope_key=refreshed_scope_key,
            )
            refresh_bundle = create_invitation_bundle(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                recipient=recipient_public,
                scope_ids=(scope["scope_id"],),
                expires_at=(datetime.now(UTC) + timedelta(hours=1)).replace(
                    microsecond=0
                ).isoformat(),
            )
            refreshed = refresh_enrollment_bundle(
                recipient_db,
                project_id=1,
                encoded=refresh_bundle,
                recipient=recipient,
                recipient_key_reference="identity/recipient",
            )
            self.assertEqual(refreshed["state"], "refreshed")
            self.assertEqual(
                open_current_scope_key(
                    recipient_db,
                    project_id=1,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    recipient=recipient,
                ),
                refreshed_scope_key,
            )

            event = create_encrypted_event(
                {
                    "event_type": "memory.asserted",
                    "object_id": "atlas-boundary",
                    "text": "Atlas keeps the HTTP boundary thin",
                    "valid_from": "2026-09-07T00:00:00+00:00",
                    "privacy_class": "internal",
                    "epistemic_state": "observed",
                },
                identity=owner,
                scope_key=scope_key,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                epoch=1,
                author_sequence=1,
                capability_event_id=space["bootstrap"]["event_id"],
                parents=(),
                received_at="2026-09-07T00:00:00+00:00",
            )
            store_event(owner_db, project_id=1, envelope=event)
            validate_and_accept_event(
                owner_db,
                project_id=1,
                envelope=event,
                author_signing_public_key=owner.signing_public_bytes,
                scope_key=scope_key,
            )
            relay = FilesystemFederationRelay(root / "relay")
            push_to_relay(
                owner_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                actor_peer_id=owner.identity_id,
                relay=relay,
            )
            synced = pull_and_validate_from_relay(
                recipient_db,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                actor=recipient,
                relay=relay,
                transport_id="independent-proof",
            )
            self.assertEqual(synced["accepted"], 1)
            projection = rebuild_domain_projection(
                recipient_db,
                project_id=1,
                space_id=space["space_id"],
                actor_peer_id=recipient.identity_id,
                scope_keys={1: scope_key},
            )
            self.assertEqual(projection["state"], "ready")
            self.assertEqual(projection["objects"][0]["object_id"], "atlas-boundary")

            with self.assertRaisesRegex(FederationInvitationError, "recipient"):
                preview_invitation_bundle(encoded, recipient=outsider)

            tampered = json.loads(encoded)
            tampered["ciphertext_sha256"] = "f" * 64
            with self.assertRaises(FederationInvitationError):
                preview_invitation_bundle(
                    json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode("ascii"),
                    recipient=recipient,
                )


if __name__ == "__main__":
    unittest.main()
