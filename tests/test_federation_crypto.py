import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from rta_brain.federation_crypto import (
    FederationCryptoError,
    create_encrypted_event,
    create_identity,
    create_identity_backup,
    decrypt_event,
    export_public_identity,
    generate_scope_key,
    import_public_identity,
    load_identity,
    open_scope_key,
    restore_identity_backup,
    seal_scope_key,
)

PASSPHRASE = b"correct horse battery staple"


class FederationIdentityTests(unittest.TestCase):
    def test_identity_backup_is_signed_encrypted_and_restores_without_clobber(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            restored_root = root / "restored"
            identity = create_identity(source, passphrase=PASSPHRASE)
            backup = create_identity_backup(source, passphrase=PASSPHRASE)
            self.assertNotIn(identity.signing_private_key.private_bytes_raw(), backup)
            restored = restore_identity_backup(
                backup,
                restored_root,
                passphrase=PASSPHRASE,
            )
            self.assertEqual(restored.identity_id, identity.identity_id)
            with self.assertRaises(FileExistsError):
                restore_identity_backup(backup, restored_root, passphrase=PASSPHRASE)
            tampered = bytearray(backup)
            tampered[-8] = ord("A") if tampered[-8] != ord("A") else ord("B")
            with self.assertRaises(FederationCryptoError):
                restore_identity_backup(
                    bytes(tampered),
                    root / "tampered",
                    passphrase=PASSPHRASE,
                )

    def test_public_identity_manifest_is_self_signed_and_contains_no_private_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity = create_identity(Path(tmp) / "identity", passphrase=PASSPHRASE)

            encoded = export_public_identity(identity)
            imported = import_public_identity(encoded)

            self.assertEqual(imported.identity_id, identity.identity_id)
            self.assertEqual(imported.signing_public_bytes, identity.signing_public_bytes)
            self.assertEqual(imported.envelope_public_bytes, identity.envelope_public_bytes)
            self.assertNotIn(b"PRIVATE KEY", encoded)
            self.assertNotIn(PASSPHRASE, encoded)

            tampered = json.loads(encoded)
            tampered["envelope_public_key"] = tampered["signing_public_key"]
            with self.assertRaisesRegex(FederationCryptoError, "identity"):
                import_public_identity(
                    json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode("ascii")
                )

    def test_identity_private_keys_are_encrypted_and_reloadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "identity"
            created = create_identity(root, passphrase=PASSPHRASE)

            signing_bytes = (root / "signing.pem").read_bytes()
            envelope_bytes = (root / "envelope.pem").read_bytes()
            public_manifest = json.loads((root / "identity.json").read_text(encoding="utf-8"))

            self.assertIn(b"ENCRYPTED PRIVATE KEY", signing_bytes)
            self.assertIn(b"ENCRYPTED PRIVATE KEY", envelope_bytes)
            self.assertNotIn(PASSPHRASE, signing_bytes + envelope_bytes)
            self.assertEqual(public_manifest["identity_id"], created.identity_id)
            self.assertNotIn("passphrase", public_manifest)
            self.assertEqual(load_identity(root, passphrase=PASSPHRASE).identity_id, created.identity_id)

            with self.assertRaisesRegex(FederationCryptoError, "cannot decrypt identity"):
                load_identity(root, passphrase=b"wrong passphrase")

    def test_identity_creation_is_no_clobber(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "identity"
            create_identity(root, passphrase=PASSPHRASE)

            with self.assertRaisesRegex(FileExistsError, "already exists"):
                create_identity(root, passphrase=PASSPHRASE)


class FederationCryptoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.alice = create_identity(base / "alice", passphrase=PASSPHRASE)
        self.bob = create_identity(base / "bob", passphrase=PASSPHRASE)
        self.mallory = create_identity(base / "mallory", passphrase=PASSPHRASE)
        self.space_id = "a" * 64
        self.scope_id = "b" * 64

    def test_scope_key_hpke_envelope_opens_only_for_recipient_and_context(self):
        scope_key = generate_scope_key()
        sealed = seal_scope_key(
            scope_key,
            recipient_public_key=self.bob.envelope_public_bytes,
            space_id=self.space_id,
            scope_id=self.scope_id,
            epoch=1,
            recipient_peer_id=self.bob.identity_id,
        )

        opened = open_scope_key(
            sealed,
            recipient_private_key=self.bob.envelope_private_key,
            space_id=self.space_id,
            scope_id=self.scope_id,
            epoch=1,
            recipient_peer_id=self.bob.identity_id,
        )
        self.assertEqual(opened, scope_key)

        with self.assertRaisesRegex(FederationCryptoError, "cannot open scope key"):
            open_scope_key(
                sealed,
                recipient_private_key=self.mallory.envelope_private_key,
                space_id=self.space_id,
                scope_id=self.scope_id,
                epoch=1,
                recipient_peer_id=self.bob.identity_id,
            )
        with self.assertRaisesRegex(FederationCryptoError, "cannot open scope key"):
            open_scope_key(
                sealed,
                recipient_private_key=self.bob.envelope_private_key,
                space_id=self.space_id,
                scope_id=self.scope_id,
                epoch=2,
                recipient_peer_id=self.bob.identity_id,
            )

    def test_event_round_trip_hides_payload_and_binds_header(self):
        scope_key = generate_scope_key()
        payload = {
            "event_type": "memory.asserted",
            "object_id": "atlas-architecture",
            "text": "Atlas demo architecture",
            "valid_from": "2026-09-07T00:00:00+00:00",
        }
        envelope = create_encrypted_event(
            payload,
            identity=self.alice,
            scope_key=scope_key,
            space_id=self.space_id,
            scope_id=self.scope_id,
            epoch=1,
            author_sequence=1,
            capability_event_id="1" * 64,
            parents=(),
            received_at="2026-09-07T00:00:00+00:00",
        )

        self.assertNotIn(b"Atlas demo architecture", envelope.encoded)
        self.assertEqual(
            decrypt_event(
                envelope,
                author_signing_public_key=self.alice.signing_public_bytes,
                scope_key=scope_key,
            ),
            payload,
        )

    def test_event_rejects_wrong_key_tampering_and_header_change(self):
        scope_key = generate_scope_key()
        envelope = create_encrypted_event(
            {"event_type": "comment.added", "text": "reviewed"},
            identity=self.alice,
            scope_key=scope_key,
            space_id=self.space_id,
            scope_id=self.scope_id,
            epoch=1,
            author_sequence=1,
            capability_event_id="1" * 64,
            parents=(),
            received_at="2026-09-07T00:00:00+00:00",
        )

        with self.assertRaises(FederationCryptoError):
            decrypt_event(
                envelope,
                author_signing_public_key=self.alice.signing_public_bytes,
                scope_key=generate_scope_key(),
            )

        changed_ciphertext = envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1])
        tampered = replace(
            envelope,
            ciphertext=changed_ciphertext,
            ciphertext_sha256=hashlib.sha256(changed_ciphertext).hexdigest(),
        )
        with self.assertRaisesRegex(FederationCryptoError, "signature"):
            decrypt_event(
                tampered,
                author_signing_public_key=self.alice.signing_public_bytes,
                scope_key=scope_key,
            )

        wrong_scope = replace(envelope, scope_id="e" * 64)
        with self.assertRaises(FederationCryptoError):
            decrypt_event(
                wrong_scope,
                author_signing_public_key=self.alice.signing_public_bytes,
                scope_key=scope_key,
            )

        bad_signature = replace(envelope, signature=b"x" * 64)
        with self.assertRaisesRegex(FederationCryptoError, "signature"):
            decrypt_event(
                bad_signature,
                author_signing_public_key=self.alice.signing_public_bytes,
                scope_key=scope_key,
            )


if __name__ == "__main__":
    unittest.main()
