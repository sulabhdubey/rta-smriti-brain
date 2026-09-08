import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from rta_brain.cli import main
from rta_brain.db import connect, init_project
from rta_brain.federation import store_event
from rta_brain.federation_bundle import (
    FederationBundleError,
    create_encrypted_review_bundle,
    export_review_bundle_from_store,
    import_review_bundle_to_store,
    open_encrypted_review_bundle,
    preview_review_bundle_export,
    preview_review_bundle_import,
)
from rta_brain.federation_crypto import (
    create_encrypted_event,
    create_identity,
    generate_scope_key,
)
from rta_brain.federation_governance import (
    add_peer,
    create_scope,
    create_space,
    grant_capabilities,
    revoke_capabilities,
    rotate_scope_key,
    validate_and_accept_event,
)

PASSPHRASE = b"correct horse battery staple"


class FederationBundleTests(unittest.TestCase):
    def test_export_rejects_recipient_without_current_scope_read_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "brain.sqlite"
            author = create_identity(root / "author", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            scope_key = generate_scope_key()
            conn = connect(database)
            try:
                init_project(conn, "atlas", str(root / "repo"))
                space = create_space(
                    conn, project_id=1, owner=author,
                    owner_key_reference="managed-local-identity:author",
                )
                scope = create_scope(
                    conn, project_id=1, space_id=space["space_id"], owner=author,
                    kind="review", label="Review",
                )
                add_peer(
                    conn, project_id=1, space_id=space["space_id"], author=author,
                    peer=recipient, label="Reviewer",
                )
                grant_capabilities(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=scope["scope_id"], author=author,
                    subject_peer_id=recipient.identity_id,
                    capabilities=("read",),
                )
                rotate_scope_key(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=scope["scope_id"], author=author, scope_key=scope_key,
                )
                event = create_encrypted_event(
                    {"event_type": "review.requested", "text": "review evidence"},
                    identity=author,
                    scope_key=scope_key,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    epoch=1,
                    author_sequence=1,
                    capability_event_id=space["bootstrap"]["event_id"],
                    parents=(),
                    received_at="2026-09-07T00:00:00+00:00",
                )
                store_event(conn, project_id=1, envelope=event)
                validate_and_accept_event(
                    conn,
                    project_id=1,
                    envelope=event,
                    author_signing_public_key=author.signing_public_bytes,
                    scope_key=scope_key,
                )
                revoke_capabilities(
                    conn,
                    project_id=1,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    author=author,
                    subject_peer_id=recipient.identity_id,
                )

                with self.assertRaisesRegex(FederationBundleError, "recipient.*read"):
                    preview_review_bundle_export(
                        conn,
                        project_id=1,
                        space_id=space["space_id"],
                        scope_id=scope["scope_id"],
                        actor=author,
                        recipient_peer_id=recipient.identity_id,
                        event_ids=(event.event_id,),
                        privacy_ceiling="internal",
                    )
            finally:
                conn.close()

    def test_store_export_enforces_privacy_ceiling_before_encryption(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "brain.sqlite"
            author = create_identity(root / "author", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            scope_key = generate_scope_key()
            recipient_database = root / "recipient.sqlite"
            conn = connect(database)
            try:
                init_project(conn, "atlas", str(root / "repo"))
                space = create_space(
                    conn, project_id=1, owner=author,
                    owner_key_reference="managed-local-identity:author",
                )
                scope = create_scope(
                    conn, project_id=1, space_id=space["space_id"], owner=author,
                    kind="review", label="Review",
                )
                add_peer(
                    conn, project_id=1, space_id=space["space_id"], author=author,
                    peer=recipient, label="Reviewer",
                )
                grant_capabilities(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=scope["scope_id"], author=author,
                    subject_peer_id=recipient.identity_id,
                    capabilities=("read",),
                )
                rotate_scope_key(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=scope["scope_id"], author=author, scope_key=scope_key,
                )
                recipient_conn = connect(recipient_database)
                try:
                    conn.backup(recipient_conn)
                finally:
                    recipient_conn.close()
                events = []
                for sequence, privacy in enumerate(("public", "restricted"), 1):
                    event = create_encrypted_event(
                        {
                            "event_type": "review.requested",
                            "object_id": f"review-{sequence}",
                            "privacy_class": privacy,
                            "summary": f"{privacy} review evidence",
                        },
                        identity=author,
                        scope_key=scope_key,
                        space_id=space["space_id"],
                        scope_id=scope["scope_id"],
                        epoch=1,
                        author_sequence=sequence,
                        capability_event_id=space["bootstrap"]["event_id"],
                        parents=(),
                        received_at=f"2026-09-07T00:0{sequence}:00+00:00",
                    )
                    store_event(conn, project_id=1, envelope=event)
                    validate_and_accept_event(
                        conn, project_id=1, envelope=event,
                        author_signing_public_key=author.signing_public_bytes,
                        scope_key=scope_key,
                    )
                    events.append(event)

                plan = preview_review_bundle_export(
                    conn,
                    project_id=1,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    actor=author,
                    recipient_peer_id=recipient.identity_id,
                    event_ids=tuple(event.event_id for event in events),
                    privacy_ceiling="public",
                )
                encoded = export_review_bundle_from_store(
                    conn,
                    project_id=1,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    actor=author,
                    recipient_peer_id=recipient.identity_id,
                    event_ids=tuple(event.event_id for event in events),
                    privacy_ceiling="public",
                    confirmation_digest=plan["confirmation_digest"],
                )
            finally:
                conn.close()

            self.assertEqual(plan["included_event_count"], 1)
            self.assertEqual(plan["excluded_event_count"], 1)
            opened = open_encrypted_review_bundle(
                encoded,
                recipient=recipient,
                author_signing_public_key=author.signing_public_bytes,
            )
            self.assertEqual(opened["event_count"], 1)
            self.assertNotIn(b"restricted review evidence", encoded)

            passphrase_file = root / "passphrase.txt"
            passphrase_file.write_text(PASSPHRASE.decode("ascii"), encoding="utf-8")
            bundle_path = root / "review-bundle.json"

            def invoke(*arguments):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    code = main([
                        "--db", str(database), "--json", "federation",
                        "review-bundle", *arguments,
                    ])
                self.assertEqual(code, 0)
                payload = json.loads(stdout.getvalue())
                self.assertNotIn(str(root), json.dumps(payload))
                return payload

            cli_plan = invoke(
                "preview", "--project", "atlas",
                "--identity-dir", str(root / "author"),
                "--passphrase-file", str(passphrase_file),
                "--space-id", space["space_id"], "--scope-id", scope["scope_id"],
                "--recipient-peer-id", recipient.identity_id,
                "--event-id", events[0].event_id,
                "--event-id", events[1].event_id,
                "--privacy-ceiling", "public",
            )
            exported = invoke(
                "export", "--project", "atlas",
                "--identity-dir", str(root / "author"),
                "--passphrase-file", str(passphrase_file),
                "--space-id", space["space_id"], "--scope-id", scope["scope_id"],
                "--recipient-peer-id", recipient.identity_id,
                "--event-id", events[0].event_id,
                "--event-id", events[1].event_id,
                "--privacy-ceiling", "public",
                "--confirmation-digest", cli_plan["confirmation_digest"],
                "--output", str(bundle_path),
            )
            verified_stdout = io.StringIO()
            with redirect_stdout(verified_stdout):
                code = main([
                    "--db", str(recipient_database), "--json", "federation",
                    "review-bundle", "verify", "--project", "atlas",
                    "--identity-dir", str(root / "recipient"),
                    "--passphrase-file", str(passphrase_file),
                    "--source", str(bundle_path),
                ])
            self.assertEqual(code, 0)
            verified = json.loads(verified_stdout.getvalue())
            self.assertNotIn(str(root), json.dumps(verified))
            self.assertEqual(exported["state"], "exported")
            self.assertEqual(verified["state"], "verified")
            self.assertEqual(verified["event_count"], 1)
            self.assertEqual(len(verified["confirmation_digest"]), 64)

            recipient_stdout = io.StringIO()
            with redirect_stdout(recipient_stdout):
                code = main([
                    "--db", str(recipient_database), "--json", "federation",
                    "review-bundle", "import", "--project", "atlas",
                    "--identity-dir", str(root / "recipient"),
                    "--passphrase-file", str(passphrase_file),
                    "--source", str(bundle_path),
                    "--confirmation-digest", verified["confirmation_digest"],
                ])
            self.assertEqual(code, 0)
            imported = json.loads(recipient_stdout.getvalue())
            self.assertEqual(imported["state"], "imported")
            self.assertEqual(imported["accepted_event_count"], 1)
            self.assertNotIn(str(root), json.dumps(imported))

            recipient_conn = connect(recipient_database)
            try:
                accepted = recipient_conn.execute(
                    "SELECT COUNT(*) FROM federation_event_validation "
                    "WHERE project_id = 1 AND validation_state = 'accepted'"
                ).fetchone()[0]
            finally:
                recipient_conn.close()
            self.assertEqual(accepted, 1)

    def test_review_import_preview_is_read_only_and_apply_is_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            author = create_identity(root / "author", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            database = root / "brain.sqlite"
            conn = connect(database)
            try:
                init_project(conn, "atlas", str(root / "repo"))
                space = create_space(
                    conn, project_id=1, owner=author,
                    owner_key_reference="managed-local-identity:author",
                )
                scope = create_scope(
                    conn, project_id=1, space_id=space["space_id"], owner=author,
                    kind="review", label="Review",
                )
                add_peer(
                    conn, project_id=1, space_id=space["space_id"], author=author,
                    peer=recipient, label="Reviewer",
                )
                grant_capabilities(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=scope["scope_id"], author=author,
                    subject_peer_id=recipient.identity_id,
                    capabilities=("read",),
                )
                scope_key = generate_scope_key()
                rotate_scope_key(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=scope["scope_id"], author=author, scope_key=scope_key,
                )
                event = create_encrypted_event(
                    {
                        "event_type": "review.requested",
                        "object_id": "review-1",
                        "privacy_class": "internal",
                        "summary": "Review Atlas evidence",
                    },
                    identity=author, scope_key=scope_key,
                    space_id=space["space_id"], scope_id=scope["scope_id"],
                    epoch=1, author_sequence=1,
                    capability_event_id=space["bootstrap"]["event_id"], parents=(),
                    received_at="2026-09-07T00:00:00+00:00",
                )
                encoded = create_encrypted_review_bundle(
                    events=(event,), author=author,
                    recipient_peer_id=recipient.identity_id,
                    recipient_envelope_public_key=recipient.envelope_public_bytes,
                    space_id=space["space_id"], scope_id=scope["scope_id"], epoch=1,
                    privacy_ceiling="internal",
                    evidence_manifest=(
                        {"evidence_id": event.event_id, "digest": event.envelope_sha256},
                    ),
                    excluded_manifest=(),
                )

                preview = preview_review_bundle_import(
                    conn, project_id=1, encoded=encoded, recipient=recipient
                )
                self.assertFalse(preview["writes_performed"])
                self.assertEqual(preview["accepted_event_count"], 1)
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM federation_events WHERE project_id = 1"
                    ).fetchone()[0],
                    0,
                )

                with self.assertRaisesRegex(FederationBundleError, "changed after verification"):
                    import_review_bundle_to_store(
                        conn, project_id=1, encoded=encoded, recipient=recipient,
                        confirmation_digest="f" * 64,
                    )
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM federation_events WHERE project_id = 1"
                    ).fetchone()[0],
                    0,
                )
                revoke_capabilities(
                    conn,
                    project_id=1,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    author=author,
                    subject_peer_id=recipient.identity_id,
                )
                with self.assertRaisesRegex(FederationBundleError, "active scope capability"):
                    import_review_bundle_to_store(
                        conn, project_id=1, encoded=encoded, recipient=recipient,
                        confirmation_digest=preview["confirmation_digest"],
                    )
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) FROM federation_events WHERE project_id = 1"
                    ).fetchone()[0],
                    0,
                )
            finally:
                conn.close()

    def test_bundle_supports_documented_size_above_default_canonical_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            author = create_identity(root / "author", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            evidence_manifest = tuple(
                {
                    "evidence_id": f"evidence-{index:04d}-" + ("x" * 1400),
                    "digest": f"{index:064x}",
                }
                for index in range(1, 751)
            )

            encoded = create_encrypted_review_bundle(
                events=(),
                author=author,
                recipient_peer_id=recipient.identity_id,
                recipient_envelope_public_key=recipient.envelope_public_bytes,
                space_id="a" * 64,
                scope_id="b" * 64,
                epoch=1,
                privacy_ceiling="internal",
                evidence_manifest=evidence_manifest,
                excluded_manifest=(),
            )

            self.assertGreater(len(encoded), 1024 * 1024)
            opened = open_encrypted_review_bundle(
                encoded,
                recipient=recipient,
                author_signing_public_key=author.signing_public_bytes,
            )
            self.assertEqual(len(opened["evidence_manifest"]), 750)

    def test_bundle_binds_author_recipient_scope_manifest_and_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            author = create_identity(root / "author", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            outsider = create_identity(root / "outsider", passphrase=PASSPHRASE)
            scope_key = generate_scope_key()
            event = create_encrypted_event(
                {
                    "event_type": "review.requested",
                    "object_id": "atlas-review",
                    "review_id": "review-1",
                    "summary": "Review public Atlas evidence",
                },
                identity=author,
                scope_key=scope_key,
                space_id="a" * 64,
                scope_id="b" * 64,
                epoch=1,
                author_sequence=1,
                capability_event_id="c" * 64,
                parents=(),
                received_at="2026-09-07T00:00:00+00:00",
            )
            encoded = create_encrypted_review_bundle(
                events=(event,),
                author=author,
                recipient_peer_id=recipient.identity_id,
                recipient_envelope_public_key=recipient.envelope_public_bytes,
                space_id="a" * 64,
                scope_id="b" * 64,
                epoch=1,
                privacy_ceiling="internal",
                evidence_manifest=(
                    {"evidence_id": "atlas-readme", "digest": "d" * 64},
                ),
                excluded_manifest=(
                    {"reference": "private-transcript", "digest": "e" * 64},
                ),
            )
            self.assertNotIn(b"private-transcript", encoded)
            opened = open_encrypted_review_bundle(
                encoded,
                recipient=recipient,
                author_signing_public_key=author.signing_public_bytes,
            )
            self.assertEqual(opened["event_count"], 1)
            self.assertEqual(opened["privacy_ceiling"], "internal")
            self.assertEqual(opened["evidence_manifest"][0]["evidence_id"], "atlas-readme")
            self.assertEqual(len(opened["excluded_content_proof"]), 64)
            self.assertNotIn("excluded_manifest", opened)

            with self.assertRaisesRegex(FederationBundleError, "recipient"):
                open_encrypted_review_bundle(
                    encoded,
                    recipient=outsider,
                    author_signing_public_key=author.signing_public_bytes,
                )

    def test_modified_ciphertext_and_manifest_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            author = create_identity(root / "author", passphrase=PASSPHRASE)
            recipient = create_identity(root / "recipient", passphrase=PASSPHRASE)
            encoded = create_encrypted_review_bundle(
                events=(),
                author=author,
                recipient_peer_id=recipient.identity_id,
                recipient_envelope_public_key=recipient.envelope_public_bytes,
                space_id="a" * 64,
                scope_id="b" * 64,
                epoch=1,
                privacy_ceiling="public",
                evidence_manifest=(),
                excluded_manifest=(),
            )
            value = json.loads(encoded)
            value["privacy_ceiling"] = "restricted"
            tampered = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
            with self.assertRaisesRegex(FederationBundleError, "signature"):
                open_encrypted_review_bundle(
                    tampered,
                    recipient=recipient,
                    author_signing_public_key=author.signing_public_bytes,
                )


if __name__ == "__main__":
    unittest.main()
