import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path

from rta_brain.cli import main
from rta_brain.db import connect, init_project
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
    grant_capabilities,
    revoke_capabilities,
    rotate_scope_key,
    validate_and_accept_event,
)
from rta_brain.federation_projection import rebuild_domain_projection
from rta_brain.mcp_server import RtaBrainMcpServer
from rta_brain.trusted_lifecycle import inspect_lifecycle

PASSPHRASE = b"correct horse battery staple"


class FederationInterfaceTests(unittest.TestCase):
    def test_cli_and_mcp_apply_current_scope_authorization_before_returning_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            database = base / "brain.sqlite"
            owner = create_identity(base / "owner", passphrase=PASSPHRASE)
            reader = create_identity(base / "reader", passphrase=PASSPHRASE)
            conn = connect(database)
            try:
                init_project(conn, "atlas", root)
                space = create_space(
                    conn, project_id=1, owner=owner,
                    owner_key_reference="synthetic-owner",
                )
                shared = create_scope(
                    conn, project_id=1, space_id=space["space_id"], owner=owner,
                    kind="team", label="Shared",
                )
                private = create_scope(
                    conn, project_id=1, space_id=space["space_id"], owner=owner,
                    kind="custom", label="Private",
                )
                add_public_peer(
                    conn, project_id=1, space_id=space["space_id"], author=owner,
                    peer=import_public_identity(export_public_identity(reader)),
                    label="Reader",
                )
                grant_capabilities(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=shared["scope_id"], author=owner,
                    subject_peer_id=reader.identity_id,
                    capabilities=("read", "context", "diagnose", "export", "index"),
                )
                keys = {
                    shared["scope_id"]: generate_scope_key(),
                    private["scope_id"]: generate_scope_key(),
                }
                for sequence, (scope, text) in enumerate(
                    ((shared, "shared atlas contract"), (private, "private atlas secret")),
                    start=1,
                ):
                    event = create_encrypted_event(
                        {
                            "event_type": "memory.asserted",
                            "object_id": f"memory-{sequence}",
                            "text": text,
                            "privacy_class": "internal",
                            "epistemic_state": "observed",
                        },
                        identity=owner,
                        scope_key=keys[scope["scope_id"]],
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
                        author_signing_public_key=owner.signing_public_bytes,
                        scope_key=keys[scope["scope_id"]],
                    )
                rebuild_domain_projection(
                    conn,
                    project_id=1,
                    space_id=space["space_id"],
                    actor_peer_id=reader.identity_id,
                    scope_keys={
                        (shared["scope_id"], 1): keys[shared["scope_id"]],
                        (private["scope_id"], 1): keys[private["scope_id"]],
                    },
                )
            finally:
                conn.close()

            cli_args = [
                "--db", str(database), "--json", "federation", "search", "atlas",
                "--project", "atlas", "--space-id", space["space_id"],
                "--actor-peer-id", reader.identity_id, "--operation", "context",
            ]
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(main(cli_args), 0)
            cli_result = json.loads(stdout.getvalue())
            self.assertEqual(cli_result["result_count"], 1)
            self.assertIn("shared atlas contract", json.dumps(cli_result))
            self.assertNotIn("private atlas secret", json.dumps(cli_result))

            server = RtaBrainMcpServer(database, "atlas", expected_root=root)
            mcp_args = {
                "space_id": space["space_id"],
                "actor_peer_id": reader.identity_id,
                "query": "atlas",
                "operation": "context",
            }
            mcp_result = server.call_tool(
                "brain_federation_search", mcp_args
            )["structuredContent"]
            self.assertEqual(mcp_result, cli_result)

            conn = connect(database)
            try:
                revoke_capabilities(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=shared["scope_id"], author=owner,
                    subject_peer_id=reader.identity_id,
                )
            finally:
                conn.close()

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(main(cli_args), 0)
            self.assertEqual(json.loads(stdout.getvalue())["result_count"], 0)
            self.assertEqual(
                server.call_tool(
                    "brain_federation_search", mcp_args
                )["structuredContent"]["result_count"],
                0,
            )

    def test_cli_managed_sync_enrollment_is_preview_bound_and_path_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            database = base / "brain.sqlite"
            identity_root = base / "owner"
            passphrase_file = base / "passphrase.txt"
            relay_root = base / "relay"
            relay_root.mkdir()
            passphrase_file.write_text(PASSPHRASE.decode("ascii"), encoding="utf-8")
            owner = create_identity(identity_root, passphrase=PASSPHRASE)
            conn = connect(database)
            try:
                init_project(conn, "atlas", root)
                space = create_space(
                    conn,
                    project_id=1,
                    owner=owner,
                    owner_key_reference="managed-local-identity",
                )
                scope = create_scope(
                    conn,
                    project_id=1,
                    space_id=space["space_id"],
                    owner=owner,
                    kind="team",
                    label="Team",
                )
            finally:
                conn.close()

            common = [
                "--project", "atlas",
                "--space-id", space["space_id"],
                "--scope-id", scope["scope_id"],
                "--identity-dir", str(identity_root),
                "--passphrase-file", str(passphrase_file),
                "--relay-root", str(relay_root),
            ]

            def invoke(action, *extra):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    code = main([
                        "--db", str(database), "--json", "federation", "sync",
                        action, *common, *extra,
                    ])
                self.assertEqual(code, 0)
                payload = json.loads(stdout.getvalue())
                self.assertNotIn(str(base), json.dumps(payload))
                return payload

            preview = invoke("daemon-preview")
            self.assertFalse(preview["writes_performed"])
            configured = invoke(
                "daemon-configure",
                "--confirmation-digest", preview["confirmation_digest"],
            )
            self.assertEqual(configured["state"], "configured")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([
                    "--db", str(database), "--json", "federation", "sync",
                    "daemon-status", "--project", "atlas",
                ])
            self.assertEqual(code, 0)
            status = json.loads(stdout.getvalue())
            self.assertEqual(status["state"], "configured")
            self.assertNotIn(str(base), json.dumps(status))

    def test_cli_identity_lifecycle_is_no_clobber_and_path_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            identity_root = base / "owner"
            restored_root = base / "restored"
            passphrase_file = base / "passphrase.txt"
            public_manifest = base / "owner-public.json"
            backup = base / "owner-backup.json"
            passphrase_file.write_text(PASSPHRASE.decode("ascii"), encoding="utf-8")

            def invoke(*arguments):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    code = main(["--json", "federation", "identity", *arguments])
                self.assertEqual(code, 0)
                payload = json.loads(stdout.getvalue())
                self.assertNotIn(str(base), json.dumps(payload))
                return payload

            created = invoke(
                "create",
                "--identity-dir", str(identity_root),
                "--passphrase-file", str(passphrase_file),
            )
            inspected = invoke(
                "inspect",
                "--identity-dir", str(identity_root),
                "--passphrase-file", str(passphrase_file),
            )
            exported = invoke(
                "export-public",
                "--identity-dir", str(identity_root),
                "--passphrase-file", str(passphrase_file),
                "--output", str(public_manifest),
            )
            backed_up = invoke(
                "backup",
                "--identity-dir", str(identity_root),
                "--passphrase-file", str(passphrase_file),
                "--output", str(backup),
            )
            restored = invoke(
                "restore",
                "--identity-dir", str(restored_root),
                "--passphrase-file", str(passphrase_file),
                "--source", str(backup),
            )

            self.assertEqual(
                {created["identity_id"], inspected["identity_id"], exported["identity_id"],
                 backed_up["identity_id"], restored["identity_id"]},
                {created["identity_id"]},
            )
            self.assertTrue(public_manifest.is_file())
            self.assertTrue(backup.is_file())
            self.assertTrue((restored_root / "identity.json").is_file())

    def test_cli_invitation_issue_preview_and_accept_are_selective_and_path_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            owner_root = base / "owner"
            recipient_root = base / "recipient"
            owner_passphrase = base / "owner-passphrase.txt"
            recipient_passphrase = base / "recipient-passphrase.txt"
            recipient_manifest = base / "recipient-public.json"
            invitation = base / "invitation.json"
            owner_db = base / "owner.sqlite"
            recipient_db = base / "recipient.sqlite"
            owner_passphrase.write_text(PASSPHRASE.decode("ascii"), encoding="utf-8")
            recipient_passphrase.write_text(PASSPHRASE.decode("ascii"), encoding="utf-8")
            owner = create_identity(owner_root, passphrase=PASSPHRASE)
            recipient = create_identity(recipient_root, passphrase=PASSPHRASE)
            recipient_manifest.write_bytes(export_public_identity(recipient))

            conn = connect(owner_db)
            try:
                init_project(conn, "atlas", str(base / "owner-repo"))
                space = create_space(
                    conn, project_id=1, owner=owner,
                    owner_key_reference="synthetic-owner",
                )
                scope = create_scope(
                    conn, project_id=1, space_id=space["space_id"], owner=owner,
                    kind="review", label="Selective review",
                )
                public_recipient = import_public_identity(recipient_manifest.read_bytes())
                add_public_peer(
                    conn, project_id=1, space_id=space["space_id"], author=owner,
                    peer=public_recipient, label="Reviewer",
                )
                grant_capabilities(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=scope["scope_id"], author=owner,
                    subject_peer_id=recipient.identity_id,
                    capabilities=("read", "review", "sync"),
                )
                rotate_scope_key(
                    conn, project_id=1, space_id=space["space_id"],
                    scope_id=scope["scope_id"], author=owner,
                    scope_key=generate_scope_key(),
                )
            finally:
                conn.close()
            conn = connect(recipient_db)
            try:
                init_project(conn, "atlas", str(base / "recipient-repo"))
            finally:
                conn.close()

            def invoke(database, *arguments):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    code = main([
                        "--db", str(database), "--json", "federation", "invitation",
                        *arguments,
                    ])
                self.assertEqual(code, 0)
                payload = json.loads(stdout.getvalue())
                self.assertNotIn(str(base), json.dumps(payload))
                return payload

            issued = invoke(
                owner_db, "issue", "--project", "atlas",
                "--space-id", space["space_id"],
                "--identity-dir", str(owner_root),
                "--passphrase-file", str(owner_passphrase),
                "--recipient-manifest", str(recipient_manifest),
                "--scope-id", scope["scope_id"],
                "--expires-at", (datetime.now(UTC) + timedelta(hours=1)).replace(
                    microsecond=0
                ).isoformat(),
                "--output", str(invitation),
            )
            preview = invoke(
                recipient_db, "preview", "--project", "atlas",
                "--identity-dir", str(recipient_root),
                "--passphrase-file", str(recipient_passphrase),
                "--source", str(invitation),
            )
            accepted = invoke(
                recipient_db, "accept", "--project", "atlas",
                "--identity-dir", str(recipient_root),
                "--passphrase-file", str(recipient_passphrase),
                "--source", str(invitation),
            )

            self.assertEqual(issued["state"], "issued")
            self.assertEqual(preview["state"], "valid")
            self.assertEqual(preview["scope_count"], 1)
            self.assertEqual(accepted["state"], "accepted")
            self.assertEqual(accepted["scope_count"], 1)

            conn = connect(owner_db)
            try:
                receipts_before = int(conn.execute(
                    "SELECT COUNT(*) FROM federation_invitation_receipts"
                ).fetchone()[0])
            finally:
                conn.close()
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = main([
                    "--db", str(owner_db), "--json", "federation", "invitation",
                    "issue", "--project", "atlas", "--space-id", space["space_id"],
                    "--identity-dir", str(owner_root),
                    "--passphrase-file", str(owner_passphrase),
                    "--recipient-manifest", str(recipient_manifest),
                    "--scope-id", scope["scope_id"],
                    "--expires-at", (datetime.now(UTC) + timedelta(hours=1)).replace(
                        microsecond=0
                    ).isoformat(),
                    "--output", str(invitation),
                ])
            self.assertEqual(code, 1)
            conn = connect(owner_db)
            try:
                receipts_after = int(conn.execute(
                    "SELECT COUNT(*) FROM federation_invitation_receipts"
                ).fetchone()[0])
            finally:
                conn.close()
            self.assertEqual(receipts_after, receipts_before)

    def test_cli_filesystem_sync_is_preview_first_resumable_and_path_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            identity_root = base / "owner"
            passphrase_file = base / "passphrase.txt"
            passphrase_file.write_text(PASSPHRASE.decode("ascii"), encoding="utf-8")
            relay_root = base / "relay"
            source_db = base / "source.sqlite"
            destination_db = base / "destination.sqlite"
            owner = create_identity(identity_root, passphrase=PASSPHRASE)
            scope_key = generate_scope_key()

            source = connect(source_db)
            destination = connect(destination_db)
            try:
                init_project(source, "atlas", str(base / "source-repo"))
                space = create_space(
                    source, project_id=1, owner=owner,
                    owner_key_reference="managed-local-identity:owner",
                )
                scope = create_scope(
                    source, project_id=1, space_id=space["space_id"], owner=owner,
                    kind="team", label="Team memory",
                )
                rotate_scope_key(
                    source, project_id=1, space_id=space["space_id"],
                    scope_id=scope["scope_id"], author=owner, scope_key=scope_key,
                )
                source.backup(destination)
                event = create_encrypted_event(
                    {
                        "event_type": "memory.asserted",
                        "object_id": "memory-1",
                        "text": "private project memory",
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
                    received_at="2026-09-07T00:01:00+00:00",
                )
                store_event(source, project_id=1, envelope=event)
                validate_and_accept_event(
                    source,
                    project_id=1,
                    envelope=event,
                    author_signing_public_key=owner.signing_public_bytes,
                    scope_key=scope_key,
                )
            finally:
                source.close()
                destination.close()

            def invoke(database, action, *extra):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    code = main([
                        "--db", str(database), "--json", "federation", "sync",
                        action, "--project", "atlas",
                        "--space-id", space["space_id"],
                        "--scope-id", scope["scope_id"],
                        "--identity-dir", str(identity_root),
                        "--passphrase-file", str(passphrase_file),
                        "--relay-root", str(relay_root),
                        *extra,
                    ])
                self.assertEqual(code, 0)
                payload = json.loads(stdout.getvalue())
                self.assertNotIn(str(base), json.dumps(payload))
                return payload

            push_preview = invoke(source_db, "preview-push")
            pushed = invoke(
                source_db, "push",
                "--confirmation-digest", push_preview["confirmation_digest"],
            )
            pull_preview = invoke(destination_db, "preview-pull")
            pulled = invoke(
                destination_db, "pull",
                "--confirmation-digest", pull_preview["confirmation_digest"],
            )
            verified = invoke(destination_db, "verify")
            repair_preview = invoke(destination_db, "preview-repair")
            repaired = invoke(
                destination_db, "repair",
                "--confirmation-digest", repair_preview["confirmation_digest"],
            )

            self.assertEqual(push_preview["state"], "preview")
            self.assertEqual(push_preview["event_count"], 1)
            self.assertEqual(pushed["stored"], 1)
            self.assertEqual(pull_preview["selected"], 1)
            self.assertEqual(pulled["accepted"], 1)
            self.assertEqual(verified["state"], "healthy")
            self.assertEqual(verified["local_event_count"], 1)
            self.assertEqual(verified["relay_event_count"], 1)
            self.assertEqual(repaired["state"], "healthy")

    def test_lifecycle_reports_configured_federation_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            database = base / "brains" / "brain.sqlite"
            database.parent.mkdir()
            owner = create_identity(
                base / "owner", passphrase=b"correct horse battery staple"
            )
            conn = connect(database)
            try:
                init_project(conn, "atlas", str(root))
                project = int(
                    conn.execute(
                        "SELECT id FROM projects WHERE name = 'atlas'"
                    ).fetchone()["id"]
                )
                space = create_space(
                    conn,
                    project_id=project,
                    owner=owner,
                    owner_key_reference="identity/owner",
                )
                scope = create_scope(
                    conn,
                    project_id=project,
                    space_id=space["space_id"],
                    owner=owner,
                    kind="team",
                    label="Team memory",
                )
                rotate_scope_key(
                    conn,
                    project_id=project,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    author=owner,
                    scope_key=generate_scope_key(),
                )
            finally:
                conn.close()

            snapshot = inspect_lifecycle({
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "atlas",
                "root": root,
                "sessions_root": base / "sessions",
            })

            axis = snapshot["health_axes"]["federation_health"]
            self.assertEqual(axis["state"], "healthy")
            self.assertEqual(axis["scope_count"], 1)
            self.assertNotIn(str(root), json.dumps(axis))

    def test_cli_and_mcp_report_the_same_not_configured_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            database = Path(tmp) / "brain.sqlite"
            conn = connect(database)
            try:
                init_project(conn, "atlas", str(root))
            finally:
                conn.close()

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([
                    "--db", str(database), "--json", "federation", "status",
                    "--project", "atlas",
                ])
            self.assertEqual(code, 0)
            cli_payload = json.loads(stdout.getvalue())
            self.assertEqual(cli_payload["state"], "not_configured")

            server = RtaBrainMcpServer(database, "atlas", expected_root=root)
            self.assertIn("brain_federation_status", server.enabled_tools)
            mcp_payload = server.call_tool(
                "brain_federation_status", {}
            )["structuredContent"]
            self.assertEqual(mcp_payload["state"], cli_payload["state"])
            self.assertEqual(mcp_payload["axes"], cli_payload["axes"])
            self.assertNotIn(str(root), json.dumps(mcp_payload))

    def test_cli_preview_and_apply_share_the_operator_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            database = base / "brain.sqlite"
            identity_root = base / "owner"
            passphrase_file = base / "passphrase.txt"
            passphrase_file.write_text(PASSPHRASE.decode("ascii"), encoding="utf-8")
            owner = create_identity(identity_root, passphrase=PASSPHRASE)
            conn = connect(database)
            try:
                init_project(conn, "atlas", str(root))
                space = create_space(
                    conn,
                    project_id=1,
                    owner=owner,
                    owner_key_reference="managed-local-identity:owner",
                )
            finally:
                conn.close()
            parameters = json.dumps(
                {
                    "space_id": space["space_id"],
                    "kind": "team",
                    "label": "Engineering",
                }
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(
                    [
                        "--db", str(database), "--json", "federation", "plan",
                        "--project", "atlas", "--action", "scope-create",
                        "--actor-peer-id", owner.identity_id,
                        "--parameters-json", parameters,
                    ]
                )
            self.assertEqual(code, 0)
            plan = json.loads(stdout.getvalue())
            self.assertFalse(plan["writes_performed"])

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main(
                    [
                        "--db", str(database), "--json", "federation", "apply",
                        "--project", "atlas", "--action", "scope-create",
                        "--parameters-json", parameters,
                        "--identity-dir", str(identity_root),
                        "--passphrase-file", str(passphrase_file),
                        "--confirmation-digest", plan["confirmation_digest"],
                    ]
                )
            self.assertEqual(code, 0)
            applied = json.loads(stdout.getvalue())
            self.assertEqual(applied["state"], "applied")
            self.assertNotIn(str(base), json.dumps(applied))

    def test_mcp_federation_mutation_requires_explicit_startup_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            database = base / "brain.sqlite"
            identity_root = base / "owner"
            passphrase_file = base / "passphrase.txt"
            passphrase_file.write_text(PASSPHRASE.decode("ascii"), encoding="utf-8")
            owner = create_identity(identity_root, passphrase=PASSPHRASE)
            conn = connect(database)
            try:
                init_project(conn, "atlas", str(root))
                space = create_space(
                    conn,
                    project_id=1,
                    owner=owner,
                    owner_key_reference="managed-local-identity:owner",
                )
            finally:
                conn.close()
            default_server = RtaBrainMcpServer(database, "atlas", expected_root=root)
            self.assertIn("brain_federation_plan", default_server.enabled_tools)
            self.assertNotIn("brain_federation_apply", default_server.enabled_tools)
            self.assertIn(
                "brain_federation_sync_status", default_server.enabled_tools
            )
            self.assertIn(
                "brain_federation_sync_plan", default_server.enabled_tools
            )
            self.assertNotIn(
                "brain_federation_sync_apply", default_server.enabled_tools
            )
            sync_status = default_server.call_tool(
                "brain_federation_sync_status", {}
            )["structuredContent"]
            self.assertEqual(sync_status["state"], "not_configured")

            server = RtaBrainMcpServer(
                database,
                "atlas",
                expected_root=root,
                allow_federation_writes=True,
                federation_identity_root=identity_root,
                federation_passphrase_file=passphrase_file,
            )
            self.assertIn("brain_federation_sync_apply", server.enabled_tools)
            parameters = {
                "space_id": space["space_id"],
                "kind": "review",
                "label": "Review",
            }
            plan = server.call_tool(
                "brain_federation_plan",
                {
                    "action": "scope-create",
                    "actor_peer_id": owner.identity_id,
                    "parameters": parameters,
                },
            )["structuredContent"]
            applied = server.call_tool(
                "brain_federation_apply",
                {
                    "action": "scope-create",
                    "parameters": parameters,
                    "confirmation_digest": plan["confirmation_digest"],
                },
            )["structuredContent"]
            self.assertEqual(applied["state"], "applied")
            self.assertNotIn(str(base), json.dumps(applied))


if __name__ == "__main__":
    unittest.main()
