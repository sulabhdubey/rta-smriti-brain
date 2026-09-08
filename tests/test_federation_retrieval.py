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
    add_peer,
    create_scope,
    create_space,
    grant_capabilities,
    validate_and_accept_event,
)
from rta_brain.federation_projection import rebuild_domain_projection
from rta_brain.federation_retrieval import search_federated_events

PASSPHRASE = b"correct horse battery staple"


class FederationRetrievalTests(unittest.TestCase):
    def test_query_term_count_is_bounded_before_projection_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            self.addCleanup(conn.close)
            init_schema(conn)
            conn.execute(
                "INSERT INTO projects(id, name, created_at) VALUES "
                "(1, 'atlas', '2026-09-07T00:00:00+00:00')"
            )
            owner = create_identity(Path(tmp) / "owner", passphrase=PASSPHRASE)
            space = create_space(
                conn, project_id=1, owner=owner, owner_key_reference="identity/owner"
            )

            with self.assertRaisesRegex(ValueError, "term count"):
                search_federated_events(
                    conn,
                    project_id=1,
                    space_id=space["space_id"],
                    actor_peer_id=owner.identity_id,
                    query=" ".join(f"term{index}" for index in range(65)),
                )

    def test_retrieval_filters_unauthorized_scope_before_payload_matching(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = create_identity(root / "owner", passphrase=PASSPHRASE)
            reader = create_identity(root / "reader", passphrase=PASSPHRASE)
            conn = sqlite3.connect(":memory:")
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            self.addCleanup(conn.close)
            init_schema(conn)
            conn.execute(
                "INSERT INTO projects(id, name, created_at) VALUES "
                "(1, 'atlas', '2026-09-07T00:00:00+00:00')"
            )
            space = create_space(
                conn, project_id=1, owner=owner, owner_key_reference="identity/owner"
            )
            team = create_scope(
                conn,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="team",
                label="Team",
            )
            private = create_scope(
                conn,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="custom",
                label="Private",
            )
            add_peer(
                conn,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                peer=reader,
                label="Reader",
            )
            grant_capabilities(
                conn,
                project_id=1,
                space_id=space["space_id"],
                scope_id=team["scope_id"],
                author=owner,
                subject_peer_id=reader.identity_id,
                capabilities=("read", "context", "diagnose", "export", "index"),
            )
            keys = {team["scope_id"]: generate_scope_key(), private["scope_id"]: generate_scope_key()}
            for sequence, (scope, text) in enumerate(
                ((team, "shared atlas boundary"), (private, "secret atlas acquisition")),
                start=1,
            ):
                event = create_encrypted_event(
                    {
                        "event_type": "memory.asserted",
                        "object_id": f"memory-{sequence}",
                        "text": text,
                        "privacy_class": "internal",
                        "epistemic_state": "observed",
                        "supersedes_event_ids": [],
                    },
                    identity=owner,
                    scope_key=keys[scope["scope_id"]],
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    epoch=1,
                    author_sequence=sequence,
                    capability_event_id=space["bootstrap"]["event_id"],
                    parents=(),
                    received_at="2026-09-07T00:00:00+00:00",
                )
                store_event(conn, project_id=1, envelope=event)
                validate_and_accept_event(
                    conn,
                    project_id=1,
                    envelope=event,
                    author_signing_public_key=owner.signing_public_bytes,
                    scope_key=keys[scope["scope_id"]],
                )
            rebuild_domain_projection(
                conn,
                project_id=1,
                space_id=space["space_id"],
                actor_peer_id=reader.identity_id,
                scope_keys={
                    (team["scope_id"], 1): keys[team["scope_id"]],
                    (private["scope_id"], 1): keys[private["scope_id"]],
                },
            )
            for operation in ("read", "context", "diagnose", "export", "index"):
                with self.subTest(operation=operation):
                    result = search_federated_events(
                        conn,
                        project_id=1,
                        space_id=space["space_id"],
                        actor_peer_id=reader.identity_id,
                        query="atlas",
                        operation=operation,
                    )
                    serialized = str(result)
                    self.assertEqual(result["result_count"], 1)
                    self.assertIn("shared atlas boundary", serialized)
                    self.assertNotIn("secret atlas acquisition", serialized)


if __name__ == "__main__":
    unittest.main()
