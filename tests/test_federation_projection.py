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
    revoke_capabilities,
    validate_and_accept_event,
)
from rta_brain.federation_projection import rebuild_domain_projection

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


class FederationProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.owner = create_identity(root / "owner", passphrase=PASSPHRASE)
        self.alice = create_identity(root / "alice", passphrase=PASSPHRASE)
        self.bob = create_identity(root / "bob", passphrase=PASSPHRASE)
        self.conn = connection()
        self.addCleanup(self.conn.close)
        self.space = create_space(
            self.conn, project_id=1, owner=self.owner, owner_key_reference="identity/owner"
        )
        self.scope = create_scope(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            owner=self.owner,
            kind="team",
            label="Team memory",
        )
        self.grants = {self.owner.identity_id: self.space["bootstrap"]["event_id"]}
        for label, peer in (("Alice", self.alice), ("Bob", self.bob)):
            add_peer(
                self.conn,
                project_id=1,
                space_id=self.space["space_id"],
                author=self.owner,
                peer=peer,
                label=label,
            )
            self.grants[peer.identity_id] = grant_capabilities(
                self.conn,
                project_id=1,
                space_id=self.space["space_id"],
                scope_id=self.scope["scope_id"],
                author=self.owner,
                subject_peer_id=peer.identity_id,
                capabilities=("read", "write", "review", "sync"),
            )["event_id"]
        self.key = generate_scope_key()

    def _event(self, peer, sequence, payload, *, parents=()):
        envelope = create_encrypted_event(
            payload,
            identity=peer,
            scope_key=self.key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=sequence,
            capability_event_id=self.grants[peer.identity_id],
            parents=parents,
            received_at=f"2026-09-07T00:{sequence:02d}:00+00:00",
        )
        store_event(self.conn, project_id=1, envelope=envelope)
        validate_and_accept_event(
            self.conn,
            project_id=1,
            envelope=envelope,
            author_signing_public_key=peer.signing_public_bytes,
            scope_key=self.key,
        )
        return envelope

    def test_divergent_claims_remain_conflicted_until_explicit_decision(self):
        first = self._event(
            self.alice,
            1,
            {
                "event_type": "memory.asserted",
                "object_id": "release-channel",
                "text": "Publish as a prerelease",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
        )
        second = self._event(
            self.bob,
            1,
            {
                "event_type": "memory.asserted",
                "object_id": "release-channel",
                "text": "Hold publication",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
        )

        conflicted = rebuild_domain_projection(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            actor_peer_id=self.owner.identity_id,
            scope_keys={1: self.key},
        )
        self.assertEqual(conflicted["state"], "conflict")
        self.assertEqual(conflicted["conflict_count"], 1)
        claim = conflicted["objects"][0]
        self.assertEqual(claim["object_id"], "release-channel")
        self.assertEqual(set(claim["head_event_ids"]), {first.event_id, second.event_id})
        self.assertEqual(len(claim["versions"]), 2)

        decision = self._event(
            self.owner,
            1,
            {
                "event_type": "decision.recorded",
                "decision_id": "release-decision-1",
                "object_id": "release-channel",
                "outcome": "accepted",
                "selected_event_ids": [first.event_id],
                "resolved_event_ids": [first.event_id, second.event_id],
                "reason": "Owner-approved release path",
            },
            parents=(first.event_id, second.event_id),
        )
        resolved = rebuild_domain_projection(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            actor_peer_id=self.owner.identity_id,
            scope_keys={1: self.key},
        )
        self.assertEqual(resolved["state"], "ready")
        self.assertEqual(resolved["conflict_count"], 0)
        self.assertEqual(resolved["objects"][0]["selected_event_ids"], [first.event_id])
        self.assertEqual(resolved["decisions"][0]["event_id"], decision.event_id)

    def test_concurrent_decisions_remain_conflicted_until_a_causal_decision_resolves_them(self):
        self.grants[self.alice.identity_id] = grant_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.alice.identity_id,
            capabilities=("admin",),
        )["event_id"]
        first = self._event(
            self.alice,
            1,
            {
                "event_type": "memory.asserted",
                "object_id": "release-channel",
                "text": "Publish as a prerelease",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
        )
        second = self._event(
            self.bob,
            1,
            {
                "event_type": "memory.asserted",
                "object_id": "release-channel",
                "text": "Hold publication",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
        )
        owner_decision = self._event(
            self.owner,
            1,
            {
                "event_type": "decision.recorded",
                "decision_id": "owner-decision",
                "object_id": "release-channel",
                "outcome": "accepted",
                "selected_event_ids": [first.event_id],
                "resolved_event_ids": [first.event_id, second.event_id],
                "reason": "Owner selected the prerelease path",
            },
            parents=(first.event_id, second.event_id),
        )
        peer_decision = self._event(
            self.alice,
            2,
            {
                "event_type": "decision.recorded",
                "decision_id": "peer-decision",
                "object_id": "release-channel",
                "outcome": "accepted",
                "selected_event_ids": [second.event_id],
                "resolved_event_ids": [first.event_id, second.event_id],
                "reason": "Peer selected the hold path",
            },
            parents=(first.event_id, second.event_id),
        )

        conflicted = rebuild_domain_projection(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            actor_peer_id=self.owner.identity_id,
            scope_keys={1: self.key},
        )
        item = conflicted["objects"][0]
        self.assertEqual(item["state"], "conflict")
        self.assertEqual(
            set(item["decision_conflict_event_ids"]),
            {owner_decision.event_id, peer_decision.event_id},
        )
        self.assertEqual(item["selected_event_ids"], [])

        final_decision = self._event(
            self.owner,
            2,
            {
                "event_type": "decision.recorded",
                "decision_id": "final-decision",
                "object_id": "release-channel",
                "outcome": "accepted",
                "selected_event_ids": [first.event_id],
                "resolved_event_ids": [
                    first.event_id,
                    second.event_id,
                    owner_decision.event_id,
                    peer_decision.event_id,
                ],
                "reason": "Explicitly resolve the concurrent decisions",
            },
            parents=(owner_decision.event_id, peer_decision.event_id),
        )
        resolved = rebuild_domain_projection(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            actor_peer_id=self.owner.identity_id,
            scope_keys={1: self.key},
        )
        item = resolved["objects"][0]
        self.assertEqual(item["state"], "ready")
        self.assertEqual(item["selected_event_ids"], [first.event_id])
        self.assertEqual(item["decision_event_id"], final_decision.event_id)
        self.assertEqual(item["decision_conflict_event_ids"], [])

    def test_comments_reviews_evidence_and_approvals_are_append_only_attributed_history(self):
        memory = self._event(
            self.alice,
            1,
            {
                "event_type": "memory.asserted",
                "object_id": "atlas-architecture",
                "text": "Atlas uses a thin HTTP boundary",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
        )
        self._event(
            self.bob,
            1,
            {
                "event_type": "evidence.attached",
                "evidence_id": "atlas-readme",
                "object_id": "atlas-architecture",
                "source_identifier": "README.md",
                "source_hash": "a" * 64,
                "polarity": "supporting",
            },
            parents=(memory.event_id,),
        )
        self._event(
            self.bob,
            2,
            {
                "event_type": "comment.added",
                "comment_id": "comment-1",
                "object_id": "atlas-architecture",
                "text": "Verified against the synthetic fixture",
            },
            parents=(memory.event_id,),
        )
        review = self._event(
            self.alice,
            2,
            {
                "event_type": "review.requested",
                "review_id": "review-1",
                "object_id": "atlas-architecture",
                "summary": "Confirm the architecture statement",
            },
            parents=(memory.event_id,),
        )
        self._event(
            self.bob,
            3,
            {
                "event_type": "approval.proposed",
                "proposal_id": "approval-1",
                "object_id": "atlas-architecture",
                "review_id": "review-1",
                "outcome": "approve",
                "reason": "Source evidence matches",
            },
            parents=(review.event_id,),
        )

        result = rebuild_domain_projection(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            actor_peer_id=self.owner.identity_id,
            scope_keys={1: self.key},
        )
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["counts"], {
            "memories": 1,
            "evidence": 1,
            "comments": 1,
            "reviews": 1,
            "approvals": 1,
            "decisions": 0,
        })
        self.assertEqual(result["comments"][0]["author_peer_id"], self.bob.identity_id)
        self.assertEqual(result["approvals"][0]["outcome"], "approve")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.conn.execute(
                "UPDATE federation_domain_events SET payload_json = '{}' WHERE event_id = ?",
                (memory.event_id,),
            )

    def test_projection_rejects_unsupported_or_malformed_domain_payload(self):
        self._event(
            self.alice,
            1,
            {"event_type": "memory.asserted", "object_id": "missing-text"},
        )
        with self.assertRaisesRegex(ValueError, "text is required"):
            rebuild_domain_projection(
                self.conn,
                project_id=1,
                space_id=self.space["space_id"],
                actor_peer_id=self.owner.identity_id,
                scope_keys={1: self.key},
            )

    def test_projection_requires_current_index_capability_before_decryption(self):
        event = self._event(
            self.alice,
            1,
            {
                "event_type": "memory.asserted",
                "object_id": "index-boundary",
                "text": "confidential projection payload",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
        )
        revoke_capabilities(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            author=self.owner,
            subject_peer_id=self.alice.identity_id,
        )

        result = rebuild_domain_projection(
            self.conn,
            project_id=1,
            space_id=self.space["space_id"],
            actor_peer_id=self.alice.identity_id,
            scope_keys={1: self.key},
        )

        self.assertEqual(result["counts"]["memories"], 0)
        self.assertEqual(result["authorized_scope_count"], 0)
        self.assertIsNone(
            self.conn.execute(
                "SELECT 1 FROM federation_domain_events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
        )


if __name__ == "__main__":
    unittest.main()
