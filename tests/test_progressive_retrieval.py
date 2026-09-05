import json
import tempfile
import unittest
from pathlib import Path

from rta_brain import db
from rta_brain.progressive_retrieval import ProgressiveRetriever
from rta_brain.temporal import (
    append_claim,
    attach_evidence,
    relate_claims,
    revise_claim,
)


class ProgressiveRetrievalTests(unittest.TestCase):
    def _seed_snapshot_sources(self, tmp: str):
        root = Path(tmp) / "repo"
        root.mkdir()
        (root / "ARCHITECTURE.md").write_text(
            "policy gate " + ("stable architecture evidence " * 32),
            encoding="utf-8",
        )
        conn = db.connect(Path(tmp) / "brain.sqlite")
        db.init_project(conn, "demo", root)
        db.ingest_repo(conn, root, project="demo")
        memory = db.remember(
            conn,
            "The policy gate must fail closed.",
            project="demo",
            memory_type="decision",
            metadata={"privacy_class": "internal"},
            provenance={
                "source_path": "ARCHITECTURE.md",
                "verification_status": "verified",
                "metadata": {"review": "operator"},
            },
        )
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id="policy-gate",
            subject="policy gate",
            predicate="mode",
            value="fail-closed",
            authority_class="operator",
            verification_status="verified",
            idempotency_key="policy-gate:1",
            expected_stream_version=0,
        )
        retriever = ProgressiveRetriever(b"test-secret")
        index = retriever.retrieve(
            conn,
            project="demo",
            query="policy gate",
            stage="index",
            limit=20,
        )
        return root, conn, retriever, memory, index

    def _assert_snapshot_stale(self, retriever, conn, index):
        with self.assertRaisesRegex(PermissionError, "snapshot is stale"):
            retriever.retrieve(
                conn,
                project="demo",
                stage="evidence",
                expansion_handle=index["expansion_handle"],
            )

    def test_handle_expires_when_selected_memory_text_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, conn, retriever, memory, index = self._seed_snapshot_sources(tmp)
            try:
                conn.execute(
                    "UPDATE memories SET text = ? WHERE id = ?",
                    ("The policy gate is now permissive.", memory["memory"]["id"]),
                )
                conn.commit()

                self._assert_snapshot_stale(retriever, conn, index)
            finally:
                conn.close()

    def test_handle_expires_when_selected_chunk_tail_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, conn, retriever, _, index = self._seed_snapshot_sources(tmp)
            try:
                chunk_id = next(
                    item["id"] for item in index["items"] if item["kind"] == "chunk"
                )
                original = conn.execute(
                    "SELECT text FROM chunks WHERE id = ?", (chunk_id,)
                ).fetchone()["text"]
                self.assertGreater(len(original), 500)
                conn.execute(
                    "UPDATE chunks SET text = ? WHERE id = ?",
                    (original[:-1] + ("x" if original[-1] != "x" else "y"), chunk_id),
                )
                conn.commit()

                self._assert_snapshot_stale(retriever, conn, index)
            finally:
                conn.close()

    def test_handle_expires_when_selected_truth_content_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, conn, retriever, _, index = self._seed_snapshot_sources(tmp)
            try:
                revise_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="policy-gate",
                    value="fail-open",
                    reason="regression mutation",
                    idempotency_key="policy-gate:2",
                    expected_stream_version=1,
                )

                self._assert_snapshot_stale(retriever, conn, index)
            finally:
                conn.close()

    def test_handle_expires_when_selected_truth_authority_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, conn, retriever, _, index = self._seed_snapshot_sources(tmp)
            try:
                conn.execute(
                    """
                    UPDATE truth_claim_versions SET authority_class = 'agent-unverified'
                    WHERE claim_id = 'policy-gate' AND recorded_to_sequence IS NULL
                    """
                )
                conn.commit()

                self._assert_snapshot_stale(retriever, conn, index)
            finally:
                conn.close()

    def test_handle_expires_when_selected_truth_privacy_policy_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, conn, retriever, _, index = self._seed_snapshot_sources(tmp)
            try:
                conn.execute(
                    """
                    UPDATE truth_claim_versions SET sharing_policy = 'workspace-only'
                    WHERE claim_id = 'policy-gate' AND recorded_to_sequence IS NULL
                    """
                )
                conn.commit()

                self._assert_snapshot_stale(retriever, conn, index)
            finally:
                conn.close()

    def test_handle_expires_when_selected_truth_validity_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, conn, retriever, _, index = self._seed_snapshot_sources(tmp)
            try:
                conn.execute(
                    """
                    UPDATE truth_claim_versions SET valid_to = '2999-01-01T00:00:00Z'
                    WHERE claim_id = 'policy-gate' AND recorded_to_sequence IS NULL
                    """
                )
                conn.commit()

                self._assert_snapshot_stale(retriever, conn, index)
            finally:
                conn.close()

    def test_handle_expires_when_selected_truth_contradictions_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, conn, retriever, _, _ = self._seed_snapshot_sources(tmp)
            try:
                for claim_id in ("alternate-a", "alternate-b"):
                    append_claim(
                        conn,
                        project="demo",
                        active_root=root,
                        claim_id=claim_id,
                        subject=claim_id,
                        predicate="mode",
                        value="fail-open",
                        idempotency_key=f"{claim_id}:1",
                        expected_stream_version=0,
                    )
                relate_claims(
                    conn,
                    project="demo",
                    active_root=root,
                    from_claim_id="policy-gate",
                    relation_type="contradicts",
                    to_claim_id="alternate-a",
                    relation_id="policy-conflict-a",
                    idempotency_key="policy-conflict-a:1",
                    expected_stream_version=0,
                )
                index = retriever.retrieve(
                    conn, project="demo", query="policy gate", stage="index"
                )
                relate_claims(
                    conn,
                    project="demo",
                    active_root=root,
                    from_claim_id="policy-gate",
                    relation_type="contradicts",
                    to_claim_id="alternate-b",
                    relation_id="policy-conflict-b",
                    idempotency_key="policy-conflict-b:1",
                    expected_stream_version=0,
                )

                self._assert_snapshot_stale(retriever, conn, index)
            finally:
                conn.close()

    def test_handle_expires_when_selected_truth_citation_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, conn, retriever, _, index = self._seed_snapshot_sources(tmp)
            try:
                attach_evidence(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="policy-gate",
                    evidence_id="operator-review",
                    source_identifier=str(root / "PRIVATE-REVIEW.md"),
                    method="operator-review",
                    polarity="supporting",
                    authority_class="operator",
                    confidence=0.9,
                    provenance={"review": "manual"},
                    idempotency_key="operator-review:1",
                    expected_stream_version=0,
                )

                self._assert_snapshot_stale(retriever, conn, index)
            finally:
                conn.close()

    def test_timeline_handle_expires_when_latest_checkpoint_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, conn, retriever, _, _ = self._seed_snapshot_sources(tmp)
            try:
                db.save_checkpoint(conn, "demo", "First verified checkpoint")
                index = retriever.retrieve(
                    conn, project="demo", query="policy gate", stage="index"
                )

                db.save_checkpoint(conn, "demo", "Replacement verified checkpoint")

                with self.assertRaisesRegex(PermissionError, "snapshot is stale"):
                    retriever.retrieve(
                        conn,
                        project="demo",
                        stage="timeline",
                        expansion_handle=index["expansion_handle"],
                    )
            finally:
                conn.close()

    def test_timeline_handle_expires_when_event_stream_head_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, conn, retriever, _, index = self._seed_snapshot_sources(tmp)
            try:
                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="unrelated-timeline-event",
                    subject="orbital schedule",
                    predicate="mode",
                    value="night",
                    idempotency_key="unrelated-timeline-event:1",
                    expected_stream_version=0,
                )

                with self.assertRaisesRegex(PermissionError, "snapshot is stale"):
                    retriever.retrieve(
                        conn,
                        project="demo",
                        stage="timeline",
                        expansion_handle=index["expansion_handle"],
                    )
            finally:
                conn.close()

    def test_timeline_identity_is_scoped_to_the_selected_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, conn, retriever, _, index = self._seed_snapshot_sources(tmp)
            try:
                other_root = root.parent / "other-repo"
                other_root.mkdir()
                db.init_project(conn, "other", other_root)
                db.save_checkpoint(conn, "other", "Other project checkpoint")
                append_claim(
                    conn,
                    project="other",
                    active_root=other_root,
                    claim_id="other-project-event",
                    subject="other project",
                    predicate="mode",
                    value="changed",
                    idempotency_key="other-project-event:1",
                    expected_stream_version=0,
                )

                timeline = retriever.retrieve(
                    conn,
                    project="demo",
                    stage="timeline",
                    expansion_handle=index["expansion_handle"],
                )

                self.assertEqual(timeline["status"], "ok")
            finally:
                conn.close()

    def test_evidence_includes_bounded_provenance_refs_without_private_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, conn, retriever, _, _ = self._seed_snapshot_sources(tmp)
            try:
                attach_evidence(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="policy-gate",
                    evidence_id="operator-review",
                    source_identifier=str(root / "PRIVATE-REVIEW.md"),
                    source_hash="a" * 64,
                    method="operator-review",
                    polarity="supporting",
                    authority_class="operator",
                    confidence=0.9,
                    provenance={"review": "manual"},
                    idempotency_key="operator-review:1",
                    expected_stream_version=0,
                )
                index = retriever.retrieve(
                    conn, project="demo", query="policy gate", stage="index"
                )
                evidence = retriever.retrieve(
                    conn,
                    project="demo",
                    stage="evidence",
                    expansion_handle=index["expansion_handle"],
                )
                serialized = json.dumps(evidence)

                self.assertIn("provenance_reported", evidence["report"])
                self.assertTrue(evidence["report"]["provenance_reported"])
                self.assertTrue(
                    all(item.get("provenance_refs") for item in evidence["items"])
                )
                truth = next(
                    item for item in evidence["items"] if item["kind"] == "truth"
                )
                self.assertIn(
                    "operator-review",
                    {ref.get("evidence_id") for ref in truth["provenance_refs"]},
                )
                self.assertNotIn(str(root), serialized)
                self.assertNotIn("PRIVATE-REVIEW.md", serialized)
            finally:
                conn.close()

    def test_truth_snapshot_binding_is_scoped_to_the_selected_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            other_root = Path(tmp) / "other"
            demo_root = Path(tmp) / "demo"
            other_root.mkdir()
            demo_root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "other", other_root)
                db.init_project(conn, "demo", demo_root)
                for project, root, value in (
                    ("other", other_root, "other-value"),
                    ("demo", demo_root, "demo-value"),
                ):
                    append_claim(
                        conn,
                        project=project,
                        active_root=root,
                        claim_id="shared-claim-id",
                        subject="shared policy gate",
                        predicate="mode",
                        value=value,
                        idempotency_key=f"{project}:shared-claim-id:1",
                        expected_stream_version=0,
                    )
                retriever = ProgressiveRetriever(b"test-secret")
                index = retriever.retrieve(
                    conn, project="demo", query="shared policy", stage="index"
                )
                revise_claim(
                    conn,
                    project="other",
                    active_root=other_root,
                    claim_id="shared-claim-id",
                    value="changed-other-value",
                    reason="other project mutation",
                    idempotency_key="other:shared-claim-id:2",
                    expected_stream_version=1,
                )

                try:
                    evidence = retriever.retrieve(
                        conn,
                        project="demo",
                        stage="evidence",
                        expansion_handle=index["expansion_handle"],
                    )
                except PermissionError as exc:
                    self.fail(f"other-project mutation invalidated demo handle: {exc}")

                self.assertEqual(evidence["status"], "ok")
                self.assertIn("demo-value", json.dumps(evidence["items"]))
                self.assertNotIn("changed-other-value", json.dumps(evidence["items"]))
            finally:
                conn.close()

    def test_public_ceiling_excludes_internal_repository_chunks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            marker = "INTERNAL-REPOSITORY-MARKER-7F91"
            (root / "PRIVATE-NOTES.md").write_text(
                f"{marker} lifecycle evidence", encoding="utf-8"
            )
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", root)
                db.ingest_repo(conn, root, project="demo")
                retriever = ProgressiveRetriever(b"test-secret")

                index = retriever.retrieve(
                    conn,
                    project="demo",
                    query=marker,
                    stage="index",
                    privacy_ceiling="public",
                )
                evidence = retriever.retrieve(
                    conn,
                    project="demo",
                    stage="evidence",
                    expansion_handle=index["expansion_handle"],
                    privacy_ceiling="public",
                )

                self.assertEqual(index["items"], [])
                self.assertEqual(evidence["items"], [])
                self.assertGreaterEqual(index["report"]["privacy_filtered_count"], 1)
                self.assertNotIn(marker, json.dumps((index, evidence)))
            finally:
                conn.close()

    def test_index_rejects_queries_too_large_for_the_handle_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", root)
                retriever = ProgressiveRetriever(b"test-secret")

                with self.assertRaisesRegex(ValueError, "query.*size limit"):
                    retriever.retrieve(
                        conn,
                        project="demo",
                        query="q" * 10_001,
                        stage="index",
                    )
                self.assertEqual(retriever._handles, {})
            finally:
                conn.close()

    def test_restricted_and_unknown_memories_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", root)
                db.remember(
                    conn,
                    "Restricted policy evidence",
                    project="demo",
                    metadata={"privacy_class": "restricted"},
                )
                db.remember(
                    conn,
                    "Unknown policy evidence",
                    project="demo",
                    metadata={"privacy_class": "future-class"},
                )
                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="restricted-policy",
                    subject="policy evidence",
                    predicate="contains",
                    value="restricted timeline value",
                    privacy_class="restricted",
                    idempotency_key="restricted-policy:1",
                    expected_stream_version=0,
                )
                db.save_checkpoint(
                    conn,
                    "demo",
                    "Private continuity objective",
                    source="private-checkpoint-source",
                    trigger="private-checkpoint-trigger",
                )
                retriever = ProgressiveRetriever(b"test-secret")

                result = retriever.retrieve(
                    conn,
                    project="demo",
                    query="policy evidence",
                    stage="index",
                    privacy_ceiling="internal",
                )

                self.assertEqual(result["items"], [])
                self.assertEqual(result["report"]["privacy_filtered_count"], 3)
                timeline = retriever.retrieve(
                    conn,
                    project="demo",
                    stage="timeline",
                    expansion_handle=result["expansion_handle"],
                )
                self.assertNotIn("restricted-policy", json.dumps(timeline["items"]))
                self.assertNotIn("private-checkpoint", json.dumps(timeline["items"]))
                with self.assertRaisesRegex(ValueError, "privacy ceiling"):
                    retriever.retrieve(
                        conn,
                        project="demo",
                        query="policy evidence",
                        stage="index",
                        privacy_ceiling="future-class",
                    )
            finally:
                conn.close()

    def test_handles_are_bounded_and_oldest_handle_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "README.md").write_text(
                "alpha beta gamma lifecycle evidence", encoding="utf-8"
            )
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", root)
                db.ingest_repo(conn, root, project="demo")
                retriever = ProgressiveRetriever(b"test-secret", max_handles=2)
                handles = [
                    retriever.retrieve(
                        conn, project="demo", query=query, stage="index"
                    )["expansion_handle"]
                    for query in ("alpha", "beta", "gamma")
                ]

                with self.assertRaisesRegex(PermissionError, "expired"):
                    retriever.retrieve(
                        conn,
                        project="demo",
                        stage="timeline",
                        expansion_handle=handles[0],
                    )
                latest = retriever.retrieve(
                    conn,
                    project="demo",
                    stage="timeline",
                    expansion_handle=handles[-1],
                )
                self.assertEqual(latest["status"], "ok")
            finally:
                conn.close()

    def test_expansion_never_uses_a_broader_ceiling_than_the_current_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", root)
                db.remember(
                    conn,
                    "shared phrase public evidence",
                    project="demo",
                    metadata={"privacy_class": "public"},
                )
                db.remember(
                    conn,
                    "shared phrase internal evidence",
                    project="demo",
                    metadata={"privacy_class": "internal"},
                )
                retriever = ProgressiveRetriever(b"test-secret")
                index = retriever.retrieve(
                    conn,
                    project="demo",
                    query="shared phrase",
                    stage="index",
                    privacy_ceiling="internal",
                )

                expanded = retriever.retrieve(
                    conn,
                    project="demo",
                    stage="evidence",
                    expansion_handle=index["expansion_handle"],
                    privacy_ceiling="public",
                )

                rendered = json.dumps(expanded)
                self.assertIn("public evidence", rendered)
                self.assertNotIn("internal evidence", rendered)
                self.assertEqual(expanded["privacy_ceiling"], "public")
            finally:
                conn.close()

    def test_index_stage_enforces_its_token_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", root)
                for index in range(12):
                    db.remember(
                        conn,
                        f"Lifecycle evidence record {index}",
                        project="demo",
                        metadata={"privacy_class": "internal"},
                    )
                retriever = ProgressiveRetriever(b"test-secret")

                result = retriever.retrieve(
                    conn,
                    project="demo",
                    query="lifecycle evidence",
                    stage="index",
                    limit=12,
                    max_tokens=64,
                )

                self.assertLessEqual(result["report"]["token_estimate"], 64)
                self.assertTrue(result["report"]["truncated"])
                self.assertGreater(result["report"]["omitted_count"], 0)
            finally:
                conn.close()

    def test_index_timeline_and_evidence_are_snapshot_bound_and_budgeted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "ARCHITECTURE.md").write_text(
                "Atlas routes requests through a policy gate before persistence.",
                encoding="utf-8",
            )
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
                db.ingest_repo(conn, root, project="demo")
                db.remember(
                    conn,
                    "The policy gate must fail closed.",
                    project="demo",
                    memory_type="decision",
                )
                retriever = ProgressiveRetriever(b"test-secret")

                index = retriever.retrieve(
                    conn, project="demo", query="policy gate", stage="index"
                )
                self.assertEqual(index["stage"], "index")
                self.assertTrue(index["expansion_handle"])
                self.assertNotIn("fail closed", str(index["items"]).lower())
                self.assertIn("token_estimate", index["report"])
                self.assertIn("omitted_count", index["report"])
                self.assertIn("privacy_filtered_count", index["report"])

                timeline = retriever.retrieve(
                    conn,
                    project="demo",
                    stage="timeline",
                    expansion_handle=index["expansion_handle"],
                )
                self.assertEqual(timeline["snapshot_digest"], index["snapshot_digest"])
                self.assertEqual(timeline["stage"], "timeline")

                evidence = retriever.retrieve(
                    conn,
                    project="demo",
                    stage="evidence",
                    expansion_handle=index["expansion_handle"],
                    max_tokens=80,
                )
                self.assertEqual(evidence["stage"], "evidence")
                self.assertLessEqual(evidence["report"]["token_estimate"], 80)
                self.assertTrue(evidence["items"])
            finally:
                conn.close()

    def test_tampered_or_cross_project_handle_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "README.md").write_text("Atlas policy gate", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", root)
                db.ingest_repo(conn, root, project="demo")
                retriever = ProgressiveRetriever(b"test-secret")
                index = retriever.retrieve(
                    conn, project="demo", query="policy", stage="index"
                )
                tampered = index["expansion_handle"][:-1] + (
                    "A" if index["expansion_handle"][-1] != "A" else "B"
                )
                with self.assertRaisesRegex(PermissionError, "handle"):
                    retriever.retrieve(
                        conn,
                        project="demo",
                        stage="evidence",
                        expansion_handle=tampered,
                    )
                with self.assertRaisesRegex(PermissionError, "project"):
                    retriever.retrieve(
                        conn,
                        project="other",
                        stage="timeline",
                        expansion_handle=index["expansion_handle"],
                    )
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
