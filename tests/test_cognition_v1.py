import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from rta_brain import db
from rta_brain.continuity import init_continuity_schema, upsert_work_item
from rta_brain.temporal import append_claim, attach_evidence


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


class CognitionSchemaTests(unittest.TestCase):
    def test_schema_v11_adds_cognition_and_multimodal_tables_idempotently(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.init_schema(conn)
                db.init_schema(conn)
                tables = {
                    row["name"]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 11)
                self.assertTrue(
                    {
                        "cognition_observations",
                        "cognition_reconciliation_receipts",
                        "multimodal_sources",
                        "multimodal_derivations",
                    }.issubset(tables)
                )
            finally:
                conn.close()


class CognitionProjectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        _git(self.root, "init")
        _git(self.root, "config", "user.email", "test@example.invalid")
        _git(self.root, "config", "user.name", "Rta Test")
        (self.root / "app.py").write_text("def answer():\n    return 42\n", encoding="utf-8")
        (self.root / "test_app.py").write_text(
            "from app import answer\n\ndef test_answer():\n    assert answer() == 42\n",
            encoding="utf-8",
        )
        _git(self.root, "add", "app.py", "test_app.py")
        _git(self.root, "commit", "-m", "baseline")
        self.conn = db.connect(self.base / "brain.sqlite")
        db.init_project(self.conn, "demo", str(self.root))
        db.ingest_repo(self.conn, self.root, project="demo", force=True)
        init_continuity_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _claim(self, claim_id: str, *, state: str, expires_at: str | None = None):
        return append_claim(
            self.conn,
            project="demo",
            active_root=self.root,
            subject=f"decision:{claim_id}",
            predicate="status",
            value="enabled",
            claim_id=claim_id,
            idempotency_key=f"test:{claim_id}",
            expected_stream_version=0,
            epistemic_state=state,
            authority_class="operator",
            confidence=0.95,
            verification_status="verified",
            expires_at=expires_at,
        )

    def test_snapshot_exposes_unsupported_and_expired_decision_debt(self):
        self._claim("unsupported", state="accepted")
        self._claim(
            "expired",
            state="accepted",
            expires_at="2020-01-01T00:00:00+00:00",
        )
        supported = self._claim("supported", state="accepted")
        attach_evidence(
            self.conn,
            project="demo",
            active_root=self.root,
            claim_id=supported["claim"]["claim_id"],
            evidence_id="evidence-supported",
            source_identifier="test_app.py",
            source_hash=hashlib.sha256(
                (self.root / "test_app.py").read_bytes()
            ).hexdigest(),
            method="pytest",
            polarity="supporting",
            authority_class="pratyaksha",
            confidence=1.0,
            provenance={"command": "pytest", "verification_status": "verified"},
            idempotency_key="test:evidence-supported",
            expected_stream_version=0,
            verification_status="verified",
        )

        from rta_brain.cognition import cognition_snapshot

        before = self.conn.total_changes
        first = cognition_snapshot(
            self.conn,
            project="demo",
            active_root=self.root,
            now="2026-08-25T00:00:00+00:00",
        )
        second = cognition_snapshot(
            self.conn,
            project="demo",
            active_root=self.root,
            now="2026-08-25T00:00:00+00:00",
        )

        self.assertEqual(self.conn.total_changes, before)
        self.assertEqual(first["digest"], second["digest"])
        debt = {item["claim_id"]: item for item in first["decision_debt"]["items"]}
        self.assertIn("unsupported", debt)
        self.assertIn("expired", debt)
        self.assertNotIn("supported", debt)
        self.assertIn("missing_supporting_evidence", debt["unsupported"]["reasons"])
        self.assertIn("expired", debt["expired"]["reasons"])
        self.assertNotIn(str(self.base), json.dumps(first))

    def test_twin_and_coverage_distinguish_fresh_bytes_from_operational_truth(self):
        self._claim("unverified", state="observed")
        upsert_work_item(
            self.conn,
            project="demo",
            item_type="approval",
            external_id="release-approval",
            qa_state="unknown",
            decision="pending",
            next_action="Owner review",
        )
        from rta_brain.cognition import cognition_snapshot

        result = cognition_snapshot(
            self.conn,
            project="demo",
            active_root=self.root,
            now="2026-08-25T00:00:00+00:00",
        )

        self.assertTrue(result["identity"]["canonical_match"])
        self.assertEqual(result["repository"]["freshness"], "fresh")
        self.assertEqual(result["repository"]["freshness_mode"], "index-snapshot")
        self.assertFalse(result["readiness"]["continuation_ready"])
        self.assertIn("pending_work", result["readiness"]["reasons"])
        truth = result["knowledge_coverage"]["subsystems"]["truth"]
        self.assertGreaterEqual(truth["known"], 1)
        self.assertEqual(truth["verified"], 0)
        self.assertNotEqual(
            result["knowledge_coverage"]["summary"]["verified_ratio"], 1.0
        )

    def test_change_impact_links_changed_file_to_symbols_and_tests(self):
        (self.root / "app.py").write_text(
            "def answer():\n    return 43\n", encoding="utf-8"
        )
        from rta_brain.cognition import cognition_snapshot

        result = cognition_snapshot(
            self.conn,
            project="demo",
            active_root=self.root,
            now="2026-08-25T00:00:00+00:00",
        )
        impact = result["change_impact"]
        self.assertEqual(impact["state"], "changed")
        self.assertIn("app.py", impact["changed_paths"])
        linked = [item for item in impact["items"] if item["path"] == "app.py"]
        self.assertEqual(len(linked), 1)
        self.assertTrue(linked[0]["symbols"])
        self.assertIn("test_app.py", linked[0]["related_tests"])
        self.assertIn(linked[0]["confidence"], {"direct", "approximate"})


class MultimodalEvidenceTests(unittest.TestCase):
    def test_ingestion_preserves_source_and_derived_observation_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            media = root / "proof.png"
            media.write_bytes(b"\x89PNG\r\n\x1a\n" + b"synthetic-proof")
            conn = db.connect(base / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.multimodal import add_derivation, ingest_media

                source = ingest_media(
                    conn,
                    project="demo",
                    active_root=root,
                    path=media,
                    privacy_class="internal",
                    sharing_policy="local-only",
                )
                derived = add_derivation(
                    conn,
                    project="demo",
                    source_id=source["source_id"],
                    method="operator-caption",
                    text="The screenshot shows the synthetic proof fixture.",
                    confidence=0.8,
                    verification_status="unverified",
                    tool_identity="operator",
                )

                self.assertEqual(source["media_kind"], "image")
                self.assertEqual(len(source["content_sha256"]), 64)
                self.assertEqual(derived["verification_status"], "unverified")
                self.assertNotIn(str(root), json.dumps(source))
                with self.assertRaises(PermissionError):
                    add_derivation(
                        conn,
                        project="demo",
                        source_id=source["source_id"],
                        method="local-model",
                        text="Model assertion",
                        confidence=1.0,
                        verification_status="verified",
                        tool_identity="model:test",
                    )
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
