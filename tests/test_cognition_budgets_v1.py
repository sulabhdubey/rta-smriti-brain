import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db
from rta_brain.cognition import cognition_snapshot, record_observation
from rta_brain.temporal import append_claim


from rta_brain.continuity import upsert_work_item
class CognitionBudgetTests(unittest.TestCase):
    def test_pathological_observations_stay_within_public_snapshot_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "README.md").write_text("# fixture\n", encoding="utf-8")
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", str(root))
                db.ingest_repo(conn, root, project="demo", force=True)
                payload = "x" * 4096
                for index in range(500):
                    record_observation(
                        conn,
                        project="demo",
                        active_root=root,
                        observation_id=f"observation-{index:04d}",
                        subsystem="external-system",
                        entity_key=f"entity-{index:04d}",
                        expected_state=payload,
                        observed_state=payload,
                        status="conflicting",
                        source_identifier=f"adapter://fixture/{index:04d}/" + ("s" * 512),
                    )
                snapshot = cognition_snapshot(
                    conn,
                    project="demo",
                    active_root=root,
                    include_change_impact=False,
                )
            finally:
                conn.close()

        encoded = json.dumps(
            snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.assertLessEqual(len(encoded), 512 * 1024)
        self.assertTrue(snapshot["output_budget"]["truncated"])
        self.assertEqual(snapshot["output_budget"]["maximum_bytes"], 512 * 1024)
        self.assertGreater(snapshot["project_twin"]["observation_count"], 0)
        self.assertLess(
            len(snapshot["project_twin"]["observations"]),
            snapshot["project_twin"]["observation_count"],
        )
        self.assertGreater(snapshot["project_twin"]["conflict_count"], 0)
        self.assertLess(
            len(snapshot["project_twin"]["conflicts"]),
            snapshot["project_twin"]["conflict_count"],
        )

    def test_truth_projection_overflow_fails_closed_as_critical_debt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "README.md").write_text("# fixture\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                db.ingest_repo(conn, root, project="demo", force=True)
                for index in range(3):
                    append_claim(
                        conn, project="demo", active_root=root,
                        subject=f"decision:{index}", predicate="status", value="active",
                        claim_id=f"decision-{index}", idempotency_key=f"budget:{index}",
                        expected_stream_version=0, epistemic_state="accepted",
                        authority_class="operator", confidence=0.9,
                        verification_status="verified",
                    )
                with patch("rta_brain.cognition.MAX_TRUTH_PROJECTION_ROWS", 2):
                    snapshot = cognition_snapshot(
                        conn, project="demo", active_root=root,
                        include_change_impact=False,
                    )
            finally:
                conn.close()

        debt = {
            item["debt_id"]: item for item in snapshot["decision_debt"]["items"]
        }
        self.assertIn("system:truth-projection-budget", debt)
        self.assertEqual(debt["system:truth-projection-budget"]["severity"], "critical")
        self.assertIn(
            "claims_projection_truncated",
            debt["system:truth-projection-budget"]["reasons"],
        )
        self.assertGreaterEqual(snapshot["knowledge_coverage"]["summary"]["blocked"], 1)
        self.assertFalse(snapshot["readiness"]["continuation_ready"])

    def test_observation_and_work_projection_overflow_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "README.md").write_text("# fixture\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                db.ingest_repo(conn, root, project="demo", force=True)
                for index in range(3):
                    record_observation(
                        conn,
                        project="demo",
                        active_root=root,
                        observation_id=f"observation-{index}",
                        subsystem="ci",
                        entity_key=f"job-{index}",
                        observed_state="pending",
                        status="observed",
                        source_identifier=f"ci://job/{index}",
                    )
                    upsert_work_item(
                        conn,
                        "demo",
                        "job",
                        f"job-{index}",
                        qa_state="pending",
                        decision="pending",
                    )
                with (
                    patch("rta_brain.cognition.MAX_OBSERVATIONS", 2),
                    patch("rta_brain.cognition.MAX_WORK_ITEMS", 2),
                ):
                    snapshot = cognition_snapshot(
                        conn,
                        project="demo",
                        active_root=root,
                        include_change_impact=False,
                    )
            finally:
                conn.close()

        self.assertEqual(snapshot["project_twin"]["observation_count"], 5)
        self.assertEqual(snapshot["project_twin"]["work_item_count"], 3)
        self.assertIn("observation_projection_truncated", snapshot["readiness"]["reasons"])
        self.assertIn("work_state_projection_truncated", snapshot["readiness"]["reasons"])
        debt_ids = {item["debt_id"] for item in snapshot["decision_debt"]["items"]}
        self.assertIn("system:work-state-projection-budget", debt_ids)
        self.assertFalse(snapshot["readiness"]["continuation_ready"])

    def test_decision_debt_preserves_total_when_items_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "README.md").write_text("# fixture\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                db.ingest_repo(conn, root, project="demo", force=True)
                for index in range(3):
                    upsert_work_item(
                        conn,
                        "demo",
                        "release",
                        f"candidate-{index}",
                        qa_state="failed",
                        decision="blocked",
                        next_action="repair the release proof",
                    )
                with patch("rta_brain.cognition.MAX_DEBT_ITEMS", 2):
                    snapshot = cognition_snapshot(
                        conn,
                        project="demo",
                        active_root=root,
                        include_change_impact=False,
                    )
            finally:
                conn.close()

        self.assertEqual(snapshot["decision_debt"]["count"], 3)
        self.assertEqual(len(snapshot["decision_debt"]["items"]), 2)
        self.assertTrue(snapshot["decision_debt"]["truncated"])


if __name__ == "__main__":
    unittest.main()
