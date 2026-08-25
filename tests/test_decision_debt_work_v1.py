import tempfile
import unittest
from pathlib import Path

from rta_brain import db
from rta_brain.cognition import cognition_snapshot
from rta_brain.continuity import upsert_work_item


class OperationalDecisionDebtTests(unittest.TestCase):
    def test_unresolved_work_commitments_become_explainable_decision_debt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "README.md").write_text("# fixture\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                db.ingest_repo(conn, root, project="demo", force=True)
                upsert_work_item(
                    conn,
                    "demo",
                    "release",
                    "candidate-1",
                    qa_state="failed",
                    decision="blocked",
                    attempt_count=3,
                    fallback="restore the prior candidate",
                    next_action="repair the failing operator test",
                )
                snapshot = cognition_snapshot(
                    conn, project="demo", active_root=root,
                    include_change_impact=False,
                )
            finally:
                conn.close()

        item = next(
            row for row in snapshot["decision_debt"]["items"]
            if row["debt_id"] == "work:release:candidate-1"
        )
        self.assertEqual(item["source_type"], "work_item")
        self.assertEqual(item["severity"], "critical")
        self.assertEqual(item["repair"], "repair the failing operator test")
        self.assertIn("blocked_decision", item["reasons"])
        self.assertIn("failed_qa", item["reasons"])


if __name__ == "__main__":
    unittest.main()
