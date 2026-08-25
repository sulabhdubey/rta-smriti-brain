import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path

from rta_brain import db


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    )


class CognitionReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        _git(self.root, "init")
        _git(self.root, "config", "user.email", "test@example.invalid")
        _git(self.root, "config", "user.name", "Rta Test")
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        _git(self.root, "add", "app.py")
        _git(self.root, "commit", "-m", "baseline")
        self.conn = db.connect(self.base / "brain.sqlite")
        db.init_project(self.conn, "demo", str(self.root))
        db.ingest_repo(self.conn, self.root, project="demo", force=True)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _record(self, observation_id: str = "ci-state"):
        from rta_brain.cognition import record_observation

        return record_observation(
            self.conn,
            project="demo",
            active_root=self.root,
            observation_id=observation_id,
            subsystem="delivery",
            entity_key="main-ci",
            expected_state="passing",
            observed_state="failing",
            status="conflicting",
            source_identifier="adapter://github-actions",
            source_hash="a" * 64,
            evidence={"run_id": "fixture-1"},
            observed_at="2026-08-25T00:00:00+00:00",
        )

    def test_reconciliation_is_operator_gated_idempotent_and_immutable(self):
        from rta_brain.cognition import reconcile_observation

        created = self._record()
        replay = self._record()
        self.assertFalse(created["idempotent_replay"])
        self.assertTrue(replay["idempotent_replay"])

        with self.assertRaises(PermissionError):
            reconcile_observation(
                self.conn,
                project="demo",
                active_root=self.root,
                observation_id="ci-state",
                receipt_id="resolve-ci",
                action="set_status",
                outcome="observed",
                reason="CI recovered in the verified fixture.",
                actor_type="agent",
                actor_id="agent-1",
                evidence={"run_id": "fixture-2"},
            )
        receipt = reconcile_observation(
            self.conn,
            project="demo",
            active_root=self.root,
            observation_id="ci-state",
            receipt_id="resolve-ci",
            action="set_status",
            outcome="observed",
            reason="CI recovered in the verified fixture.",
            actor_type="operator",
            actor_id="operator-fixture",
            evidence={"run_id": "fixture-2"},
            created_at="2026-08-25T00:10:00+00:00",
        )
        receipt_replay = reconcile_observation(
            self.conn,
            project="demo",
            active_root=self.root,
            observation_id="ci-state",
            receipt_id="resolve-ci",
            action="set_status",
            outcome="observed",
            reason="CI recovered in the verified fixture.",
            actor_type="operator",
            actor_id="operator-fixture",
            evidence={"run_id": "fixture-2"},
            created_at="2026-08-25T00:10:00+00:00",
        )
        self.assertFalse(receipt["idempotent_replay"])
        self.assertTrue(receipt_replay["idempotent_replay"])
        self.assertEqual(receipt["status"], "observed")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "UPDATE cognition_reconciliation_receipts SET reason = 'changed'"
            )

    def test_conflicts_are_governed_context_candidates(self):
        from rta_brain.context_candidates import adapt_context_candidates

        self._record("deploy-conflict")
        adapted = adapt_context_candidates(self.conn, project="demo")
        cognition = [
            item for item in adapted["candidates"]
            if item["source_type"] == "cognition"
        ]
        self.assertTrue(cognition)
        self.assertTrue(any("deploy-conflict" in json.dumps(item) for item in cognition))
        self.assertTrue(any(item["epistemic_state"] == "disputed" for item in cognition))


if __name__ == "__main__":
    unittest.main()
