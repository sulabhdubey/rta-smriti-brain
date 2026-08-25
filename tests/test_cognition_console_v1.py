import hashlib
import json
import subprocess
import tempfile
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

from rta_brain.console_daemon import start_console, stop_console
from rta_brain.db import connect, ingest_repo, init_project


ROOT = Path(__file__).resolve().parents[1]


class CognitionConsoleApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.brain_dir = self.base / "brains"
        self.brain_dir.mkdir()
        self.root = self.base / "repo"
        self.root.mkdir()
        subprocess.run(["git", "init"], cwd=self.root, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.invalid"],
            cwd=self.root,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Rta Test"], cwd=self.root, check=True
        )
        (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
        (self.root / "proof.png").write_bytes(b"\x89PNG\r\n\x1a\nproof")
        subprocess.run(
            ["git", "add", "app.py", "proof.png"], cwd=self.root, check=True
        )
        subprocess.run(
            ["git", "commit", "-m", "fixture"], cwd=self.root, check=True
        )
        self.database = self.brain_dir / "demo.sqlite"
        conn = connect(self.database)
        try:
            init_project(conn, "demo", str(self.root))
            ingest_repo(conn, self.root, project="demo")
        finally:
            conn.close()
        started = start_console(
            ROOT, self.brain_dir, port=0, open_browser=False, startup_timeout=10.0
        )
        self.token = started["url"].split("#token=", 1)[1]
        self.base_url = f"http://127.0.0.1:{started['port']}"

    def tearDown(self):
        try:
            stop_console(self.brain_dir, timeout=5.0)
        finally:
            self.tmp.cleanup()

    def _get(self, path: str, **params):
        query = urllib.parse.urlencode(
            {"db_path": str(self.database), "project": "demo", **params}
        )
        request = urllib.request.Request(
            f"{self.base_url}{path}?{query}",
            headers={"X-Rta-Smriti-Token": self.token},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))

    def _post(self, path: str, payload: dict):
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(
                {"db_path": str(self.database), "project": "demo", **payload}
            ).encode("utf-8"),
            headers={
                "X-Rta-Smriti-Token": self.token,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))

    def test_cognition_and_multimodal_operator_contracts(self):
        initial = self._get("/api/cognition")
        self.assertEqual(initial["contract_version"], "1.0")
        observed = self._post(
            "/api/cognition",
            {
                "action": "observe",
                "observation_id": "release-ci",
                "subsystem": "delivery",
                "entity_key": "main-ci",
                "expected_state": "passing",
                "observed_state": "failing",
                "status": "conflicting",
                "source_identifier": "console://fixture",
                "source_hash": hashlib.sha256(b"fixture").hexdigest(),
                "evidence": {"run": "fixture"},
            },
        )
        self.assertFalse(observed["idempotent_replay"])
        snapshot = self._get("/api/cognition")
        self.assertIn("release-ci", json.dumps(snapshot["project_twin"]))
        reconciled = self._post(
            "/api/cognition",
            {
                "action": "reconcile",
                "observation_id": "release-ci",
                "receipt_id": "release-ci-resolved",
                "status": "observed",
                "reason": "Synthetic CI proof passed.",
                "evidence": {"run": "fixture-2"},
            },
        )
        self.assertEqual(reconciled["status"], "observed")

        source = self._post(
            "/api/multimodal",
            {"action": "add", "path": "proof.png", "privacy_class": "internal"},
        )
        listed = self._get("/api/multimodal", mode="sources")
        self.assertEqual(listed["items"][0]["source_id"], source["source_id"])
        verified = self._get(
            "/api/multimodal", mode="verify", source_id=source["source_id"]
        )
        self.assertEqual(verified["state"], "current")
        exported = self._get("/api/multimodal", mode="export", audience="public")
        self.assertEqual(exported["included"], 0)
        self.assertEqual(exported["redacted"], 1)


if __name__ == "__main__":
    unittest.main()
