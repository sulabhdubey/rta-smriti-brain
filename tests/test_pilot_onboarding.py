import json
import tempfile
import threading
import unittest
import urllib.request
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from rta_brain import console, db


ROOT = Path(__file__).resolve().parents[1]


class PilotConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "atlas"
        self.repo.mkdir()
        (self.repo / "README.md").write_text("# Atlas\nStore timestamps in UTC.\n")
        self.brains = self.root / "brains"
        self.database = self.brains / "atlas.sqlite"
        conn = db.connect(self.database)
        try:
            db.init_project(conn, "atlas", str(self.repo))
            db.ingest_repo(conn, self.repo, project="atlas")
            self.memory = db.remember(conn, "Atlas decisions use UTC timestamps.", project="atlas")
        finally:
            conn.close()
        self.server, self.config, url = console.create_dashboard_server(
            ROOT, self.brains, default_db=self.database, default_project="atlas", port=0,
        )
        self.url = url.split("/#", 1)[0].rstrip("/")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def post(self, endpoint, expected_status=200, **data):
        request = urllib.request.Request(
            self.url + endpoint,
            data=json.dumps({"db_path": str(self.database), "project": "atlas", **data}).encode(),
            headers={"Content-Type": "application/json", "X-Rta-Smriti-Token": self.config.capability_token},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                self.assertEqual(response.status, expected_status)
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == expected_status:
                return json.load(exc)
            self.fail(f"{endpoint}: {exc.code}: {exc.read().decode()}")

    def test_recovery_rejects_newer_schema_without_modifying_it(self):
        import sqlite3
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION + 1}")
        for endpoint, query in (("/api/search", {"query": "Atlas"}), ("/api/context-pack", {"task": "Atlas"})):
            result = self.post(endpoint, expected_status=400, **query)
            self.assertIn("newer schema", result["error"]["message"])
        with closing(sqlite3.connect(self.database)) as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION + 1)

    def test_recovery_reads_never_open_write_capable_connections(self):
        with patch.object(console, "_open_db", wraps=console._open_db) as writer:
            result = self.post("/api/search", query="Atlas decisions UTC")
            pack = self.post("/api/context-pack", task="Atlas decisions UTC")
        self.assertTrue(result["memories"])
        self.assertEqual(pack["status"], "ok")
        self.assertEqual(writer.call_count, 0, "recovery endpoints must be query-only")

    def test_console_capture_is_opt_in_and_forwards_explicit_flags(self):
        with patch("rta_brain.onboarding.onboard_project", return_value={"ready": True}) as setup:
            self.post("/api/bootstrap", path=str(self.repo))
            self.assertIs(setup.call_args.kwargs.get("start_continuity_capture"), False)
            self.assertIs(setup.call_args.kwargs.get("start_universal_capture"), False)
            self.post("/api/bootstrap", path=str(self.repo), start_sync=False,
                      start_continuity_capture=True, start_universal_capture=True)
            self.assertIs(setup.call_args.kwargs["start_sync"], False)
            self.assertIs(setup.call_args.kwargs["start_continuity_capture"], True)
            self.assertIs(setup.call_args.kwargs["start_universal_capture"], True)

    def test_recovery_works_during_an_active_writer_without_mutation(self):
        writer = db.connect(self.database)
        try:
            writer.execute("BEGIN IMMEDIATE")
            before = writer.total_changes
            for _ in range(3):
                result = self.post("/api/search", query="Atlas decisions UTC")
                self.assertTrue(result["memories"])
                self.assertEqual(result["access"], {"mode": "read_only", "writes_performed": False})
                self.assertEqual(self.post("/api/context-pack", task="Atlas UTC")["status"], "ok")
            self.assertEqual(writer.total_changes, before)
        finally:
            writer.rollback()
            writer.close()

    def test_string_capture_flags_do_not_grant_consent(self):
        with patch("rta_brain.onboarding.onboard_project", return_value={"ready": True}) as setup:
            self.post("/api/bootstrap", path=str(self.repo),
                      start_continuity_capture="true", start_universal_capture="false", write_agents="false")
            self.assertIs(setup.call_args.kwargs.get("start_continuity_capture"), False)
            self.assertIs(setup.call_args.kwargs.get("start_universal_capture"), False)
            self.assertIs(setup.call_args.kwargs.get("write_agents"), False)

    def test_saved_decision_survives_new_request_and_stays_unverified(self):
        saved = self.post("/api/memory", text="Atlas pilot uses UTC for every decision.",
                          type="decision", pramana="sabda", confidence=0.75,
                          provenance={"verification_status": "unverified", "metadata": {"source": "operator"}})
        result = self.post("/api/search", query="Atlas pilot UTC")
        recovered = next(m for m in result["memories"] if m["id"] == saved["memory"]["id"])
        self.assertEqual(recovered["text"], saved["memory"]["text"])
        self.assertEqual(recovered["project"], "atlas")
        self.assertNotEqual(saved["memory"]["provenance"]["verification_status"], "verified")
