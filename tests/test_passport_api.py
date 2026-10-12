import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from rta_brain import console, db


class PassportApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "atlas"
        self.repo.mkdir()
        self.brains = self.root / "brains"
        self.path = self.brains / "atlas.sqlite"
        with closing(db.connect(self.path)) as conn:
            db.init_project(conn, "atlas", str(self.repo))
            db.save_checkpoint(conn, "atlas", "Resume operator acceptance")
        self.server, self.config, url = console.create_dashboard_server(
            Path(__file__).resolve().parents[1], self.brains, default_db=self.path,
            default_project="atlas", port=0,
        )
        self.url = url.split("/#", 1)[0].rstrip("/")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temp.cleanup()

    def post(self, data=None, *, token=True, status=200):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Rta-Smriti-Token"] = self.config.capability_token
        request = urllib.request.Request(self.url + "/api/passport", headers=headers,
            data=json.dumps({"db_path": str(self.path), "project": "atlas", **(data or {})}).encode())
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                self.assertEqual(response.status, status)
                return json.load(response)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, status, exc.read().decode())

    def test_inspect_and_preview_are_query_only_under_writer(self):
        with closing(db.connect(self.path)) as writer, patch.object(console, "_open_db", side_effect=AssertionError("write connector")):
            writer.execute("BEGIN IMMEDIATE")
            result = self.post()
            preview = self.post({"action": "preview", "revision": result["revision"],
                                 "selection": {"checkpoint_fields": ["objective"]}})
            self.assertIn("Resume operator acceptance", preview["markdown"])
            writer.rollback()

    def test_auth_unknown_action_and_wrong_project(self):
        self.post(token=False, status=403)
        self.post({"action": "publish"}, status=400)
        self.post({"project": "foreign"}, status=400)

    def test_old_preview_is_rejected(self):
        before = self.post()
        with closing(db.connect(self.path)) as conn:
            db.save_checkpoint(conn, "atlas", "Another operator changed the task")
        self.post({"action": "preview", "revision": before["revision"],
                   "selection": {"checkpoint_fields": ["objective"]}}, status=400)
