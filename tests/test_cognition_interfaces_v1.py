import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rta_brain import db
from rta_brain.mcp_server import RtaBrainMcpServer
from rta_brain.sdk import BrainClient


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "rta-brain.py"


def run_cli(*args: str):
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class CognitionInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        (self.root / "README.md").write_text("# Public fixture\n", encoding="utf-8")
        self.database = self.base / "brain.sqlite"
        conn = db.connect(self.database)
        try:
            db.init_project(conn, "demo", str(self.root))
            db.ingest_repo(conn, self.root, project="demo", force=True)
        finally:
            conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_sdk_exposes_stable_cognition_and_multimodal_read_contracts(self):
        client = BrainClient(self.database, "demo", self.root)
        cognition = client.cognition(include_change_impact=False)
        media = client.multimodal()

        self.assertEqual(cognition["contract_version"], "1.0")
        self.assertEqual(media["contract_version"], "1.0")
        self.assertEqual(media["items"], [])
        self.assertNotIn(str(self.base), json.dumps(cognition))

    def test_mcp_advertises_and_dispatches_read_only_cognition_tools(self):
        server = RtaBrainMcpServer(self.database, "demo", expected_root=self.root)
        names = {tool["name"] for tool in server.agent_tools}
        self.assertIn("brain_cognition_snapshot", names)
        self.assertIn("brain_multimodal_list", names)

        cognition = server.call_tool(
            "brain_cognition_snapshot", {"include_change_impact": False}
        )["structuredContent"]
        media = server.call_tool("brain_multimodal_list", {})["structuredContent"]
        self.assertEqual(cognition["contract_version"], "1.0")
        self.assertEqual(media["items"], [])

    def test_cli_cognition_and_media_list_emit_json(self):
        cognition = run_cli(
            "--db",
            str(self.database),
            "--json",
            "cognition",
            "--project",
            "demo",
            "--root",
            str(self.root),
            "--no-change-impact",
        )
        media = run_cli(
            "--db", str(self.database), "--json", "media", "list",
            "--project", "demo",
        )
        self.assertEqual(cognition.returncode, 0, cognition.stderr)
        self.assertEqual(media.returncode, 0, media.stderr)
        self.assertEqual(json.loads(cognition.stdout)["contract_version"], "1.0")
        self.assertEqual(json.loads(media.stdout)["items"], [])


if __name__ == "__main__":
    unittest.main()
