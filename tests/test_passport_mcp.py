import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from rta_brain import db
from rta_brain.mcp_server import RtaBrainMcpServer


class PassportMcpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        self.database = Path(self.temp.name) / "brain.sqlite"
        with closing(db.connect(self.database)) as conn:
            db.init_project(conn, "atlas", str(self.root))
            db.save_checkpoint(conn, "atlas", "Private objective", next_action="Run the UTC test")
        self.server = RtaBrainMcpServer(self.database, "atlas", expected_root=self.root, tool_profile="passport")

    def test_inspect_shares_metadata_only_and_preview_requires_explicit_fields(self):
        self.assertEqual({tool["name"] for tool in self.server.agent_tools}, {"brain_capabilities", "brain_project_passport"})
        inspected = self.server.call_tool("brain_project_passport", {})["structuredContent"]
        self.assertNotIn("Private objective", json.dumps(inspected))
        self.assertNotIn("Run the UTC test", json.dumps(inspected))
        self.assertEqual(inspected["checkpoint_version"], 1)
        selected = self.server.call_tool("brain_project_passport", {
            "action": "preview", "revision": inspected["revision"],
            "selection": {"checkpoint_fields": ["next_action"]},
        })["structuredContent"]
        self.assertEqual(selected["document"]["checkpoint"], {"next_action": "Run the UTC test"})
        self.assertNotIn("Private objective", json.dumps(selected))
        self.assertEqual(selected["sha256"], hashlib.sha256(selected["json"].encode("utf-8")).hexdigest())
        self.assertEqual(selected["markdown_sha256"], hashlib.sha256(selected["markdown"].encode("utf-8")).hexdigest())
        with self.assertRaises(ValueError):
            self.server.call_tool("brain_project_passport", {"project": "foreign"})

    def test_live_writer_does_not_block_mcp_reads_and_public_ceiling_fails_closed(self):
        with closing(db.connect(self.database)) as writer:
            writer.execute("BEGIN IMMEDIATE")
            inspected = self.server.call_tool("brain_project_passport", {})["structuredContent"]
            self.assertTrue(inspected["metadata_only"])
            writer.rollback()
        public_server = RtaBrainMcpServer(self.database, "atlas", expected_root=self.root,
                                         tool_profile="passport", maximum_privacy_ceiling="public")
        with self.assertRaises(PermissionError):
            public_server.call_tool("brain_project_passport", {})

    def test_fresh_stdio_client_discovers_and_reads_the_passport(self):
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "passport-acceptance", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "brain_project_passport", "arguments": {}}},
        ]
        result = subprocess.run([sys.executable, "-m", "rta_brain.mcp_server", "--db", str(self.database), "--project", "atlas", "--tool-profile", "passport"],
                                input="\n".join(map(json.dumps, messages)) + "\n", text=True,
                                encoding="utf-8", capture_output=True, timeout=30, check=False,
                                cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(result.returncode, 0, result.stderr)
        replies = {item["id"]: item for line in result.stdout.splitlines() if (item := json.loads(line)).get("id")}
        self.assertIn("brain_project_passport", [tool["name"] for tool in replies[2]["result"]["tools"]])
        self.assertEqual(replies[3]["result"]["structuredContent"]["checkpoint_version"], 1)
