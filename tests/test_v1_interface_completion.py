import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from rta_brain import db
from rta_brain.mcp_server import RtaBrainMcpServer
from rta_brain.multimodal import add_derivation, ingest_media
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


class V1InterfaceCompletionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        (self.root / "README.md").write_text("# fixture\n", encoding="utf-8")
        (self.root / "proof.png").write_bytes(b"\x89PNG\r\n\x1a\nfixture")
        self.database = self.base / "brain.sqlite"
        conn = db.connect(self.database)
        try:
            db.init_project(conn, "demo", str(self.root))
            db.ingest_repo(conn, self.root, project="demo", force=True)
            source = ingest_media(
                conn,
                project="demo",
                active_root=self.root,
                path=self.root / "proof.png",
                privacy_class="public",
                sharing_policy="exportable",
            )
            add_derivation(
                conn,
                project="demo",
                source_id=source["source_id"],
                method="operator-caption",
                text="Verified fixture image.",
                tool_identity="test-suite",
                confidence=1.0,
                verification_status="verified",
                actor_type="operator",
                actor_id="interface-test-operator",
            )
            self.source_id = source["source_id"]
        finally:
            conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_sdk_covers_truth_context_portability_and_multimodal_reads(self):
        client = BrainClient(self.database, "demo", self.root)
        self.assertEqual(client.truth_current("missing")["status"], "abstain")
        self.assertIn("operationally_ready", client.integrity())
        self.assertEqual(len(client.multimodal_derivations(self.source_id)["items"]), 1)
        self.assertEqual(client.verify_media(self.source_id)["state"], "current")
        exported = client.export_media_manifest(audience="public")
        self.assertEqual(exported["contract_version"], "1.0")
        self.assertNotIn(str(self.base), json.dumps(exported))
        self.assertTrue(callable(client.compile_context))

    def test_mcp_exposes_bounded_read_only_media_inspection(self):
        server = RtaBrainMcpServer(self.database, "demo", expected_root=self.root)
        names = {tool["name"] for tool in server.agent_tools}
        self.assertTrue({
            "brain_multimodal_derivations",
            "brain_multimodal_verify",
            "brain_multimodal_export",
        }.issubset(names))
        derivations = server.call_tool(
            "brain_multimodal_derivations", {"source_id": self.source_id}
        )["structuredContent"]
        verified = server.call_tool(
            "brain_multimodal_verify", {"source_id": self.source_id}
        )["structuredContent"]
        exported = server.call_tool(
            "brain_multimodal_export", {"audience": "public"}
        )["structuredContent"]
        self.assertEqual(len(derivations["items"]), 1)
        self.assertEqual(verified["state"], "current")
        self.assertNotIn(str(self.base), json.dumps(exported))

    def test_cli_exposes_media_read_and_operator_lifecycle_controls(self):
        derivations = run_cli(
            "--db", str(self.database), "--json", "media", "derivations",
            "--project", "demo", "--source-id", self.source_id,
        )
        verified = run_cli(
            "--db", str(self.database), "--json", "media", "verify",
            "--project", "demo", "--root", str(self.root),
            "--source-id", self.source_id,
        )
        exported = run_cli(
            "--db", str(self.database), "--json", "media", "export",
            "--project", "demo", "--audience", "public",
        )
        for result in (derivations, verified, exported):
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(derivations.stdout)["items"]), 1)
        self.assertEqual(json.loads(verified.stdout)["state"], "current")
        self.assertNotIn(str(self.base), exported.stdout)


if __name__ == "__main__":
    unittest.main()
