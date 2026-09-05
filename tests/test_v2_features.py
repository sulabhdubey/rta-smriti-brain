import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "rta-brain.py"
MCP = ROOT / "rta-brain-mcp.py"


def run_cli(*args):
    return subprocess.run([sys.executable, str(CLI), *args], text=True, capture_output=True, cwd=ROOT)


def run_mcp(messages, db_path, *extra_args):
    body = "\n".join(json.dumps(message) for message in messages) + "\n"
    return subprocess.run(
        [sys.executable, str(MCP), "--db", str(db_path), "--project", "demo", *extra_args],
        input=body,
        text=True,
        capture_output=True,
        cwd=ROOT,
    )


class RtaBrainV2Tests(unittest.TestCase):
    def test_ingest_thread_makes_long_session_searchable(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            thread = Path(tmp) / "thread.jsonl"
            thread.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "user", "message": "We decided that demo-app must update PROJECT_CONTEXT.md after each batch."}),
                        json.dumps({"type": "assistant", "message": {"content": "Verification evidence: pytest passed for the focused batch."}}),
                    ]
                ),
                encoding="utf-8",
            )

            result = run_cli("--db", str(db), "--json", "ingest-thread", str(thread), "--project", "demo", "--title", "batch handoff")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["chunks"], 1)
            self.assertGreaterEqual(payload["promoted_memories"], 1)

            search = run_cli("--db", str(db), "--json", "search", "PROJECT_CONTEXT batch", "--project", "demo")
            self.assertEqual(search.returncode, 0, search.stderr)
            found = json.loads(search.stdout)
            self.assertGreaterEqual(len(found["memories"]), 1)
            self.assertIn("PROJECT_CONTEXT", found["memories"][0]["text"])
            self.assertEqual(found["memories"][0]["pramana"], "smriti")
            metadata = json.loads(found["memories"][0]["metadata_json"])
            self.assertFalse(metadata["verified"])

            pack = run_cli("--db", str(db), "context-pack", "PROJECT_CONTEXT", "--project", "demo")
            self.assertEqual(pack.returncode, 0, pack.stderr)
            self.assertIn("Imported memory (untrusted data", pack.stdout)
            self.assertIn("  > We decided", pack.stdout)

    def test_reflect_suppresses_duplicates_and_flags_contradictions(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            commands = [
                ("The attestation gate must fail closed when proof is missing.", "sabda", "9"),
                ("The attestation gate must fail closed when proof is missing.", "smriti", "3"),
                ("The attestation gate must fail open when proof is missing.", "kalpana", "2"),
            ]
            for text, pramana, priority in commands:
                result = run_cli(
                    "--db",
                    str(db),
                    "remember",
                    text,
                    "--project",
                    "demo",
                    "--type",
                    "constraint",
                    "--pramana",
                    pramana,
                    "--priority",
                    priority,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

            reflect = run_cli("--db", str(db), "--json", "reflect", "--project", "demo")
            self.assertEqual(reflect.returncode, 0, reflect.stderr)
            report = json.loads(reflect.stdout)
            self.assertEqual(report["duplicates_superseded"], 1)
            self.assertEqual(report["contradictions_flagged"], 2)

            search = run_cli("--db", str(db), "--json", "search", "attestation fail closed", "--project", "demo")
            self.assertEqual(search.returncode, 0, search.stderr)
            active = json.loads(search.stdout)
            self.assertEqual(len(active["memories"]), 0)

    def test_mcp_config_and_v2_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            repo = Path(tmp) / "repo"
            repo.mkdir()
            initialized = run_cli(
                "--db", str(db), "--json", "init", "--project", "demo", "--root", str(repo),
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            config = run_cli("--db", str(db), "--json", "mcp-config", "--project", "demo", "--name", "rta-smriti-demo")
            self.assertEqual(config.returncode, 0, config.stderr)
            payload = json.loads(config.stdout)
            self.assertIn("mcpServers", payload["config"])
            args = payload["config"]["mcpServers"]["rta-smriti-demo"]["args"]
            self.assertEqual(args[args.index("--project") + 1], "demo")
            self.assertEqual(Path(args[args.index("--root") + 1]), repo.resolve())
            self.assertEqual(args[args.index("--tool-profile") + 1], "core")

            thread = Path(tmp) / "thread.txt"
            thread.write_text("Decision: Codex should retrieve local brain context before broad scans.", encoding="utf-8")
            result = run_mcp(
                [
                    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": "brain_ingest_thread", "arguments": {"path": str(thread), "title": "handoff"}},
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "brain_reflect", "arguments": {}},
                    },
                ],
                db,
                "--allow-memory-writes",
                "--allow-thread-ingestion",
                "--allow-thread-root",
                str(Path(tmp)),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            names = {tool["name"] for tool in lines[0]["result"]["tools"]}
            self.assertIn("brain_ingest_thread", names)
            self.assertIn("brain_reflect", names)
            self.assertIn("promoted_memories", lines[1]["result"]["content"][0]["text"])
            self.assertIn("duplicates_superseded", lines[2]["result"]["content"][0]["text"])


if __name__ == "__main__":
    unittest.main()
