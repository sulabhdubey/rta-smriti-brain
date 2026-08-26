import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db
from rta_brain.compaction import compact_session_events, validate_ollama_endpoint
from rta_brain.parsers import ParserRegistry, _native_lsp_parse, discover_lsp_servers


class V06FeedbackTests(unittest.TestCase):
    def test_large_files_default_to_metadata_only_without_claiming_full_freshness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "small.py").write_text("def ready():\n    return True\n", encoding="utf-8")
            large = root / "legacy-generated.js"
            large.write_text("x" * 520_000, encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                result = db.ingest_repo(conn, root, project="demo")
                self.assertEqual(result["blocked_files"], 0)
                self.assertEqual(result["metadata_only_files"], 1)
                source = conn.execute(
                    "SELECT metadata_json FROM sources WHERE project_id = "
                    "(SELECT id FROM projects WHERE name = 'demo') AND path = ?",
                    (str(large.resolve()),),
                ).fetchone()
                metadata = json.loads(source["metadata_json"])
                self.assertFalse(metadata["content_indexed"])
                self.assertEqual(metadata["reason"], "oversized:520000")
                self.assertEqual(
                    conn.execute(
                        "SELECT COUNT(*) AS c FROM chunks WHERE source_id = "
                        "(SELECT id FROM sources WHERE path = ?)",
                        (str(large.resolve()),),
                    ).fetchone()["c"],
                    0,
                )
                freshness = db.stale_check(conn, "demo", deep=True)
                self.assertEqual(freshness["state"], "fresh_with_warnings")
                self.assertEqual(freshness["metadata_only"], 1)
                self.assertEqual(freshness["uninspectable"], 0)
            finally:
                conn.close()

    def test_strict_large_file_policy_remains_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "large.js").write_text("x" * 520_000, encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                db.update_project_settings(conn, "demo", {"large_file_policy": "block"})
                result = db.ingest_repo(conn, root, project="demo")
                self.assertEqual(result["blocked_files"], 1)
                self.assertEqual(result["metadata_only_files"], 0)
                self.assertEqual(db.stale_check(conn, "demo")["state"], "stale")
            finally:
                conn.close()

    def test_language_servers_are_discovered_without_project_local_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = (Path(tmp) / "pyright-langserver").resolve()
            fake.write_text("trusted operator executable", encoding="utf-8")

            def finder(command):
                return str(fake) if command == "pyright-langserver" else None

            discovered = discover_lsp_servers(finder=finder)
            self.assertEqual(discovered[0]["name"], "pyright")
            self.assertEqual(discovered[0]["command"], [str(fake), "--stdio"])
            self.assertRegex(discovered[0]["executable_identity"], r"^\d+:\d+$")
            registry = ParserRegistry(load_entry_points=False, lsp_auto_discovery=True, executable_finder=finder)
            capability = registry.capabilities()["lsp"]
            self.assertTrue(capability["available"])
            self.assertEqual(capability["detected_servers"][0]["name"], "pyright")
            self.assertEqual(discover_lsp_servers(finder=finder, excluded_root=Path(tmp)), [])

    def test_native_lsp_client_reads_document_symbols_with_bounded_json_rpc(self):
        server_source = r'''
import json, sys
def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if line in {b"\r\n", b"\n"}: break
        key, value = line.decode("ascii").split(":", 1)
        headers[key.lower()] = value.strip()
    return json.loads(sys.stdin.buffer.read(int(headers["content-length"])))
def send(value):
    raw = json.dumps(value).encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(raw)}\r\n\r\n".encode("ascii") + raw)
    sys.stdout.buffer.flush()
while True:
    message = read_message()
    if message.get("method") == "initialize":
        send({"jsonrpc":"2.0","id":message["id"],"result":{"capabilities":{"documentSymbolProvider":True}}})
    elif message.get("method") == "textDocument/documentSymbol":
        send({"jsonrpc":"2.0","id":message["id"],"result":[{"name":"ReleaseService","children":[{"name":"verify"}]}]})
    elif message.get("method") == "shutdown":
        send({"jsonrpc":"2.0","id":message["id"],"result":None})
    elif message.get("method") == "exit":
        break
'''
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
            source = root / "service.py"
            source.write_text("def verify():\n    return helper()\n", encoding="utf-8")
            server = root / "fake_lsp.py"
            server.write_text(server_source, encoding="utf-8")
            result = _native_lsp_parse(
                source,
                source.read_text(encoding="utf-8"),
                {"name": "fake", "command": [sys.executable, "-u", str(server)]},
            )
        self.assertEqual(result.parser, "lsp:fake")
        self.assertEqual(result.symbols, ["ReleaseService", "verify"])
        self.assertIn("helper", result.calls)

    def test_lsp_timeout_falls_back_without_aborting_the_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = (Path(tmp) / "pyright-langserver").resolve()
            fake.write_text("trusted operator executable", encoding="utf-8")

            def finder(command):
                return str(fake) if command == "pyright-langserver" else None

            registry = ParserRegistry(
                load_entry_points=False,
                lsp_auto_discovery=True,
                executable_finder=finder,
            )
            with patch("rta_brain.parsers._native_lsp_parse", side_effect=TimeoutError("stalled server")):
                result = registry.parse(Path("service.py"), "def ready():\n    return True\n", "lsp")
        self.assertEqual(result.parser, "regex")
        self.assertIn("lsp unavailable; used regex: stalled server", result.warnings)

    def test_replaced_language_server_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "pyright-langserver"
            fake.write_text("original", encoding="utf-8")
            discovered = discover_lsp_servers(
                finder=lambda command: str(fake) if command == "pyright-langserver" else None,
            )[0]
            fake.write_text("replacement with a different identity", encoding="utf-8")
            source = root / "service.py"
            source.write_text("def ready():\n    return True\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "changed after discovery"):
                _native_lsp_parse(source, source.read_text(encoding="utf-8"), discovered)

    def test_ollama_compaction_is_loopback_only_redacted_and_bounded(self):
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, amount):
                self.amount = amount
                return json.dumps({"response": "Objective: continue release checks"}).encode("utf-8")

        def opener(request, timeout):
            captured["url"] = request.full_url
            captured["body"] = request.data.decode("utf-8")
            captured["timeout"] = timeout
            return Response()

        result = compact_session_events(
            [{"event_type": "message", "payload": {"role": "user", "content": "password=super-secret-value"}}],
            model="qwen3:0.6b",
            endpoint="http://127.0.0.1:11434",
            opener=opener,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["verification_status"], "unverified")
        self.assertNotIn("super-secret-value", captured["body"])
        self.assertTrue(captured["url"].endswith("/api/generate"))
        self.assertEqual(validate_ollama_endpoint("http://localhost:11434"), "http://127.0.0.1:11434")
        with self.assertRaisesRegex(ValueError, "loopback"):
            validate_ollama_endpoint("https://ollama.example.com")

    def test_standard_package_and_binary_include_ast_and_signing_capabilities(self):
        pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
        dependencies = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0]
        self.assertIn("tree-sitter-language-pack", dependencies)
        self.assertIn("cryptography", dependencies)
        self.assertIn("watchdog", dependencies)
        spec = (Path(__file__).parents[1] / "rta-smriti.spec").read_text(encoding="utf-8")
        self.assertIn('collect_all("tree_sitter_language_pack")', spec)
        self.assertIn('collect_all("cryptography")', spec)
        self.assertIn('collect_all("watchdog")', spec)
        self.assertNotIn('"tree_sitter_language_pack",', spec.split("excludes=[", 1)[1])

    def test_initial_ingest_warms_every_deep_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "one.py").write_text("print('one')\n", encoding="utf-8")
            (root / "two.ts").write_text("export const two = 2;\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                db.ingest_repo(conn, root, project="demo")
                result = db.stale_check(conn, "demo", deep=True)
                self.assertEqual(result["hash_cache_hits"], 2)
                self.assertEqual(result["hash_cache_misses"], 0)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
