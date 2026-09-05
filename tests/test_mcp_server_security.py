import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db, mcp_server
from rta_brain.continuity import upsert_work_item
from rta_brain.mcp_server import RtaBrainMcpServer
from rta_brain.progressive_retrieval import ProgressiveRetriever


def _prepare_database(database: Path, *, project: str = "demo") -> Path:
    root = database.parent / "repo"
    root.mkdir()
    conn = db.connect(database)
    try:
        db.init_project(conn, project, root)
    finally:
        conn.close()
    return root


class _CoordinatedConnection:
    def __init__(
        self,
        connection,
        *,
        ownership_read: threading.Event,
        release_read: threading.Event,
    ) -> None:
        self._connection = connection
        self._ownership_read = ownership_read
        self._release_read = release_read

    def execute(self, sql, parameters=()):
        result = self._connection.execute(sql, parameters)
        if "SELECT metadata_json FROM work_items" in str(sql):
            self._ownership_read.set()
            if not self._release_read.wait(timeout=5):
                raise TimeoutError("ownership race test did not release the MCP write")
        return result

    def __getattr__(self, name):
        return getattr(self._connection, name)


class McpServerSecurityTests(unittest.TestCase):
    def test_work_item_ownership_check_and_write_are_one_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = _prepare_database(database)
            server = RtaBrainMcpServer(
                database,
                "demo",
                expected_root=root,
                allow_memory_writes=True,
            )
            item = {
                "item_type": "asset",
                "external_id": "race-target",
                "qa_state": "pending",
                "decision": "pending",
            }
            server.call_tool("brain_work_item", item)

            ownership_read = threading.Event()
            release_read = threading.Event()
            operator_started = threading.Event()
            failures: list[Exception] = []
            real_connect = mcp_server.connect

            def coordinated_connect(path):
                return _CoordinatedConnection(
                    real_connect(path),
                    ownership_read=ownership_read,
                    release_read=release_read,
                )

            def mcp_write():
                try:
                    server.call_tool(
                        "brain_work_item",
                        {**item, "next_action": "agent overwrite"},
                    )
                except Exception as exc:  # noqa: BLE001 - worker failures are asserted below
                    failures.append(exc)

            def operator_write():
                operator_started.set()
                conn = db.connect(database)
                try:
                    upsert_work_item(
                        conn,
                        "demo",
                        "asset",
                        "race-target",
                        qa_state="passed",
                        decision="approved",
                        next_action="operator decision",
                        metadata={"_rta_authority": "operator"},
                    )
                except Exception as exc:  # noqa: BLE001 - worker failures are asserted below
                    failures.append(exc)
                finally:
                    conn.close()

            with patch("rta_brain.mcp_server.connect", side_effect=coordinated_connect):
                mcp_thread = threading.Thread(target=mcp_write)
                mcp_thread.start()
                self.assertTrue(ownership_read.wait(timeout=5))
                operator_thread = threading.Thread(target=operator_write)
                operator_thread.start()
                self.assertTrue(operator_started.wait(timeout=5))
                time.sleep(0.2)
                release_read.set()
                mcp_thread.join(timeout=6)
                operator_thread.join(timeout=6)

            self.assertFalse(mcp_thread.is_alive())
            self.assertFalse(operator_thread.is_alive())
            self.assertEqual(failures, [])
            conn = db.connect(database)
            try:
                row = conn.execute(
                    "SELECT metadata_json, next_action FROM work_items "
                    "WHERE external_id = ?",
                    ("race-target",),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(json.loads(row["metadata_json"])["_rta_authority"], "operator")
            self.assertEqual(row["next_action"], "operator decision")

    def test_host_proof_records_protocol_function_not_client_identity_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = _prepare_database(database, project="atlas-demo")
            server = RtaBrainMcpServer(
                database,
                "atlas-demo",
                expected_root=root,
                host_proof_receipt=Path(tmp) / "configuration-receipt.json",
                host_proof_challenge_token="challenge-token",
            )
            observed: list[dict[str, object]] = []

            with patch(
                "rta_brain.mcp_server.record_server_observed_tool_event",
                side_effect=lambda _path, _token, event: observed.append(dict(event)),
            ):
                initialized = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "clientInfo": {
                                "name": "forged-host-identity",
                                "version": "9999",
                            },
                        },
                    }
                )
                server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                called = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "brain_capabilities",
                            "arguments": {},
                        },
                    }
                )

            self.assertIn("result", initialized)
            self.assertIn("result", called)
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0]["host_version"], "mcp-protocol:2025-06-18")
            self.assertEqual(
                observed[0]["proof_semantics"],
                "functional_protocol_observation",
            )
            self.assertFalse(observed[0]["host_identity_attested"])
            self.assertNotIn("forged-host-identity", json.dumps(observed))

    def test_public_progressive_timeline_omits_checkpoint_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            _prepare_database(database)
            conn = db.connect(database)
            try:
                db.save_checkpoint(conn, "demo", "private checkpoint contents")
                retriever = ProgressiveRetriever(b"test-secret")
                index = retriever.retrieve(
                    conn,
                    project="demo",
                    query="checkpoint",
                    stage="index",
                    privacy_ceiling="public",
                )
                timeline = retriever.retrieve(
                    conn,
                    project="demo",
                    stage="timeline",
                    expansion_handle=index["expansion_handle"],
                    privacy_ceiling="public",
                )
            finally:
                conn.close()

            checkpoints = [
                item for item in timeline["items"] if item.get("kind") == "checkpoint"
            ]
            self.assertEqual(checkpoints, [])
            self.assertNotIn("version", json.dumps(timeline["items"]))


if __name__ == "__main__":
    unittest.main()
