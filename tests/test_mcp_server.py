import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db as brain_db
from rta_brain import mcp_server
from rta_brain.db import connect, init_project
from rta_brain.mcp_host_lifecycle import (
    apply_host_configuration,
    issue_fresh_session_challenge,
    plan_host_configuration,
    record_fresh_session_proof,
)
from rta_brain.mcp_server import McpRequestScheduler, RtaBrainMcpServer

ROOT = Path(__file__).resolve().parents[1]
MCP = ROOT / "rta-brain-mcp.py"


def prepare_mcp_db(db_path):
    db_path = Path(db_path)
    root = db_path.parent / "mcp-test-repo"
    root.mkdir(parents=True, exist_ok=True)
    conn = connect(db_path)
    try:
        init_project(conn, "demo", str(root))
    finally:
        conn.close()
    return root


def run_mcp(messages, db_path, *extra_args):
    prepare_mcp_db(db_path)
    body = "\n".join(json.dumps(message) for message in messages) + "\n"
    return subprocess.run(
        [sys.executable, str(MCP), "--db", str(db_path), "--project", "demo", *extra_args],
        input=body,
        text=True,
        capture_output=True,
        cwd=ROOT,
        check=False,
    )


def responses(stdout):
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


def run_gateway(messages, brain_dir):
    body = "\n".join(json.dumps(message) for message in messages) + "\n"
    return subprocess.run(
        [sys.executable, str(MCP), "--brain-dir", str(brain_dir)],
        input=body, text=True, capture_output=True, cwd=ROOT, check=False,
    )


class RtaBrainMcpTests(unittest.TestCase):
    def test_agent_session_events_cannot_self_assert_operator_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            server = RtaBrainMcpServer(
                database,
                "demo",
                expected_root=root,
                allow_memory_writes=True,
            )

            server.call_tool(
                "brain_session_event",
                {
                    "session_id": "agent-session",
                    "cursor": "1",
                    "event_type": "agent.note",
                    "payload": {"text": "proposal"},
                    "source": "operator",
                    "verification_status": "verified",
                },
            )

            conn = connect(database)
            try:
                row = conn.execute(
                    "SELECT source, verification_status FROM session_events"
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(dict(row), {
                "source": "mcp-agent",
                "verification_status": "unverified",
            })

    def test_agent_work_items_reject_unrecognized_or_owner_only_states(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            server = RtaBrainMcpServer(
                database,
                "demo",
                expected_root=root,
                allow_memory_writes=True,
            )

            for qa_state, decision in (
                ("passed_by_agent", "pending"),
                ("pending", "approved"),
            ):
                with self.subTest(qa_state=qa_state, decision=decision):
                    with self.assertRaisesRegex(ValueError, "work-item"):
                        server.call_tool(
                            "brain_work_item",
                            {
                                "item_type": "asset",
                                "external_id": f"{qa_state}-{decision}",
                                "qa_state": qa_state,
                                "decision": decision,
                            },
                        )

    def test_deep_stale_read_does_not_write_hash_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            (root / "README.md").write_text("hash me", encoding="utf-8")
            conn = connect(database)
            try:
                brain_db.ingest_repo(conn, root, project="demo")
                conn.execute("DELETE FROM file_hash_cache")
                conn.commit()
            finally:
                conn.close()
            server = RtaBrainMcpServer(database, "demo", expected_root=root)

            server.call_tool("brain_stale_check", {"deep": True})

            conn = connect(database)
            try:
                count = conn.execute(
                    "SELECT COUNT(*) AS c FROM file_hash_cache"
                ).fetchone()["c"]
            finally:
                conn.close()
            self.assertEqual(count, 0)

    def test_fresh_session_proof_is_recorded_only_by_live_mcp_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            database = base / "brain.sqlite"
            root = base / "atlas-repo"
            root.mkdir()
            conn = connect(database)
            try:
                init_project(conn, "atlas-demo", root)
            finally:
                conn.close()
            target = base / ".cursor" / "mcp.json"
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            installed = apply_host_configuration(
                plan, {"approved": True, "plan_digest": plan["plan_digest"]}
            )
            receipt_path = Path(installed["receipt_path"])
            confirmation = {
                "approved": True,
                "configuration_plan_digest": plan["plan_digest"],
            }
            challenge = issue_fresh_session_challenge(receipt_path, confirmation)
            server = RtaBrainMcpServer(
                database,
                "atlas-demo",
                expected_root=root,
                host_proof_receipt=receipt_path,
                host_proof_challenge_token=challenge["challenge_token"],
            )

            server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "clientInfo": {"name": "cursor", "version": "2026.09"},
                    },
                }
            )
            server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            capabilities = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "brain_capabilities", "arguments": {}},
                }
            )
            search = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "brain_search",
                        "arguments": {"query": "Atlas architecture"},
                    },
                }
            )
            proof = record_fresh_session_proof(
                receipt_path,
                {"challenge_token": challenge["challenge_token"]},
                confirmation,
            )

            self.assertIn("result", capabilities)
            self.assertIn("result", search)
            self.assertEqual(proof["state"], "protocol_verified")
            self.assertTrue(proof["evidence"]["atlas_search_observed"])
            self.assertTrue(proof["evidence"]["denied_capability_observed"])

    def test_privacy_ceiling_defaults_internal_and_cannot_be_reassigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            server = RtaBrainMcpServer(database, "demo", expected_root=root)

            self.assertEqual(server.maximum_privacy_ceiling, "internal")
            with self.assertRaises(AttributeError):
                server.maximum_privacy_ceiling = "restricted"

    def test_core_search_filters_sensitive_restricted_and_unknown_memories(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            conn = connect(database)
            try:
                for privacy_class, secret in (
                    ("public", "VISIBLE-PUBLIC-7A1"),
                    ("internal", "VISIBLE-INTERNAL-7A2"),
                    ("sensitive", "HIDDEN-SENSITIVE-7A3"),
                    ("restricted", "HIDDEN-RESTRICTED-7A4"),
                    ("future-class", "HIDDEN-UNKNOWN-7A5"),
                ):
                    brain_db.remember(
                        conn,
                        f"privacy-boundary-marker {secret}",
                        project="demo",
                        metadata={"privacy_class": privacy_class},
                    )
                malformed = brain_db.remember(
                    conn,
                    "privacy-boundary-marker HIDDEN-MALFORMED-7A6",
                    project="demo",
                    metadata={"privacy_class": "internal"},
                )
                conn.execute(
                    "UPDATE memories SET metadata_json = ? WHERE id = ?",
                    ('{"privacy_class":', malformed["memory"]["id"]),
                )
                conn.commit()
            finally:
                conn.close()
            server = RtaBrainMcpServer(
                database, "demo", expected_root=root, tool_profile="core"
            )

            payload = server.call_tool(
                "brain_search",
                {
                    "query": "privacy-boundary-marker",
                    "limit": 20,
                    "privacy_ceiling": "restricted",
                },
            )["structuredContent"]
            rendered = json.dumps(payload)

            self.assertIn("VISIBLE-PUBLIC-7A1", rendered)
            self.assertIn("VISIBLE-INTERNAL-7A2", rendered)
            for secret in (
                "HIDDEN-SENSITIVE-7A3",
                "HIDDEN-RESTRICTED-7A4",
                "HIDDEN-UNKNOWN-7A5",
                "HIDDEN-MALFORMED-7A6",
            ):
                self.assertNotIn(secret, rendered)
            self.assertEqual(payload["privacy"]["maximum_ceiling"], "internal")
            self.assertEqual(payload["privacy"]["requested_ceiling"], "restricted")
            self.assertEqual(payload["privacy"]["effective_ceiling"], "internal")
            self.assertTrue(payload["privacy"]["request_limited"])
            self.assertEqual(payload["privacy"]["filtered_counts"]["memories"], 4)
            self.assertEqual(payload["privacy"]["filtered_total"], 4)

    def test_search_public_ceiling_filters_internal_chunks_without_leaking_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            marker = "HIDDEN-REPOSITORY-CHUNK-8B1"
            (root / "private-notes.md").write_text(
                f"privacy-chunk-marker {marker}\n", encoding="utf-8"
            )
            database = Path(tmp) / "brain.sqlite"
            conn = connect(database)
            try:
                init_project(conn, "demo", str(root))
                brain_db.ingest_repo(conn, root, project="demo")
                brain_db.remember(
                    conn,
                    "privacy-chunk-marker VISIBLE-PUBLIC-8B2",
                    project="demo",
                    metadata={"privacy_class": "public"},
                )
            finally:
                conn.close()
            server = RtaBrainMcpServer(
                database,
                "demo",
                expected_root=root,
                maximum_privacy_ceiling="public",
                tool_profile="core",
            )

            payload = server.call_tool(
                "brain_search", {"query": "privacy-chunk-marker"}
            )["structuredContent"]
            rendered = json.dumps(payload)

            self.assertIn("VISIBLE-PUBLIC-8B2", rendered)
            self.assertNotIn(marker, rendered)
            self.assertEqual(payload["chunks"], [])
            self.assertGreaterEqual(payload["privacy"]["filtered_counts"]["chunks"], 1)

    def test_public_server_fails_closed_for_unfiltered_core_content_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            secret = "INTERNAL-CORE-CONTENT-4D8"
            conn = connect(database)
            try:
                brain_db.remember(
                    conn,
                    f"context-pack-marker {secret}",
                    project="demo",
                    metadata={"privacy_class": "internal"},
                )
                brain_db.save_checkpoint(
                    conn,
                    project="demo",
                    objective=f"continue {secret}",
                    verified_evidence="private operator evidence",
                    remaining_gaps="private operator gap",
                    next_action="private operator action",
                    prohibited_repetition="private operator prohibition",
                )
            finally:
                conn.close()
            server = RtaBrainMcpServer(
                database,
                "demo",
                expected_root=root,
                maximum_privacy_ceiling="public",
                tool_profile="core",
            )
            calls = {
                "brain_context_pack": {"task": "context-pack-marker"},
                "brain_repo_map": {},
                "brain_stale_check": {},
                "brain_continuation_prompt": {},
                "brain_operational_readiness": {},
                "brain_lifecycle_inspect": {},
            }

            for tool_name, arguments in calls.items():
                with self.subTest(tool=tool_name):
                    with self.assertRaises(PermissionError) as raised:
                        server.call_tool(tool_name, arguments)
                    self.assertNotIn(secret, str(raised.exception))

            self.assertEqual(
                set(calls), set(mcp_server.CORE_UNFILTERED_CONTENT_TOOLS)
            )

    def test_retrieve_cannot_raise_the_server_privacy_ceiling(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            conn = connect(database)
            try:
                brain_db.remember(
                    conn,
                    "raise-ceiling-marker HIDDEN-SENSITIVE-9C1",
                    project="demo",
                    metadata={"privacy_class": "sensitive"},
                )
            finally:
                conn.close()
            server = RtaBrainMcpServer(
                database,
                "demo",
                expected_root=root,
                maximum_privacy_ceiling="internal",
                tool_profile="core",
            )

            payload = server.call_tool(
                "brain_retrieve",
                {
                    "stage": "index",
                    "query": "raise-ceiling-marker",
                    "privacy_ceiling": "restricted",
                },
            )["structuredContent"]
            rendered = json.dumps(payload)

            self.assertNotIn("HIDDEN-SENSITIVE-9C1", rendered)
            self.assertEqual(payload["items"], [])
            self.assertEqual(payload["privacy"]["requested_ceiling"], "restricted")
            self.assertEqual(payload["privacy"]["maximum_ceiling"], "internal")
            self.assertEqual(payload["privacy"]["effective_ceiling"], "internal")
            self.assertTrue(payload["privacy"]["request_limited"])
            self.assertEqual(payload["report"]["privacy_filtered_count"], 1)

    def test_cli_defaults_to_core_and_capabilities_report_tool_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            result = run_mcp(
                [{
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "brain_capabilities", "arguments": {}},
                }],
                database,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = responses(result.stdout)[0]["result"]["structuredContent"]
            self.assertEqual(payload["active_profile"], "core")
            self.assertEqual(payload["maximum_privacy_ceiling"], "internal")
            search_contract = payload["tool_contracts"]["brain_search"]
            self.assertEqual(search_contract["effect"], "read")
            self.assertEqual(search_contract["idempotency"], "safe_repeat")
            self.assertEqual(search_contract["authority"], "server_privacy_ceiling")

    def test_progressive_retrieval_schema_bounds_cached_query_input(self):
        schema = next(
            tool for tool in mcp_server.TOOLS if tool["name"] == "brain_retrieve"
        )["inputSchema"]

        self.assertEqual(schema["properties"]["query"]["maxLength"], 10_000)

    def test_progressive_core_profile_is_bounded_and_describes_more_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            server = RtaBrainMcpServer(
                database, "demo", expected_root=root, tool_profile="core"
            )

            names = {tool["name"] for tool in server.agent_tools}
            self.assertLessEqual(len(names), 12)
            self.assertIn("brain_capabilities", names)
            self.assertIn("brain_search", names)
            self.assertIn("brain_retrieve", names)
            self.assertNotIn("brain_truth_history", names)
            discovered = server.call_tool(
                "brain_capabilities", {}
            )["structuredContent"]

            self.assertEqual(discovered["active_profile"], "core")
            self.assertIn("temporal_read", discovered["capability_groups"])
            self.assertEqual(
                discovered["capability_groups"]["capture_destructive"]["effect"],
                "destructive",
            )
            self.assertTrue(
                discovered["capability_groups"]["capture_destructive"][
                    "approval_required"
                ]
            )
            indexed = server.call_tool(
                "brain_retrieve",
                {"stage": "index", "query": "project"},
            )["structuredContent"]
            expanded = server.call_tool(
                "brain_retrieve",
                {
                    "stage": "evidence",
                    "expansion_handle": indexed["expansion_handle"],
                    "max_tokens": 128,
                },
            )["structuredContent"]
            self.assertEqual(expanded["snapshot_digest"], indexed["snapshot_digest"])
            with self.assertRaisesRegex(ValueError, "not enabled"):
                server.call_tool("brain_truth_history", {"claim_id": "missing"})

    def test_default_mcp_lifecycle_inspection_is_path_free_and_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            server = RtaBrainMcpServer(database, "demo", expected_root=root)

            self.assertIn("brain_lifecycle_inspect", server.enabled_tools)
            payload = server.call_tool(
                "brain_lifecycle_inspect", {}
            )["structuredContent"]

            self.assertEqual(payload["status"], "ok")
            self.assertEqual(
                set(payload["health_axes"]),
                {
                    "database_health",
                    "project_integrity",
                    "capture_health",
                    "continuation_health",
                    "mcp_health",
                    "federation_health",
                },
            )
            rendered = json.dumps(payload)
            self.assertNotIn(str(database), rendered)
            self.assertNotIn(str(root), rendered)
            review = server.call_tool(
                "brain_lifecycle_inspect", {"mode": "review", "receipt_limit": 10}
            )["structuredContent"]
            self.assertEqual(review["schema"], "rta-smriti.trusted-lifecycle-review/v1")
            self.assertEqual(len(review["bundle_digest"]), 64)
            self.assertNotIn(str(database), json.dumps(review))

    def test_continuity_reads_expose_only_path_free_public_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            conn = connect(database)
            try:
                brain_db.save_checkpoint(conn, "demo", "Continue safely")
            finally:
                conn.close()
            lifecycle = {
                "status": "ok",
                "state": "running",
                "project": "demo",
                "db_path": str(database),
                "root": str(root),
                "sessions_root": str(Path(tmp) / ".codex" / "sessions"),
                "pid": 42,
                "token_hash": "private-token-hash",
                "process_identity": "windows:42:123",
                "last_error": str(root / "private-error.txt"),
                "consecutive_errors": 1,
                "sessions_pending": 0,
                "process_alive": True,
                "process_identity_matches": True,
            }
            server = RtaBrainMcpServer(database, "demo")

            with patch("rta_brain.mcp_server.continuity_status", return_value=lifecycle):
                status = server.call_tool("brain_continuity_status", {})["structuredContent"]
                readiness = server.call_tool("brain_operational_readiness", {})["structuredContent"]

        self.assertTrue(status["has_error"])
        self.assertIn("continuity_capture_errors", readiness["reasons"])
        for payload in (status, readiness["continuity"]):
            rendered = json.dumps(payload)
            for secret in (
                str(database), str(root), "sessions_root", "db_path", "pid",
                "token_hash", "process_identity\"", "private-token-hash",
                "private-error.txt",
            ):
                self.assertNotIn(secret, rendered)

    def test_memory_write_capability_does_not_grant_continuity_process_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            prepare_mcp_db(database)

            memory_server = RtaBrainMcpServer(
                database, "demo", allow_memory_writes=True,
            )
            control_server = RtaBrainMcpServer(
                database, "demo", allow_continuity_control=True,
            )

        self.assertNotIn("brain_continuity_control", memory_server.enabled_tools)
        self.assertIn("brain_continuity_control", control_server.enabled_tools)

    def test_continuity_control_returns_only_path_free_public_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            root = prepare_mcp_db(database)
            server = RtaBrainMcpServer(
                database, "demo", allow_continuity_control=True,
            )
            private = {
                "status": "ok", "state": "stopped", "project": "demo",
                "db_path": str(database), "root": str(root), "pid": 42,
                "token_hash": "private-token", "process_identity": "windows:42:123",
                "last_error": str(root / "private-error.txt"),
                "consecutive_errors": 1,
            }

            with patch("rta_brain.mcp_server.stop_continuity", return_value=private):
                payload = server.call_tool(
                    "brain_continuity_control", {"action": "stop"},
                )["structuredContent"]

        self.assertTrue(payload["has_error"])
        rendered = json.dumps(payload)
        for secret in (
            str(database), str(root), "db_path", "pid", "token_hash",
            "process_identity", "private-token", "private-error.txt",
        ):
            self.assertNotIn(secret, rendered)

    def test_continuity_control_requires_explicit_cli_capability(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            listed = responses(run_mcp(
                [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}],
                database,
                "--allow-continuity-control",
            ).stdout)[0]
            names = {tool["name"] for tool in listed["result"]["tools"]}
            self.assertIn("brain_continuity_control", names)

            gateway = subprocess.run(
                [
                    sys.executable, str(MCP), "--brain-dir", str(Path(tmp) / "brains"),
                    "--allow-continuity-control",
                ],
                text=True,
                capture_output=True,
                cwd=ROOT,
                check=False,
            )
            self.assertNotEqual(gateway.returncode, 0)
            self.assertIn("capability flags are only valid", gateway.stderr)

    def test_thread_root_accepts_a_trusted_parent_alias(self):
        if os.name == "nt":
            self.skipTest("parent alias coverage uses POSIX symlink support")
        with tempfile.TemporaryDirectory() as tmp:
            real_parent = Path(tmp) / "real"
            real_parent.mkdir()
            root = real_parent / "allowed"
            root.mkdir()
            thread = root / "thread.md"
            thread.write_text("Decision: preserve canonical identity.\n", encoding="utf-8")
            alias_parent = Path(tmp) / "alias"
            alias_parent.symlink_to(real_parent, target_is_directory=True)
            database = Path(tmp) / "brain.sqlite"
            conn = connect(database)
            try:
                init_project(conn, "demo", str(root))
            finally:
                conn.close()

            server = RtaBrainMcpServer(
                database,
                "demo",
                allow_thread_ingestion=True,
                allowed_thread_roots=(alias_parent / "allowed",),
            )
            with patch("rta_brain.mcp_server.ingest_thread", return_value={"status": "ok"}):
                result = server.call_tool(
                    "brain_ingest_thread",
                    {"path": str(alias_parent / "allowed" / thread.name)},
                )
            self.assertEqual(result["structuredContent"]["status"], "ok")

    def test_brain_directory_gateway_requires_explicit_project_in_advertised_schemas(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = RtaBrainMcpServer(None, None, brain_dir=Path(tmp))

            for tool in server.agent_tools:
                schema = tool["inputSchema"]
                self.assertIn("project", schema["properties"], tool["name"])
                self.assertIn("project", schema["required"], tool["name"])
            with self.assertRaisesRegex(ValueError, "project is required"):
                server.call_tool("brain_search", {"query": "missing route"})

    def test_brain_directory_gateway_routes_projects_without_duplicate_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain_dir = Path(tmp)
            for name in ("alpha", "beta"):
                conn = brain_db.connect(brain_dir / f"{name}.sqlite")
                try:
                    brain_db.init_project(conn, name, str(brain_dir / name))
                    brain_db.remember(conn, f"{name} canonical memory", project=name)
                finally:
                    conn.close()
            result = run_gateway(
                [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "brain_search", "arguments": {"project": "beta", "query": "canonical memory"}}}],
                brain_dir,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            text = responses(result.stdout)[0]["result"]["content"][0]["text"]
            self.assertIn("beta canonical memory", text)
            self.assertNotIn("alpha canonical memory", text)

    def test_brain_directory_gateway_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain_dir = Path(tmp)
            conn = brain_db.connect(brain_dir / "alpha.sqlite")
            try:
                brain_db.init_project(conn, "alpha", str(brain_dir / "alpha"))
            finally:
                conn.close()

            server = RtaBrainMcpServer(None, None, brain_dir=brain_dir)
            exposed = {tool["name"] for tool in server.agent_tools}
            mutation_tools = {
                *mcp_server.MEMORY_WRITE_TOOLS,
                *mcp_server.REPO_INGESTION_TOOLS,
                *mcp_server.THREAD_INGESTION_TOOLS,
                *mcp_server.TEMPORAL_WRITE_TOOLS,
                *mcp_server.TEMPORAL_VALIDATOR_RUN_TOOLS,
                *mcp_server.CAPTURE_WRITE_TOOLS,
                *mcp_server.CAPTURE_DESTRUCTIVE_TOOLS,
                *mcp_server.OWNER_ONLY_GOVERNANCE_TOOLS,
                "brain_ingest_codex_session",
                "brain_session_event",
                "brain_work_item",
                "brain_continuity_control",
                "brain_reconcile",
            }
            self.assertFalse(exposed.intersection(mutation_tools))
            with self.assertRaisesRegex(ValueError, "not enabled"):
                server.call_tool(
                    "brain_remember",
                    {"project": "alpha", "text": "must not be written"},
                )
            with self.assertRaisesRegex(ValueError, "read-only gateway"):
                server.call_tool(
                    "brain_stale_check",
                    {"project": "alpha", "rehash": True},
                )

    def test_initialize_and_list_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            result = run_mcp(
                [
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                ],
                db,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payloads = responses(result.stdout)
            self.assertEqual(payloads[0]["id"], 1)
            self.assertIn("serverInfo", payloads[0]["result"])
            self.assertEqual(payloads[1]["id"], 2)
            tool_names = {tool["name"] for tool in payloads[1]["result"]["tools"]}
            self.assertIn("brain_search", tool_names)
            self.assertIn("brain_context_pack", tool_names)
            self.assertIn("brain_stale_check", tool_names)
            self.assertIn("brain_continuation_prompt", tool_names)
            self.assertNotIn("brain_remember", tool_names)
            self.assertNotIn("brain_checkpoint", tool_names)
            self.assertNotIn("brain_reflect", tool_names)
            self.assertNotIn("brain_ingest_repo", tool_names)
            self.assertNotIn("brain_ingest_thread", tool_names)
            self.assertNotIn("brain_workspace_search", tool_names)
            self.assertNotIn("brain_workspace_list", tool_names)

    def test_initialize_negotiates_supported_version_and_all_notifications_are_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            result = run_mcp(
                [
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2099-01-01"}},
                    {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "brain_remember", "arguments": {"text": "notification side effect"}}},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "brain_search", "arguments": {"query": "notification side effect"}}},
                ],
                db,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payloads = responses(result.stdout)
            self.assertEqual(len(payloads), 2)
            self.assertEqual(payloads[0]["result"]["protocolVersion"], "2025-06-18")
            self.assertIn("notification side effect", payloads[1]["result"]["content"][0]["text"])

    def test_tool_calls_remember_search_and_context_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            result = run_mcp(
                [
                    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "brain_remember",
                            "arguments": {
                                "text": "Codex should ask Rta-Smriti for context before broad repo scans.",
                                "type": "constraint",
                                "pramana": "sabda",
                                "priority": 9,
                            },
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "brain_search", "arguments": {"query": "context repo scans"}},
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {"name": "brain_context_pack", "arguments": {"task": "prepare repo work"}},
                    },
                ],
                db,
                "--allow-memory-writes",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payloads = responses(result.stdout)
            self.assertEqual(len(payloads), 4)
            payloads_by_id = {payload["id"]: payload for payload in payloads}
            search_text = payloads_by_id[3]["result"]["content"][0]["text"]
            self.assertIn("Rta-Smriti", search_text)
            pack_text = payloads_by_id[4]["result"]["content"][0]["text"]
            self.assertIn("# Rta-Smriti Context Pack", pack_text)
            self.assertIn("Pramana: anumana", pack_text)

    def test_project_override_is_rejected_even_for_read_only_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            result = run_mcp(
                [{
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "brain_search",
                        "arguments": {"project": "other", "query": "secret"},
                    },
                }],
                db,
            )
            payload = responses(result.stdout)[0]
            self.assertEqual(payload["error"]["code"], -32000)
            self.assertIn("bound to project 'demo'", payload["error"]["message"])

    def test_mutations_require_explicit_startup_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            call = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "brain_remember", "arguments": {"text": "not authorized"}},
            }
            denied = responses(run_mcp([call], db).stdout)[0]
            self.assertEqual(denied["error"]["code"], -32000)
            self.assertIn("not enabled", denied["error"]["message"])

            listed = responses(run_mcp(
                [{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}],
                db,
                "--allow-memory-writes",
                "--allow-repo-ingestion",
                "--allow-thread-ingestion",
                "--allow-thread-root",
                str(Path(tmp)),
            ).stdout)[0]
            names = {tool["name"] for tool in listed["result"]["tools"]}
            self.assertTrue({
                "brain_remember", "brain_remember_batch", "brain_checkpoint", "brain_reflect",
                "brain_ingest_repo", "brain_ingest_thread",
            }.issubset(names))
            remember_schema = next(
                tool for tool in listed["result"]["tools"] if tool["name"] == "brain_remember"
            )["inputSchema"]["properties"]
            self.assertEqual(remember_schema["pramana"]["enum"], ["anumana"])
            self.assertEqual(remember_schema["confidence"]["maximum"], 0.75)
            self.assertNotIn("source_path", remember_schema["provenance"]["properties"])
            self.assertNotIn("source_hash", remember_schema["provenance"]["properties"])
            self.assertEqual(
                remember_schema["provenance"]["properties"]["verification_status"]["enum"],
                ["unverified"],
            )
            repo_schema = next(
                tool for tool in listed["result"]["tools"] if tool["name"] == "brain_ingest_repo"
            )["inputSchema"]
            self.assertNotIn("path", repo_schema["properties"])
            self.assertNotIn("path", repo_schema["required"])

    def test_repo_ingestion_is_confined_to_the_bound_project_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bound"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            (outside / "secret.py").write_text("SECRET = True\n", encoding="utf-8")
            brain = Path(tmp) / "brain.sqlite"
            conn = connect(brain)
            try:
                init_project(conn, "demo", str(root))
            finally:
                conn.close()
            server = RtaBrainMcpServer(brain, "demo", allow_repo_ingestion=True)

            accepted = server.call_tool("brain_ingest_repo", {})
            self.assertEqual(accepted["structuredContent"]["root"], str(root.resolve()))
            with self.assertRaisesRegex(ValueError, "confined to the canonical project root"):
                server.call_tool("brain_ingest_repo", {"path": str(outside)})

    def test_repo_ingestion_short_circuits_when_index_is_already_fresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bound"
            root.mkdir()
            (root / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            brain = Path(tmp) / "brain.sqlite"
            conn = connect(brain)
            try:
                init_project(conn, "demo", str(root))
                brain_db.ingest_repo(conn, root, project="demo")
            finally:
                conn.close()
            server = RtaBrainMcpServer(brain, "demo", allow_repo_ingestion=True)

            with patch("rta_brain.mcp_server.ingest_repo", side_effect=AssertionError("full ingestion should not run")):
                accepted = server.call_tool("brain_ingest_repo", {})

            payload = accepted["structuredContent"]
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["state"], "fresh")
            self.assertTrue(payload["manifest_unchanged"])
            self.assertTrue(payload["mcp_short_circuit"])
            self.assertEqual(payload["indexed_files"], 1)

    def test_mcp_memory_writes_are_downgraded_to_unverified_agent_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            messages = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "brain_remember",
                        "arguments": {
                            "text": "agent assertion",
                            "pramana": "pratyaksha",
                            "confidence": 1,
                            "provenance": {
                                "source_path": "C:/secret.txt",
                                "source_hash": "forged",
                                "verification_status": "verified",
                                "command": "pytest",
                            },
                        },
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "brain_remember_batch",
                        "arguments": {"items": [{
                            "text": "batch assertion",
                            "pramana": "sabda",
                            "confidence": 0.95,
                            "provenance": {"source_hash": "forged", "verification_status": "verified"},
                        }]},
                    },
                },
            ]
            result = run_mcp(messages, db, "--allow-memory-writes")
            payloads = responses(result.stdout)
            for memory in (
                payloads[0]["result"]["structuredContent"]["memory"],
                payloads[1]["result"]["structuredContent"]["memories"][0],
            ):
                self.assertEqual(memory["pramana"], "anumana")
                self.assertLessEqual(memory["confidence"], 0.75)
                self.assertEqual(memory["provenance"]["verification_status"], "unverified")
                self.assertIsNone(memory["provenance"]["source_path"])
                self.assertIsNone(memory["provenance"]["source_hash"])

    def test_thread_ingestion_is_confined_and_rejects_linked_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "allowed"
            root.mkdir()
            safe = root / "thread.md"
            safe.write_text("Decision: retain the verified boundary.\n", encoding="utf-8")
            outside = Path(tmp) / "outside.md"
            outside.write_text("Decision: disclose private data.\n", encoding="utf-8")
            db = Path(tmp) / "brain.sqlite"
            args = ("--allow-thread-ingestion", "--allow-thread-root", str(root))

            accepted = responses(run_mcp([{
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "brain_ingest_thread", "arguments": {"path": str(safe)}},
            }], db, *args).stdout)[0]
            self.assertEqual(accepted["result"]["structuredContent"]["status"], "ok")

            denied = responses(run_mcp([{
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "brain_ingest_thread", "arguments": {"path": str(outside)}},
            }], db, *args).stdout)[0]
            self.assertIn("outside configured thread roots", denied["error"]["message"])

            hardlink = root / "hardlink.md"
            os.link(safe, hardlink)
            linked = responses(run_mcp([{
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "brain_ingest_thread", "arguments": {"path": str(hardlink)}},
            }], db, *args).stdout)[0]
            self.assertIn("hardlink", linked["error"]["message"])

            symlink = root / "symlink.md"
            try:
                symlink.symlink_to(outside)
            except OSError:
                return
            symlinked = responses(run_mcp([{
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "brain_ingest_thread", "arguments": {"path": str(symlink)}},
            }], db, *args).stdout)[0]
            self.assertIn("link or reparse", symlinked["error"]["message"])

    def test_thread_ingestion_binds_secure_read_to_the_matched_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "allowed"
            root.mkdir()
            thread = root / "thread.md"
            thread.write_text("Decision: retain the boundary.\n", encoding="utf-8")
            database = Path(tmp) / "brain.sqlite"
            conn = connect(database)
            try:
                init_project(conn, "default", str(root))
            finally:
                conn.close()
            server = RtaBrainMcpServer(
                database,
                "default",
                allow_thread_ingestion=True,
                allowed_thread_roots=(root,),
            )

            with patch("rta_brain.mcp_server.ingest_thread", return_value={"status": "ok"}) as ingest:
                result = server.call_tool("brain_ingest_thread", {"path": str(thread)})

            self.assertEqual(result["structuredContent"]["status"], "ok")
            self.assertEqual(ingest.call_args.kwargs["root"], root.resolve())

    def test_scheduler_applies_request_count_backpressure(self):
        class SlowServer(RtaBrainMcpServer):
            async def handle_async(self, request):
                await asyncio.sleep(0.08)
                return {"jsonrpc": "2.0", "id": request["id"], "result": {}}

        async def exercise():
            emitted = []

            async def emit(response):
                emitted.append(response["id"])

            scheduler = McpRequestScheduler(
                object.__new__(SlowServer), emit,
                max_concurrency=1, max_outstanding=1, max_outstanding_bytes=1_000,
            )
            await scheduler.submit({"jsonrpc": "2.0", "id": 1, "method": "ping"}, frame_bytes=60)
            blocked = asyncio.create_task(
                scheduler.submit({"jsonrpc": "2.0", "id": 2, "method": "ping"}, frame_bytes=60)
            )
            await asyncio.sleep(0.02)
            was_blocked = not blocked.done()
            await blocked
            await scheduler.close()
            return was_blocked, emitted, scheduler.peak_outstanding, scheduler.peak_outstanding_bytes

        was_blocked, emitted, peak_count, peak_bytes = asyncio.run(exercise())
        self.assertTrue(was_blocked)
        self.assertEqual(emitted, [1, 2])
        self.assertEqual(peak_count, 1)
        self.assertEqual(peak_bytes, 60)

    def test_scheduler_applies_byte_backpressure(self):
        class SlowServer(RtaBrainMcpServer):
            async def handle_async(self, request):
                await asyncio.sleep(0.08)
                return {"jsonrpc": "2.0", "id": request["id"], "result": {}}

        async def exercise():
            async def emit(_response):
                return None

            scheduler = McpRequestScheduler(
                object.__new__(SlowServer), emit,
                max_concurrency=2, max_outstanding=3, max_outstanding_bytes=100,
            )
            await scheduler.submit({"jsonrpc": "2.0", "id": 1, "method": "ping"}, frame_bytes=60)
            blocked = asyncio.create_task(
                scheduler.submit({"jsonrpc": "2.0", "id": 2, "method": "ping"}, frame_bytes=60)
            )
            await asyncio.sleep(0.02)
            was_blocked = not blocked.done()
            await blocked
            await scheduler.close()
            return was_blocked, scheduler.peak_outstanding_bytes

        was_blocked, peak_bytes = asyncio.run(exercise())
        self.assertTrue(was_blocked)
        self.assertEqual(peak_bytes, 60)

    def test_scheduler_preserves_mutation_order_for_following_tool_calls(self):
        class OrderedServer(RtaBrainMcpServer):
            def __init__(self):
                self.events = []

            async def handle_async(self, request):
                name = request["params"]["name"]
                self.events.append(f"start:{name}")
                if name == "brain_remember":
                    await asyncio.sleep(0.05)
                self.events.append(f"end:{name}")
                return {"jsonrpc": "2.0", "id": request["id"], "result": {}}

        async def exercise():
            server = OrderedServer()

            async def emit(_response):
                return None

            scheduler = McpRequestScheduler(server, emit, max_concurrency=2)
            await scheduler.submit({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "brain_remember", "arguments": {"text": "first"}},
            })
            await scheduler.submit({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "brain_search", "arguments": {"query": "first"}},
            })
            await scheduler.close()
            return server.events

        self.assertEqual(asyncio.run(exercise()), [
            "start:brain_remember", "end:brain_remember", "start:brain_search", "end:brain_search",
        ])

    def test_excessive_json_nesting_and_recursion_errors_are_contained(self):
        nested = (b"[" * 80) + (b"]" * 80)
        with self.assertRaisesRegex(ValueError, "nesting"):
            mcp_server.parse_request_frame(nested)
        with patch(
            "rta_brain.mcp_server.json.loads", side_effect=RecursionError("too deep")
        ), self.assertRaisesRegex(ValueError, "nesting"):
            mcp_server.parse_request_frame(b'{"jsonrpc":"2.0"}')

        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            prepare_mcp_db(db)
            body = nested.decode("ascii") + "\n" + json.dumps(
                {"jsonrpc": "2.0", "id": 2, "method": "ping"}
            ) + "\n"
            result = subprocess.run(
                [sys.executable, str(MCP), "--db", str(db), "--project", "demo"],
                input=body, text=True, capture_output=True, cwd=ROOT,
                check=False,
            )
            payloads = responses(result.stdout)
            self.assertEqual(payloads[0]["error"]["code"], -32700)
            self.assertEqual(payloads[1]["id"], 2)

    def test_invalid_tool_returns_json_rpc_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            result = run_mcp(
                [
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "brain_unknown", "arguments": {}},
                    }
                ],
                db,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = responses(result.stdout)[0]
            self.assertEqual(payload["error"]["code"], -32601)
            self.assertIn("unknown tool", payload["error"]["message"])

    def test_non_object_json_returns_error_without_stopping_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            result = run_mcp([[], {"jsonrpc": "2.0", "id": 2, "method": "ping"}], db)
            self.assertEqual(result.returncode, 0, result.stderr)
            payloads = responses(result.stdout)
            self.assertEqual(payloads[0]["error"]["code"], -32600)
            self.assertEqual(payloads[1]["id"], 2)

    def test_oversized_frame_is_rejected_and_next_frame_is_processed(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            oversized = {"jsonrpc": "2.0", "id": 1, "method": "ping", "padding": "x" * 1_100_000}
            result = run_mcp([oversized, {"jsonrpc": "2.0", "id": 2, "method": "ping"}], db)
            self.assertEqual(result.returncode, 0, result.stderr)
            payloads = responses(result.stdout)
            self.assertEqual(payloads[0]["error"]["code"], -32600)
            self.assertIn("frame exceeds", payloads[0]["error"]["message"])
            self.assertEqual(payloads[1]["id"], 2)

    def test_multibyte_frame_limit_is_enforced_in_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            oversized = {"jsonrpc": "2.0", "id": 1, "method": "ping", "padding": "\u0915" * 400_000}
            result = run_mcp([oversized, {"jsonrpc": "2.0", "id": 2, "method": "ping"}], db)
            self.assertEqual(result.returncode, 0, result.stderr)
            payloads = responses(result.stdout)
            self.assertEqual(payloads[0]["error"]["code"], -32600)
            self.assertIn("bytes", payloads[0]["error"]["message"])
            self.assertEqual(payloads[1]["id"], 2)


if __name__ == "__main__":
    unittest.main()
