import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from rta_brain import db
from rta_brain.capture import append_event, register_policy, register_source
from rta_brain.capture_daemon import capture_cycle
from rta_brain.capture_spool import CaptureSpool, capture_control_root_path
from rta_brain.capture_types import CapturePolicy, CaptureSource, NormalizedEvent
from rta_brain.cli import build_parser, main
from rta_brain.mcp_server import RtaBrainMcpServer


class CaptureCliMcpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        self.database = self.base / "brain.sqlite"
        conn = db.connect(self.database)
        db.init_project(conn, "demo", str(self.root))
        self.policy = CapturePolicy.continuity()
        register_policy(
            conn,
            project="demo",
            active_root=self.root,
            policy_id="continuity",
            policy_version=1,
            policy=self.policy,
        )
        register_source(
            conn,
            project="demo",
            active_root=self.root,
            source=CaptureSource(
                source_id="generic-local",
                adapter="generic",
                adapter_version="1",
                installation_scope="api",
                config_fingerprint=hashlib.sha256(b"generic-local").hexdigest(),
            ),
            policy_digest=self.policy.digest,
        )
        conn.close()

    def tearDown(self):
        self.temp.cleanup()

    def test_session_event_mcp_schema_bounds_durable_identifiers(self):
        server = RtaBrainMcpServer(
            self.database, "demo", allow_memory_writes=True
        )
        schema = next(
            tool["inputSchema"]
            for tool in server.agent_tools
            if tool["name"] == "brain_session_event"
        )

        self.assertEqual(schema["properties"]["session_id"]["maxLength"], 512)
        self.assertEqual(schema["properties"]["cursor"]["maxLength"], 1024)
        self.assertEqual(schema["properties"]["event_type"]["maxLength"], 128)

    def run_cli(self, *arguments, stdin_text=None):
        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = [
            "--db",
            str(self.database),
            "--json",
            "capture",
            "--project",
            "demo",
            "--root",
            str(self.root),
            *arguments,
        ]
        stream = io.StringIO(stdin_text) if stdin_text is not None else None
        with redirect_stdout(stdout), redirect_stderr(stderr):
            if stream is None:
                code = main(argv)
            else:
                original = __import__("sys").stdin
                try:
                    __import__("sys").stdin = stream
                    code = main(argv)
                finally:
                    __import__("sys").stdin = original
        return code, stdout.getvalue(), stderr.getvalue()

    def run_cli_process(self, *arguments):
        command = [
            sys.executable,
            "-m",
            "rta_brain.cli",
            "--db",
            str(self.database),
            "--json",
            "capture",
            "--project",
            "demo",
            "--root",
            str(self.root),
            *arguments,
        ]
        return subprocess.run(
            command,
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_source_adapter_command_uses_isolated_trusted_module_resolution(self):
        from types import SimpleNamespace

        from rta_brain.cli import _capture_adapter_command
        from rta_brain.runtime_control import runtime_executable

        command = _capture_adapter_command(
            SimpleNamespace(db=self.database, project="demo", root=self.root),
            "generic-project-local",
        )

        self.assertEqual(command[0], str(runtime_executable()))
        self.assertEqual(command[1:3], ("-I", "-c"))
        self.assertIn("runpy.run_module('rta_brain.cli'", command[3])
        self.assertNotIn("-m", command)

    @staticmethod
    def forge_confirmation_token(token):
        payload, signature = token.split(".", 1)
        replacement = "A" if signature[0] != "A" else "B"
        return f"{payload}.{replacement}{signature[1:]}"

    def test_capture_parser_exposes_complete_nested_command_surface(self):
        parser = build_parser()
        commands = {
            ("policy", "list"),
            ("policy", "create"),
            ("policy", "retire"),
            ("adapter", "list"),
            ("adapter", "plan"),
            ("adapter", "install"),
            ("adapter", "remove"),
            ("adapter", "pause"),
            ("adapter", "resume"),
            ("adapter", "status"),
            ("daemon", "start"),
            ("daemon", "status"),
            ("daemon", "stop"),
        }
        for group, action in commands:
            parsed = parser.parse_args(
                [
                    "capture",
                    "--project",
                    "demo",
                    "--root",
                    str(self.root),
                    group,
                    action,
                ]
            )
            self.assertEqual(
                (parsed.capture_group, parsed.capture_action), (group, action)
            )
        for action in (
            "emit",
            "bind-session",
            "events",
            "replay",
            "retain",
            "redact",
            "delete",
            "export",
            "doctor",
        ):
            parsed = parser.parse_args(
                [
                    "capture",
                    "--project",
                    "demo",
                    "--root",
                    str(self.root),
                    action,
                ]
            )
            self.assertEqual(parsed.capture_group, action)

    def test_policy_list_and_create_emit_stable_json(self):
        code, output, error = self.run_cli("policy", "list")
        self.assertEqual(code, 0, error)
        listed = json.loads(output)
        self.assertEqual(listed["policies"][0]["profile"], "continuity")

        code, output, error = self.run_cli(
            "policy",
            "create",
            "--id",
            "metadata",
            "--version",
            "1",
            "--profile",
            "metadata-only",
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["policy_id"], "metadata")

    def test_default_mcp_is_read_only_and_never_exposes_adapter_installation(self):
        server = RtaBrainMcpServer(self.database, "demo")
        exposed = {tool["name"] for tool in server.agent_tools}
        self.assertTrue(
            {
                "brain_capture_status",
                "brain_capture_events",
                "brain_capture_replay",
                "brain_capture_diagnostics",
            }.issubset(exposed)
        )
        self.assertFalse(
            {
                "brain_capture_policy_create",
                "brain_capture_bind_session",
                "brain_capture_delete",
                "brain_capture_adapter_install",
                "brain_capture_adapter_plan",
                "brain_capture_adapter_remove",
            }.intersection(exposed)
        )

        status = server.call_tool("brain_capture_status", {})["structuredContent"]
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["sources"][0]["source_id"], "generic-local")
        self.assertFalse((self.base / ".rta-smriti-capture").exists())

    def test_capture_mcp_mutations_require_explicit_capability(self):
        denied = RtaBrainMcpServer(self.database, "demo")
        with self.assertRaisesRegex(ValueError, "not enabled"):
            denied.call_tool(
                "brain_capture_policy_create",
                {
                    "policy_id": "mcp-metadata",
                    "policy_version": 1,
                    "profile": "metadata-only",
                },
            )

        allowed = RtaBrainMcpServer(
            self.database,
            "demo",
            allow_capture_writes=True,
        )
        allowed_tools = {tool["name"] for tool in allowed.agent_tools}
        self.assertFalse(
            {
                "brain_capture_retain",
                "brain_capture_redact",
                "brain_capture_delete",
            }.intersection(allowed_tools)
        )
        with self.assertRaisesRegex(ValueError, "not enabled"):
            allowed.call_tool(
                "brain_capture_delete",
                {
                    "scope": "project-content",
                    "scope_token": "demo",
                    "reason_class": "operator-request",
                    "policy_digest": self.policy.digest,
                    "confirm": False,
                },
            )
        created = allowed.call_tool(
            "brain_capture_policy_create",
            {
                "policy_id": "mcp-metadata",
                "policy_version": 1,
                "profile": "metadata-only",
            },
        )["structuredContent"]
        self.assertEqual(created["policy_id"], "mcp-metadata")
        self.assertNotIn(
            "brain_capture_adapter_install",
            allowed_tools,
        )

        destructive = RtaBrainMcpServer(
            self.database,
            "demo",
            allow_capture_destructive=True,
        )
        destructive_tools = {tool["name"] for tool in destructive.agent_tools}
        self.assertTrue(
            {
                "brain_capture_retain",
                "brain_capture_redact",
                "brain_capture_delete",
            }.issubset(destructive_tools)
        )
        self.assertNotIn("brain_capture_policy_create", destructive_tools)

    def test_capture_mcp_events_are_bounded_and_redacted(self):
        conn = db.connect(self.database)
        try:
            append_event(
                conn,
                project="demo",
                active_root=self.root,
                source_id="generic-local",
                event=NormalizedEvent(
                    event_name="tool.completed.v1",
                    session_id="root-path-session",
                    source_cursor="1",
                    observed_at="2026-08-23T01:00:01+00:00",
                    occurred_at="2026-08-23T01:00:00+00:00",
                    attributes={"summary": "C:" + "\\PrivateRoot"},
                    actor_type="agent",
                    actor_id="synthetic-agent",
                ),
                idempotency_key="mcp:root-path-redaction",
                cursor_kind="sequence",
                original_bytes=64,
            )
        finally:
            conn.close()
        server = RtaBrainMcpServer(self.database, "demo")
        result = server.call_tool(
            "brain_capture_events",
            {"after_sequence": 0, "limit": 10},
        )["structuredContent"]
        self.assertEqual(result["schema_version"], "rta-smriti.capture-export/v1")
        self.assertTrue(result["redaction_verified"])
        self.assertFalse(result["payloads_included"])
        self.assertNotIn("PrivateRoot", json.dumps(result, sort_keys=True))
        with self.assertRaisesRegex(PermissionError, "public or internal"):
            server.call_tool(
                "brain_capture_events",
                {"privacy_ceiling": "restricted"},
            )

    def test_capture_mcp_delegated_lifecycle_controls_preserve_receipts(self):
        server = RtaBrainMcpServer(
            self.database,
            "demo",
            allow_capture_writes=True,
            allow_capture_destructive=True,
        )
        bound = server.call_tool(
            "brain_capture_bind_session",
            {
                "source_id": "generic-local",
                "external_session_id": "external-a",
                "cursor_kind": "sequence",
                "start_cursor": "1",
            },
        )["structuredContent"]
        self.assertEqual(bound["status"], "active")
        closed = server.call_tool(
            "brain_capture_close_binding",
            {"binding_id": bound["binding_id"]},
        )["structuredContent"]
        self.assertEqual(closed["status"], "closed")

        paused = server.call_tool(
            "brain_capture_source_state",
            {"source_id": "generic-local", "state": "paused"},
        )["structuredContent"]
        self.assertEqual(paused["state"], "paused")
        resumed = server.call_tool(
            "brain_capture_source_state",
            {"source_id": "generic-local", "state": "active"},
        )["structuredContent"]
        self.assertEqual(resumed["state"], "active")
        with self.assertRaisesRegex(ValueError, "only be active or paused"):
            server.call_tool(
                "brain_capture_source_state",
                {"source_id": "generic-local", "state": "removed"},
            )

        retain_schema = next(
            tool["inputSchema"]
            for tool in server.agent_tools
            if tool["name"] == "brain_capture_retain"
        )
        self.assertNotIn("now", retain_schema["properties"])
        retention_preview = server.call_tool(
            "brain_capture_retain",
            {
                "policy_digest": self.policy.digest,
                "run_id": "mcp-retain-1",
                "confirm": False,
            },
        )["structuredContent"]
        self.assertEqual(retention_preview["operation"], "preview")
        self.assertIsNotNone(retention_preview["confirmation_token"])
        verification_conn = db.connect(self.database)
        try:
            self.assertEqual(
                verification_conn.execute(
                    "SELECT COUNT(*) FROM capture_retention_runs"
                ).fetchone()[0],
                0,
            )
        finally:
            verification_conn.close()
        retained = server.call_tool(
            "brain_capture_retain",
            {
                "policy_digest": self.policy.digest,
                "run_id": "mcp-retain-1",
                "confirm": True,
                "confirmation_token": retention_preview["confirmation_token"],
            },
        )["structuredContent"]
        self.assertEqual(retained["state"], "complete")

        for tool in ("brain_capture_redact", "brain_capture_delete"):
            preview = server.call_tool(
                tool,
                {
                    "scope": "project-content",
                    "scope_token": "demo",
                    "reason_class": "operator-request",
                    "policy_digest": self.policy.digest,
                    "confirm": False,
                },
            )["structuredContent"]
            self.assertEqual(preview["operation"], "preview")

    def test_retention_confirmation_rejects_missing_forged_and_stale_tokens(self):
        server = RtaBrainMcpServer(
            self.database,
            "demo",
            allow_capture_destructive=True,
        )
        arguments = {
            "policy_digest": self.policy.digest,
            "run_id": "mcp-retention-confirmation",
            "batch_size": 100,
        }
        preview = server.call_tool(
            "brain_capture_retain", {**arguments, "confirm": False}
        )["structuredContent"]
        with self.assertRaisesRegex(PermissionError, "requires its preview"):
            server.call_tool(
                "brain_capture_retain", {**arguments, "confirm": True}
            )
        with self.assertRaisesRegex(PermissionError, "token is invalid"):
            server.call_tool(
                "brain_capture_retain",
                {
                    **arguments,
                    "confirm": True,
                    "confirmation_token": self.forge_confirmation_token(
                        preview["confirmation_token"]
                    ),
                },
            )

        conn = db.connect(self.database)
        try:
            append_event(
                conn,
                project="demo",
                active_root=self.root,
                source_id="generic-local",
                event=NormalizedEvent(
                    event_name="agent.message.v1",
                    session_id="retention-session",
                    source_cursor="1",
                    observed_at="2026-08-22T10:00:01+00:00",
                    occurred_at="2026-08-22T10:00:00+00:00",
                    attributes={"text": "new state after preview"},
                    actor_type="agent",
                    actor_id="test-agent",
                ),
                idempotency_key="retention-stale:1",
                cursor_kind="sequence",
                original_bytes=32,
            )
        finally:
            conn.close()
        with self.assertRaisesRegex(PermissionError, "current preview"):
            server.call_tool(
                "brain_capture_retain",
                {
                    **arguments,
                    "confirm": True,
                    "confirmation_token": preview["confirmation_token"],
                },
            )

    def test_emit_replay_bind_retention_redaction_export_and_doctor_flow(self):
        event = {
            "source_cursor": "1",
            "cursor_kind": "sequence",
            "session_id": "session-a",
            "observed_at": "2026-08-22T10:00:01+00:00",
            "occurred_at": "2026-08-22T10:00:00+00:00",
            "vendor_event": "turn_start",
            "payload": {"status": "running", "authorization": "Bearer hidden-value"},
        }
        code, output, error = self.run_cli(
            "emit",
            "--source-id",
            "generic-local",
            stdin_text=json.dumps(event),
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["status"], "stored")
        spool_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in CaptureSpool(self.database).root.rglob("*.json")
        )
        self.assertNotIn("authorization", spool_text.lower())
        self.assertNotIn("hidden-value", spool_text)
        conn = db.connect(self.database)
        try:
            cycle = capture_cycle(conn, self.database, max_events=10)
        finally:
            conn.close()
        self.assertEqual(cycle["events_inserted"], 1)

        code, output, error = self.run_cli("events", "--limit", "10")
        self.assertEqual(code, 0, error)
        page = json.loads(output)
        self.assertEqual(len(page["events"]), 1)
        self.assertNotIn("hidden-value", output)
        event_id = page["events"][0]["event_id"]

        code, output, error = self.run_cli("replay", "--mode", "causal")
        self.assertEqual(code, 0, error)
        replay = json.loads(output)
        self.assertEqual(replay["mode"], "causal")
        self.assertFalse(replay["executes_actions"])

        code, output, error = self.run_cli(
            "bind-session",
            "--source-id",
            "generic-local",
            "--session-id",
            "session-b",
            "--start-cursor",
            "2",
        )
        self.assertEqual(code, 0, error)
        binding = json.loads(output)
        self.assertEqual(binding["status"], "active")
        code, output, error = self.run_cli(
            "bind-session",
            "--close-binding",
            binding["binding_id"],
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["status"], "closed")

        code, output, error = self.run_cli(
            "retain",
            "--policy-digest",
            self.policy.digest,
            "--run-id",
            "retain-1",
            "--now",
            "2026-08-22T11:00:00+00:00",
        )
        self.assertEqual(code, 0, error)
        retention_preview = json.loads(output)
        self.assertEqual(retention_preview["operation"], "preview")
        code, output, error = self.run_cli(
            "retain",
            "--policy-digest",
            self.policy.digest,
            "--run-id",
            "retain-1",
            "--now",
            "2026-08-22T11:00:00+00:00",
            "--confirm",
            "--confirmation-token",
            retention_preview["confirmation_token"],
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["state"], "complete")

        for action in ("redact", "delete"):
            code, output, error = self.run_cli(
                action,
                "--scope",
                "event-content",
                "--scope-token",
                event_id,
                "--policy-digest",
                self.policy.digest,
            )
            self.assertEqual(code, 0, error)
            self.assertEqual(json.loads(output)["operation"], "preview")

        export_path = self.base / "capture-export.json"
        code, output, error = self.run_cli(
            "export",
            "--output",
            str(export_path),
        )
        self.assertEqual(code, 0, error)
        receipt = json.loads(output)
        self.assertTrue(receipt["redaction_verified"])
        self.assertTrue(export_path.is_file())
        self.assertNotIn("hidden-value", export_path.read_text(encoding="utf-8"))

        code, output, error = self.run_cli("doctor")
        self.assertEqual(code, 0, error)
        diagnostics = json.loads(output)
        self.assertTrue(diagnostics["journal"]["chain_valid"])
        self.assertNotIn(str(self.base), output)

    def test_passive_emit_rejects_deep_json_without_nonzero_exit_or_durable_write(self):
        deep_json = '{"source_cursor":"1","session_id":"session-a","payload":' + (
            "[" * 5000
        ) + "0" + ("]" * 5000) + "}"

        code, output, error = self.run_cli(
            "emit",
            "--source-id",
            "generic-local",
            stdin_text=deep_json,
        )

        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output), {"status": "rejected", "reason": "invalid_json"})
        self.assertEqual(error, "")
        spool = CaptureSpool(self.database)
        self.assertFalse(any(path.is_dir() for path in spool.root.iterdir()))

    def test_private_export_removes_file_when_windows_acl_hardening_fails(self):
        from rta_brain.cli import _write_private_export

        target = self.base / "private-export.json"
        with (
            patch("rta_brain.cli.os.name", "nt"),
            patch(
                "rta_brain.cli.ensure_windows_path_private",
                side_effect=RuntimeError("synthetic ACL failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "ACL failure"),
        ):
            _write_private_export(
                target,
                {"events": [], "redaction_verified": True},
            )

        self.assertFalse(target.exists())

    def test_private_export_hardens_windows_acl_before_writing_bytes(self):
        from rta_brain.cli import _write_private_export

        target = self.base / "private-export-order.json"
        observed_sizes = []

        def record_size(path):
            observed_sizes.append(path.stat().st_size)

        with (
            patch("rta_brain.cli.os.name", "nt"),
            patch(
                "rta_brain.cli.ensure_windows_path_private",
                side_effect=record_size,
            ),
            patch("rta_brain.cli.windows_path_is_private", return_value=True),
        ):
            _write_private_export(
                target,
                {"events": [], "redaction_verified": True},
            )

        self.assertTrue(observed_sizes)
        self.assertEqual(observed_sizes[0], 0)
        self.assertGreater(target.stat().st_size, 0)

    def test_adapter_cli_is_preview_first_reversible_and_pauseable(self):
        code, output, error = self.run_cli(
            "adapter",
            "plan",
            "--adapter",
            "cursor",
            "--scope",
            "project",
        )
        self.assertEqual(code, 0, error)
        preview = json.loads(output)
        self.assertEqual(preview["status"], "preview")
        self.assertFalse((self.root / ".cursor" / "hooks.json").exists())

        code, output, error = self.run_cli(
            "adapter",
            "install",
            "--adapter",
            "cursor",
            "--scope",
            "project",
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["status"], "preview")
        install_preview = json.loads(output)
        self.assertTrue(install_preview["confirmation_token"])
        self.assertTrue(install_preview["confirmation_expires_at"])

        code, output, error = self.run_cli(
            "adapter",
            "install",
            "--adapter",
            "cursor",
            "--scope",
            "project",
            "--confirm",
            "--confirmation-token",
            install_preview["confirmation_token"],
        )
        self.assertEqual(code, 0, error)
        installed = json.loads(output)
        self.assertTrue(installed["installed"])
        source_id = installed["source_id"]
        installation_id = installed["installation_id"]

        for action, state in (("pause", "paused"), ("resume", "active")):
            code, output, error = self.run_cli(
                "adapter",
                action,
                "--source-id",
                source_id,
            )
            self.assertEqual(code, 0, error)
            self.assertEqual(json.loads(output)["state"], state)

        code, output, error = self.run_cli(
            "adapter",
            "remove",
            "--installation-id",
            installation_id,
            "--source-id",
            source_id,
        )
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(output)["status"], "preview")
        remove_preview = json.loads(output)
        self.assertTrue(remove_preview["confirmation_token"])
        self.assertTrue(remove_preview["confirmation_expires_at"])
        self.assertTrue((self.root / ".cursor" / "hooks.json").exists())

        code, output, error = self.run_cli(
            "adapter",
            "remove",
            "--installation-id",
            installation_id,
            "--source-id",
            source_id,
            "--confirm",
            "--confirmation-token",
            remove_preview["confirmation_token"],
        )
        self.assertEqual(code, 0, error)
        self.assertTrue(json.loads(output)["removed"])
        self.assertNotIn(
            "hooks",
            json.loads((self.root / ".cursor" / "hooks.json").read_text(encoding="utf-8")),
        )

    def test_adapter_install_confirmation_rejects_missing_forged_and_expired_tokens(self):
        arguments = ("adapter", "install", "--adapter", "cursor", "--scope", "project")
        code, output, error = self.run_cli(*arguments)
        self.assertEqual(code, 0, error)
        preview = json.loads(output)

        for token, expected in (
            (None, "requires its preview confirmation token"),
            (self.forge_confirmation_token(preview["confirmation_token"]), "token is invalid"),
        ):
            confirm_args = [*arguments, "--confirm"]
            if token is not None:
                confirm_args.extend(("--confirmation-token", token))
            code, _, error = self.run_cli(*confirm_args)
            self.assertEqual(code, 1)
            self.assertIn(expected, error)
            self.assertFalse((self.root / ".cursor" / "hooks.json").exists())

        with patch("rta_brain.cli._ADAPTER_CONFIRMATION_TTL_SECONDS", -1):
            code, output, error = self.run_cli(*arguments)
        self.assertEqual(code, 0, error)
        expired = json.loads(output)["confirmation_token"]
        code, _, error = self.run_cli(
            *arguments, "--confirm", "--confirmation-token", expired,
        )
        self.assertEqual(code, 1)
        self.assertIn("token expired", error)
        self.assertFalse((self.root / ".cursor" / "hooks.json").exists())

    def test_adapter_install_confirmation_rejects_stale_and_cross_operation_tokens(self):
        install_args = ("adapter", "install", "--adapter", "cursor", "--scope", "project")
        code, output, error = self.run_cli(*install_args)
        self.assertEqual(code, 0, error)
        first_preview = json.loads(output)
        config = self.root / ".cursor" / "hooks.json"
        config.parent.mkdir()
        config.write_text('{"version": 1}\n', encoding="utf-8")
        code, _, error = self.run_cli(
            *install_args,
            "--confirm",
            "--confirmation-token",
            first_preview["confirmation_token"],
        )
        self.assertEqual(code, 1)
        self.assertIn("does not match the current preview", error)
        self.assertNotIn("hooks", config.read_text(encoding="utf-8"))

        code, output, error = self.run_cli(*install_args)
        self.assertEqual(code, 0, error)
        current_preview = json.loads(output)
        code, output, error = self.run_cli(
            *install_args,
            "--confirm",
            "--confirmation-token",
            current_preview["confirmation_token"],
        )
        self.assertEqual(code, 0, error)
        installed = json.loads(output)
        code, output, error = self.run_cli(
            "adapter",
            "remove",
            "--installation-id",
            installed["installation_id"],
        )
        self.assertEqual(code, 0, error)
        removal_token = json.loads(output)["confirmation_token"]
        code, _, error = self.run_cli(
            *install_args,
            "--confirm",
            "--confirmation-token",
            removal_token,
        )
        self.assertEqual(code, 1)
        self.assertIn("does not match the current preview", error)
        self.assertTrue(config.exists())

    def test_adapter_remove_confirmation_rejects_missing_forged_stale_and_install_tokens(self):
        install_args = ("adapter", "install", "--adapter", "cursor", "--scope", "project")
        code, output, error = self.run_cli(*install_args)
        self.assertEqual(code, 0, error)
        install_token = json.loads(output)["confirmation_token"]
        code, output, error = self.run_cli(
            *install_args, "--confirm", "--confirmation-token", install_token,
        )
        self.assertEqual(code, 0, error)
        installed = json.loads(output)
        remove_args = (
            "adapter", "remove", "--installation-id", installed["installation_id"],
        )
        code, output, error = self.run_cli(*remove_args)
        self.assertEqual(code, 0, error)
        remove_preview = json.loads(output)

        for token, expected in (
            (None, "requires its preview confirmation token"),
            (
                self.forge_confirmation_token(remove_preview["confirmation_token"]),
                "token is invalid",
            ),
            (install_token, "does not match the current preview"),
        ):
            confirm_args = [*remove_args, "--confirm"]
            if token is not None:
                confirm_args.extend(("--confirmation-token", token))
            code, _, error = self.run_cli(*confirm_args)
            self.assertEqual(code, 1)
            self.assertIn(expected, error)
            self.assertTrue((self.root / ".cursor" / "hooks.json").exists())

        receipt_path = (
            capture_control_root_path(self.database)
            / "adapter-installs"
            / f"{installed['installation_id']}.json"
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["test_drift"] = True
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        code, _, error = self.run_cli(
            *remove_args,
            "--confirm",
            "--confirmation-token",
            remove_preview["confirmation_token"],
        )
        self.assertEqual(code, 1)
        self.assertIn("does not match the current preview", error)
        self.assertTrue((self.root / ".cursor" / "hooks.json").exists())

    def test_adapter_confirmation_token_survives_separate_cli_processes(self):
        install_args = ("adapter", "install", "--adapter", "cursor", "--scope", "project")
        preview_process = self.run_cli_process(*install_args)
        self.assertEqual(preview_process.returncode, 0, preview_process.stderr)
        install_token = json.loads(preview_process.stdout)["confirmation_token"]
        install_process = self.run_cli_process(
            *install_args, "--confirm", "--confirmation-token", install_token,
        )
        self.assertEqual(install_process.returncode, 0, install_process.stderr)
        installed = json.loads(install_process.stdout)

        remove_args = (
            "adapter", "remove", "--installation-id", installed["installation_id"],
        )
        preview_process = self.run_cli_process(*remove_args)
        self.assertEqual(preview_process.returncode, 0, preview_process.stderr)
        remove_token = json.loads(preview_process.stdout)["confirmation_token"]
        remove_process = self.run_cli_process(
            *remove_args, "--confirm", "--confirmation-token", remove_token,
        )
        self.assertEqual(remove_process.returncode, 0, remove_process.stderr)
        self.assertTrue(json.loads(remove_process.stdout)["removed"])

    def test_deletion_confirmation_token_survives_separate_cli_processes(self):
        arguments = (
            "delete",
            "--scope",
            "project-content",
            "--scope-token",
            "demo",
            "--policy-digest",
            self.policy.digest,
        )
        preview_process = self.run_cli_process(*arguments)
        self.assertEqual(
            preview_process.returncode, 0, preview_process.stderr
        )
        confirmation_token = json.loads(preview_process.stdout)[
            "confirmation_token"
        ]

        delete_process = self.run_cli_process(
            *arguments,
            "--confirm",
            "--confirmation-token",
            confirmation_token,
        )

        self.assertEqual(delete_process.returncode, 0, delete_process.stderr)
        self.assertEqual(json.loads(delete_process.stdout)["operation"], "logical-delete")

    def test_capture_daemon_cli_start_status_stop(self):
        try:
            code, output, error = self.run_cli(
                "daemon",
                "start",
                "--interval",
                "0.1",
                "--batch-size",
                "10",
            )
            self.assertEqual(code, 0, error)
            self.assertEqual(json.loads(output)["state"], "running")
            self.assertNotIn("token_hash", output)
            code, output, error = self.run_cli("daemon", "status")
            self.assertEqual(code, 0, error)
            self.assertIn(json.loads(output)["state"], {"running", "draining"})
            self.assertNotIn(str(self.database), output)
        finally:
            code, output, error = self.run_cli("daemon", "stop", "--timeout", "10")
            self.assertEqual(code, 0, error)
            self.assertEqual(json.loads(output)["state"], "stopped")


if __name__ == "__main__":
    unittest.main()
