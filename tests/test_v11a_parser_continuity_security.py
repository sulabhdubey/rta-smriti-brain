from __future__ import annotations

import io
import json
import os
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from rta_brain import compaction, continuity, continuity_daemon, mcp_server, parsers, project
from rta_brain.db import connect, init_project


def test_parser_entry_points_are_not_loaded_until_explicitly_enabled(monkeypatch):
    calls = []

    def entry_points(*args, **kwargs):
        calls.append((args, kwargs))
        return []

    monkeypatch.setattr(parsers.importlib.metadata, "entry_points", entry_points)

    parsers.ParserRegistry().capabilities()
    assert calls == []

    parsers.ParserRegistry(load_entry_points=True).capabilities()
    assert len(calls) == 1


def test_parser_child_environment_excludes_unrelated_secrets():
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": r"C:\Windows",
        "TEMP": r"C:\Temp",
        "LANG": "en_US.UTF-8",
        "OPENAI_API_KEY": "private-openai-key",
        "AWS_SECRET_ACCESS_KEY": "private-aws-key",
        "GOOGLE_APPLICATION_CREDENTIALS": "private-google-credentials",
        "CUSTOM_TOKEN": "private-token",
        "RTA_AUTHORITY": "private-rta-authority",
    }

    child = parsers.sanitized_parser_environment(environment)

    assert child["PATH"] == environment["PATH"]
    assert child["SYSTEMROOT"] == environment["SYSTEMROOT"]
    assert child["TEMP"] == environment["TEMP"]
    assert child["LANG"] == environment["LANG"]
    assert "OPENAI_API_KEY" not in child
    assert "AWS_SECRET_ACCESS_KEY" not in child
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in child
    assert "CUSTOM_TOKEN" not in child
    assert "RTA_AUTHORITY" not in child


def test_explicit_parser_adapter_rejects_cumulative_output_over_limit(monkeypatch, tmp_path):
    class Completed:
        returncode = 0

    def run(*_args, stdout=None, **_kwargs):
        assert stdout is not None
        stdout.write(b'{"symbols":["' + b"x" * (parsers.MAX_LSP_TOTAL_RESPONSE_BYTES + 1) + b'"]}')
        return Completed()

    monkeypatch.setattr(parsers.subprocess, "run", run)
    result = parsers.ParserRegistry(
        load_entry_points=False,
        lsp_command="fake-adapter",
    ).parse(tmp_path / "sample.py", "def safe(): pass", parser_name="lsp")

    assert result.parser == "regex"
    assert any("output exceeds" in warning for warning in result.warnings)


def test_native_lsp_reader_stops_after_cumulative_output_limit(monkeypatch):
    payload = {"method": "window/logMessage", "params": {"message": "x" * 1_000_000}}
    remaining = (parsers.MAX_LSP_TOTAL_RESPONSE_BYTES // 1_000_000) + 2

    def read_frame(_stream):
        nonlocal remaining
        if remaining <= 0:
            raise EOFError("done")
        remaining -= 1
        return payload

    monkeypatch.setattr(parsers, "_read_lsp_frame", read_frame)
    client = parsers._LspClient.__new__(parsers._LspClient)
    client.process = type("Process", (), {"stdout": object()})()
    client.messages = queue.Queue()

    client._read()

    received = list(client.messages.queue)
    assert any(
        isinstance(item, ValueError) and "cumulative output" in str(item)
        for item in received
    )


def test_session_binding_fails_closed_when_latest_switch_precedes_tail_window(tmp_path):
    project_root = tmp_path / "project-a"
    foreign_root = tmp_path / "project-b"
    project_root.mkdir()
    foreign_root.mkdir()
    session = tmp_path / "session.jsonl"
    with session.open("wb") as handle:
        handle.write(
            (json.dumps({"type": "session_meta", "payload": {"id": "session-1", "cwd": str(project_root)}}) + "\n").encode()
        )
        handle.write(
            (json.dumps({"type": "turn_context", "payload": {"cwd": str(foreign_root)}}) + "\n").encode()
        )
        filler = (json.dumps({"type": "event_msg", "payload": {"message": "x" * 900_000}}) + "\n").encode()
        for _ in range(20):
            handle.write(filler)
        handle.write(b'{"type":"event_msg","payload":{"message":"foreign tail"}}\n')

    assert session.stat().st_size > continuity_daemon.MAX_SESSION_REBIND_SCAN_BYTES
    assert continuity_daemon._session_binding(session, project_root) is None


def test_session_binding_fails_closed_when_oversized_tail_can_hide_project_switch(tmp_path):
    project_root = tmp_path / "project-a"
    foreign_root = tmp_path / "project-b"
    project_root.mkdir()
    foreign_root.mkdir()
    session = tmp_path / "session.jsonl"
    rows = [
        json.dumps({"type": "session_meta", "payload": {"id": "session-1", "cwd": str(project_root)}}),
        json.dumps({"type": "turn_context", "payload": {"cwd": str(project_root)}}),
        json.dumps({
            "type": "turn_context",
            "payload": {"cwd": str(foreign_root), "padding": "x" * (continuity_daemon.MAX_SESSION_LINE_BYTES + 1)},
        }),
    ]
    session.write_text("\n".join(rows) + "\n", encoding="utf-8")

    assert continuity_daemon._session_binding(session, project_root) is None


def test_deep_session_json_isolated_and_following_metadata_remains_discoverable(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    session = tmp_path / "session.jsonl"
    deep = b'{"payload":' + (b'[' * 1_500) + b'0' + (b']' * 1_500) + b'}\n'
    valid = (json.dumps({"type": "session_meta", "payload": {"id": "safe", "cwd": str(root)}}) + "\n").encode()
    session.write_bytes(deep + valid)

    assert continuity_daemon._session_identity(session) == ("safe", root.resolve())


def test_append_event_rejects_excessive_nesting_without_recursion_error(tmp_path):
    conn = connect(tmp_path / "brain.sqlite")
    try:
        init_project(conn, "demo", str(tmp_path))
        value: object = "leaf"
        for _ in range(continuity.MAX_EVENT_NESTING + 1):
            value = {"child": value}

        with pytest.raises(ValueError, match="nesting"):
            continuity.append_event(conn, "demo", "session", "1", "tool", {"value": value})
    finally:
        conn.close()


def test_ingestion_isolates_over_nested_record_and_waits_for_valid_rebind(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    session = tmp_path / "session.jsonl"
    meta = json.dumps({"type": "session_meta", "payload": {"id": "safe", "cwd": str(root)}})
    deep = '{"type":"response_item","payload":{"role":"user","content":' + ("[" * 80) + '"hidden"' + ("]" * 80) + "}}"
    hidden = json.dumps({"type": "response_item", "payload": {"role": "user", "content": "must not cross"}})
    rebind = json.dumps({"type": "turn_context", "payload": {"cwd": str(root)}})
    visible = json.dumps({"type": "response_item", "payload": {"role": "user", "content": "safe again"}})
    session.write_text("\n".join([meta, deep, hidden, rebind, visible]) + "\n", encoding="utf-8")
    conn = connect(tmp_path / "brain.sqlite")
    try:
        init_project(conn, "demo", str(root))
        result = continuity.ingest_codex_session(
            conn,
            session,
            "demo",
            session_id="safe",
            expected_project_root=root,
        )
        events = continuity.list_events(conn, "demo", session_id="safe", limit=20)["events"]
    finally:
        conn.close()

    assert result["ignored"] >= 2
    serialized = json.dumps(events)
    assert "must not cross" not in serialized
    assert "safe again" in serialized


@pytest.mark.skipif(os.name != "nt", reason="Windows UNC semantics")
def test_mcp_rejects_unc_thread_path_before_any_filesystem_probe(monkeypatch, tmp_path):
    probed = False

    def probe(_path):
        nonlocal probed
        probed = True
        raise AssertionError("filesystem probe must not run")

    monkeypatch.setattr(mcp_server, "_path_is_link_or_reparse", probe)

    with pytest.raises(ValueError, match="network path"):
        mcp_server._confined_thread_path(Path(r"\\server\share\thread.md"), (tmp_path,))
    assert not probed


def test_ollama_compaction_refuses_redirects_before_second_endpoint_is_contacted():
    contacted = threading.Event()

    class DestinationHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            contacted.set()
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

    destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            content_length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(content_length)
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{destination.server_port}/escaped")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    redirector = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    threads = [
        threading.Thread(target=destination.serve_forever, daemon=True),
        threading.Thread(target=redirector.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        with pytest.raises(ValueError, match="redirect"):
            compaction.compact_session_events(
                [{"event": "safe"}],
                model="local-model",
                endpoint=f"http://127.0.0.1:{redirector.server_port}",
            )
        assert not contacted.wait(0.2)
    finally:
        redirector.shutdown()
        destination.shutdown()
        redirector.server_close()
        destination.server_close()


def test_install_local_refuses_project_owned_python_runtime(monkeypatch, tmp_path):
    tool_root = tmp_path / "checkout"
    tool_root.mkdir()
    interpreter = tool_root / ".venv" / ("python.exe" if os.name == "nt" else "python")
    interpreter.parent.mkdir()
    interpreter.write_bytes(b"")
    monkeypatch.setattr(project.sys, "executable", str(interpreter))
    monkeypatch.setattr(project.sys, "frozen", False, raising=False)

    with pytest.raises(ValueError, match="project-owned Python runtime"):
        project.install_local(tmp_path / "bin", tool_root, shell="powershell")


def _mcp_brain(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    database = tmp_path / "brain.sqlite"
    conn = connect(database)
    try:
        init_project(conn, "demo", str(root))
    finally:
        conn.close()
    return database, root, mcp_server.RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        allow_memory_writes=True,
    )


def test_mcp_agent_checkpoint_cannot_satisfy_continuation_readiness(tmp_path):
    database, _root, server = _mcp_brain(tmp_path)
    server.call_tool(
        "brain_checkpoint",
        {
            "objective": "Agent believes the task is ready.",
            "verified_evidence": "Agent-asserted green tests.",
            "remaining_gaps": "",
        },
    )

    conn = connect(database)
    try:
        readiness = continuity.operational_readiness(conn, "demo")
    finally:
        conn.close()

    assert not readiness["manual_continuation_ready"]
    assert "unverified_agent_checkpoint" in readiness["reasons"]
    assert readiness["latest_checkpoint"]["source"] == "agent"


def test_mcp_agent_work_item_cannot_bind_a_local_path_or_replace_operator_state(tmp_path):
    database, root, server = _mcp_brain(tmp_path)
    artifact = root / "artifact.txt"
    artifact.write_text("operator-reviewed", encoding="utf-8")

    with pytest.raises(ValueError, match="local path"):
        server.call_tool(
            "brain_work_item",
            {
                "item_type": "asset",
                "external_id": "agent-path",
                "local_path": str(artifact),
            },
        )

    conn = connect(database)
    try:
        continuity.upsert_work_item(
            conn,
            "demo",
            "asset",
            "operator-accepted",
            local_path="artifact.txt",
            qa_state="passed",
            decision="accepted",
            metadata={"authority": "operator"},
        )
    finally:
        conn.close()

    with pytest.raises(PermissionError, match="operator work item"):
        server.call_tool(
            "brain_work_item",
            {
                "item_type": "asset",
                "external_id": "operator-accepted",
                "qa_state": "unknown",
                "decision": "pending",
            },
        )

    conn = connect(database)
    try:
        row = conn.execute(
            "SELECT local_path, qa_state, decision FROM work_items WHERE external_id = ?",
            ("operator-accepted",),
        ).fetchone()
    finally:
        conn.close()
    assert dict(row) == {
        "local_path": "artifact.txt",
        "qa_state": "passed",
        "decision": "accepted",
    }


def test_mcp_agent_work_item_is_stored_as_unverified_observation(tmp_path):
    database, _root, server = _mcp_brain(tmp_path)
    server.call_tool(
        "brain_work_item",
        {
            "item_type": "blocker",
            "external_id": "agent-observation",
            "qa_state": "blocked",
            "decision": "blocked",
            "metadata": {
                "_rta_authority": "operator",
                "_rta_verification_status": "verified",
            },
        },
    )

    conn = connect(database)
    try:
        row = conn.execute(
            "SELECT metadata_json FROM work_items WHERE external_id = ?",
            ("agent-observation",),
        ).fetchone()
    finally:
        conn.close()
    metadata = json.loads(row["metadata_json"])
    assert metadata["_rta_authority"] == "mcp-agent"
    assert metadata["_rta_verification_status"] == "unverified"
