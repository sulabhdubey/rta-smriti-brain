"""Run portable smoke checks against the current platform's standalone binary."""

from __future__ import annotations

import json
import os
import queue
import re
import sqlite3
import subprocess
import tempfile
import threading
import time
import tomllib
from pathlib import Path

V11_LIFECYCLE_ACTIONS = {
    "inspect", "plan", "apply", "verify", "repair", "stop", "remove",
}
V11_MCP_HOST_PROFILES = {
    "claude-code", "codex", "cursor", "gemini-cli", "opencode", "zed",
}


def assert_v11_acceptance(evidence: dict) -> None:
    """Validate the bounded, privacy-safe v1.1A acceptance record."""

    lifecycle = evidence.get("lifecycle", {})
    if set(lifecycle.get("actions", ())) != V11_LIFECYCLE_ACTIONS:
        raise AssertionError("v1.1A lifecycle acceptance is incomplete")
    expected_states = {
        "apply_state": "complete",
        "verify_state": "verified",
        "repair_state": "verified",
        "stop_state": "complete",
        "remove_state": "removed",
    }
    if any(lifecycle.get(key) != value for key, value in expected_states.items()):
        raise AssertionError("v1.1A lifecycle states are invalid")
    if set(evidence.get("mcp_profiles", ())) != V11_MCP_HOST_PROFILES:
        raise AssertionError("v1.1A MCP host profile coverage is incomplete")
    retrieval = evidence.get("retrieval", {})
    if (
        set(retrieval.get("stages", ())) != {"index", "timeline", "evidence"}
        or retrieval.get("handle_consistent") is not True
        or retrieval.get("snapshot_consistent") is not True
    ):
        raise AssertionError("v1.1A progressive retrieval acceptance is incomplete")
    review = evidence.get("review", {})
    digest = str(review.get("bundle_digest", ""))
    if (
        review.get("schema") != "rta-smriti.trusted-lifecycle-review/v1"
        or review.get("summary_authority") != "non_authoritative"
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        raise AssertionError("v1.1A review bundle is not sealed")


class McpSession:
    """Small line-oriented MCP client with bounded reads for binary acceptance."""

    def __init__(self, command: list[str], cwd: Path):
        self.process = subprocess.Popen(
            command,
            cwd=cwd,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
        )

    def request(self, payload: dict, timeout: float = 10) -> dict:
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("MCP smoke process pipes are unavailable")
        self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        lines: queue.Queue[str] = queue.Queue(maxsize=1)
        reader = threading.Thread(
            target=lambda: lines.put(self.process.stdout.readline()), daemon=True,
        )
        reader.start()
        try:
            line = lines.get(timeout=timeout)
        except queue.Empty as exc:
            self.close()
            raise TimeoutError("MCP smoke response timed out") from exc
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"MCP smoke process exited without a response: {stderr}")
        response = json.loads(line)
        if "error" in response:
            raise AssertionError(f"MCP smoke request failed: {response['error']}")
        return response

    def close(self) -> None:
        if self.process.poll() is not None:
            return
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


def progressive_retrieval_smoke(command: list[str], cwd: Path) -> dict:
    session = McpSession(command, cwd)
    try:
        session.request({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "clientInfo": {"name": "rta-smriti-acceptance", "version": "1"},
            },
        })
        tools = session.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool_names = {item["name"] for item in tools["result"]["tools"]}
        if "brain_retrieve" not in tool_names:
            raise AssertionError("binary MCP profile omitted progressive retrieval")
        indexed = session.request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {
                "name": "brain_retrieve",
                "arguments": {"stage": "index", "query": "smoke project", "limit": 4},
            },
        })["result"]["structuredContent"]
        handle = indexed["expansion_handle"]
        timeline = session.request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {
                "name": "brain_retrieve",
                "arguments": {"stage": "timeline", "expansion_handle": handle, "max_tokens": 256},
            },
        })["result"]["structuredContent"]
        expanded = session.request({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {
                "name": "brain_retrieve",
                "arguments": {"stage": "evidence", "expansion_handle": handle, "max_tokens": 256},
            },
        })["result"]["structuredContent"]
    finally:
        session.close()
    return {
        "stages": [indexed["stage"], timeline["stage"], expanded["stage"]],
        "handle_consistent": all(
            item["expansion_handle"] == handle for item in (timeline, expanded)
        ),
        "snapshot_consistent": all(
            item["snapshot_digest"] == indexed["snapshot_digest"]
            for item in (timeline, expanded)
        ),
    }


def run(
    executable: Path,
    *arguments: str,
    stdin: str | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(executable), *arguments], input=stdin, text=True, capture_output=True,
        check=False, timeout=30, cwd=cwd,
    )
    if result.returncode:
        rendered = subprocess.list2cmdline([str(executable), *arguments])
        raise RuntimeError(
            f"command failed ({result.returncode}): {rendered}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    expected_version = str(tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])
    executable = (root / "dist" / ("rta-brain.exe" if os.name == "nt" else "rta-brain")).resolve()
    if not executable.is_file():
        raise FileNotFoundError(f"standalone executable is missing: {executable}")
    version = run(executable, "--version").stdout.strip()
    benchmark = json.loads(run(executable, "benchmark", "--json").stdout)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        if os.name != "nt":
            root.chmod(0o700)
        health = json.loads(run(executable, "--json", "doctor", cwd=root).stdout)
        project = root / "project"
        brains = root / "brains"
        project.mkdir()
        source = project / "main.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        bootstrap = json.loads(
            run(
                executable, "--json", "bootstrap-project", str(project),
                "--project", "smoke", "--brain-dir", str(brains),
            ).stdout
        )
        db_path = Path(bootstrap["db_path"])
        indexed_db = sqlite3.connect(db_path)
        try:
            parser_metadata = json.loads(indexed_db.execute(
                "SELECT metadata_json FROM sources WHERE kind = 'file' AND title = 'main.py'"
            ).fetchone()[0])
        finally:
            indexed_db.close()
        request = '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        response = json.loads(
            run(executable, "mcp-server", "--db", str(db_path), "--project", "smoke", stdin=request).stdout
        )
        mcp_probe = json.loads(
            run(executable, "--db", str(db_path), "--json", "mcp-doctor", "--project", "smoke").stdout
        )
        profiles = json.loads(
            run(executable, "mcp-host", "profiles", "--json").stdout
        )
        sessions = root / "sessions"
        sessions.mkdir()
        lifecycle_base = (
            "--db", str(db_path),
            "--project", "smoke",
            "--root", str(project),
            "--brain-dir", str(brains),
            "--sessions-root", str(sessions),
        )

        def lifecycle(action: str, *extra: str) -> dict:
            return json.loads(
                run(executable, "lifecycle", action, *lifecycle_base, *extra, "--json").stdout
            )

        inspected = lifecycle("inspect")
        planned = lifecycle("plan")
        applied = lifecycle(
            "apply",
            "--confirm-plan-digest", planned["plan_digest"],
            "--confirm-observed-state-digest", planned["observed_state_digest"],
        )
        verified = lifecycle("verify")
        review = lifecycle("review")
        repair_plan = lifecycle("plan-repair")
        repaired = lifecycle(
            "repair",
            "--confirm-plan-digest", repair_plan["plan_digest"],
            "--confirm-desired-state-digest", verified["desired_state_digest"],
            "--confirm-observed-state-digest", repair_plan["observed_state_digest"],
        )
        stop_plan = lifecycle("plan-stop")
        stopped_lifecycle = lifecycle(
            "stop",
            "--confirm-plan-digest", stop_plan["plan_digest"],
            "--confirm-observed-state-digest", stop_plan["observed_state_digest"],
        )
        remove_plan = lifecycle("plan-remove")
        removed_lifecycle = lifecycle(
            "remove",
            "--confirm-plan-digest", remove_plan["plan_digest"],
            "--confirm-observed-state-digest", remove_plan["observed_state_digest"],
        )
        retrieval = progressive_retrieval_smoke(
            [
                str(executable), "mcp-server", "--db", str(db_path),
                "--project", "smoke", "--root", str(project),
            ],
            root,
        )
        v11_evidence = {
            "lifecycle": {
                "actions": [
                    "inspect", "plan", "apply", "verify", "repair", "stop", "remove",
                ],
                "apply_state": applied.get("state"),
                "verify_state": verified.get("state"),
                "repair_state": repaired.get("state"),
                "stop_state": stopped_lifecycle.get("state"),
                "remove_state": removed_lifecycle.get("state"),
            },
            "mcp_profiles": sorted(profiles.get("profiles", {})),
            "retrieval": retrieval,
            "review": {
                "schema": review.get("schema"),
                "summary_authority": review.get("summary_authority"),
                "bundle_digest": review.get("bundle_digest"),
            },
        }
        if inspected.get("status") != "ok" or planned.get("status") != "ok":
            raise AssertionError("binary trusted lifecycle preview failed")
        assert_v11_acceptance(v11_evidence)
        adapter_home = root / "adapter-home"
        adapter_home.mkdir()
        capture_policy = json.loads(
            run(
                executable, "capture", "--db", str(db_path), "--json",
                "--project", "smoke", "--root", str(project), "policy", "create",
                "--id", "continuity", "--version", "1", "--profile", "continuity",
            ).stdout
        )
        adapter_plan = json.loads(
            run(
                executable, "capture", "--db", str(db_path), "--json",
                "--project", "smoke", "--root", str(project), "adapter", "plan",
                "--adapter", "claude-code", "--scope", "project",
                "--home", str(adapter_home),
                "--policy-digest", capture_policy["policy_digest"],
            ).stdout
        )
        adapter_install = json.loads(
            run(
                executable, "capture", "--db", str(db_path), "--json",
                "--project", "smoke", "--root", str(project), "adapter", "install",
                "--adapter", "claude-code", "--scope", "project",
                "--home", str(adapter_home),
                "--policy-digest", capture_policy["policy_digest"], "--confirm",
                "--confirmation-token", adapter_plan["confirmation_token"],
            ).stdout
        )
        capture_record = json.dumps({
            "source_cursor": "1", "cursor_kind": "sequence",
            "session_id": "binary-smoke-session",
            "observed_at": "2026-08-23T00:00:01Z",
            "occurred_at": "2026-08-23T00:00:00Z",
            "vendor_event": "PostToolUse",
            "payload": {
                "hook_event_name": "PostToolUse", "tool_name": "Read",
                "tool_status": "success", "duration_ms": 8,
                "tool_response": "synthetic binary smoke response",
            },
        })
        capture_emit = json.loads(
            run(
                executable, "capture", "--db", str(db_path), "--json",
                "--project", "smoke", "--root", str(project), "emit",
                "--source-id", adapter_install["source_id"], stdin=capture_record,
            ).stdout
        )
        capture_service = json.loads(
            run(
                executable, "capture", "--db", str(db_path), "--json",
                "--project", "smoke", "--root", str(project), "daemon", "start",
                "--interval", "0.1", "--batch-size", "10",
            ).stdout
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                capture_replay = json.loads(
                    run(
                        executable, "capture", "--db", str(db_path), "--json",
                        "--project", "smoke", "--root", str(project), "replay",
                        "--limit", "10",
                    ).stdout
                )
                if capture_replay["events"]:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("standalone capture daemon did not normalize the event")
            capture_doctor = json.loads(
                run(
                    executable, "capture", "--db", str(db_path), "--json",
                    "--project", "smoke", "--root", str(project), "doctor",
                ).stdout
            )
        finally:
            capture_stopped = json.loads(
                run(
                    executable, "capture", "--db", str(db_path), "--json",
                    "--project", "smoke", "--root", str(project), "daemon", "stop",
                ).stdout
            )
        passphrase = root / "snapshot.passphrase"
        encrypted = root / "brain.rtae"
        restored = root / "restored.sqlite"
        generated_passphrase = json.loads(
            run(executable, "--json", "snapshot", "passphrase-keygen", str(passphrase)).stdout
        )
        encrypted_result = json.loads(
            run(
                executable, "--db", str(db_path), "--json", "snapshot", "encrypt", str(encrypted),
                "--passphrase", str(passphrase),
            ).stdout
        )
        encrypted_verify = json.loads(
            run(
                executable, "--json", "snapshot", "verify-encrypted", str(encrypted),
                "--passphrase", str(passphrase),
            ).stdout
        )
        encrypted_restore = json.loads(
            run(
                executable, "--json", "snapshot", "restore", str(encrypted),
                "--passphrase", str(passphrase), "--output-db", str(restored),
            ).stdout
        )
        restored_exists = restored.is_file()
        signing_private = root / "snapshot-ed25519-private.pem"
        signing_public = root / "snapshot-ed25519-public.pem"
        signed = root / "brain-signed.rta-snapshot"
        signing_keys = json.loads(run(
            executable, "--json", "snapshot", "keygen", str(signing_private),
            "--public-key", str(signing_public),
        ).stdout)
        signed_result = json.loads(run(
            executable, "--db", str(db_path), "--json", "snapshot", "create", str(signed),
            "--private-key", str(signing_private),
        ).stdout)
        signed_verify = json.loads(run(
            executable, "--json", "snapshot", "verify", str(signed),
            "--public-key", str(signing_public),
        ).stdout)
        watcher = json.loads(
            run(
                executable, "--db", str(db_path), "--json", "watcher", "start", str(project),
                "--project", "smoke", "--interval", "0.2",
            ).stdout
        )
        try:
            source.write_text("VALUE = 2\n", encoding="utf-8")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                freshness = json.loads(
                    run(executable, "--db", str(db_path), "--json", "stale-check", "--project", "smoke").stdout
                )
                if freshness["state"] == "fresh":
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(f"standalone watcher did not refresh the project: {freshness}")
        finally:
            stopped = json.loads(
                run(executable, "--db", str(db_path), "--json", "watcher", "stop", "--project", "smoke").stdout
            )
        managed_port = 0
        managed = json.loads(
            run(
                executable, "console", "start", "--brain-dir", str(brains),
                "--port", str(managed_port), "--no-open", "--json",
            ).stdout
        )
        try:
            managed_status = json.loads(
                run(executable, "console", "status", "--brain-dir", str(brains), "--json").stdout
            )
            managed_open = json.loads(
                run(
                    executable, "console", "open", "--brain-dir", str(brains), "--no-open", "--json",
                ).stdout
            )
        finally:
            managed_stopped = json.loads(
                run(executable, "console", "stop", "--brain-dir", str(brains), "--json").stdout
            )
    if (
        expected_version not in version
        or health.get("status") != "ok"
        or not benchmark.get("corpus", {}).get("synthetic")
        or set(benchmark.get("modes", {})) != {"no_memory", "lexical", "hash_hybrid", "optional_semantic"}
        or benchmark.get("modes", {}).get("optional_semantic", {}).get("status") != "not_requested"
        or response.get("result") != {}
        or parser_metadata.get("parser") != "auto:tree-sitter"
        or not mcp_probe.get("ready")
        or adapter_install.get("status") != "ok"
        or capture_emit.get("status") != "stored"
        or capture_service.get("state") != "running"
        or len(capture_replay.get("events", [])) != 1
        or not capture_doctor.get("journal", {}).get("chain_valid")
        or capture_stopped.get("state") != "stopped"
        or generated_passphrase.get("entropy_bits") != 256
        or encrypted_result.get("encryption") != "AES-256-GCM"
        or not encrypted_verify.get("valid")
        or not encrypted_restore.get("valid")
        or not restored_exists
        or signing_keys.get("signature_algorithm") != "Ed25519"
        or signed_result.get("signature_algorithm") != "Ed25519"
        or not signed_verify.get("valid")
        or watcher.get("state") != "running"
        or stopped.get("state") != "stopped"
        or managed.get("state") != "running"
        or managed_status.get("state") != "running"
        or "url" in managed_status
        or "#token=" not in managed_open.get("url", "")
        or managed_stopped.get("state") != "stopped"
    ):
        raise RuntimeError("standalone binary smoke contract failed")
    print(
        "Standalone binary smoke passed: CLI, SQLite/FTS, MCP dispatch, public benchmark, "
        "bundled Tree-sitter, Universal Capture, encrypted and Ed25519 snapshots, "
        "background sync, and managed console lifecycle."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
