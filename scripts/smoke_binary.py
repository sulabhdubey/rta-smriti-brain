"""Run portable smoke checks against the current platform's standalone binary."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import tempfile
import tomllib
import time
from pathlib import Path


def run(executable: Path, *arguments: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(executable), *arguments], input=stdin, text=True, capture_output=True, check=True, timeout=30
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    expected_version = str(tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"])
    executable = (root / "dist" / ("rta-brain.exe" if os.name == "nt" else "rta-brain")).resolve()
    if not executable.is_file():
        raise FileNotFoundError(f"standalone executable is missing: {executable}")
    version = run(executable, "--version").stdout.strip()
    health = json.loads(run(executable, "--json", "doctor").stdout)
    benchmark = json.loads(run(executable, "benchmark", "--json").stdout)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
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
