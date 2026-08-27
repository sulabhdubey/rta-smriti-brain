import argparse
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode


def run(
    command: list[str], cwd: Path, *, stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, cwd=cwd, input=stdin, text=True, capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {command}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request_json(url: str, token: str | None = None) -> dict:
    headers = {"Origin": url.split("/api/", 1)[0]}
    if token:
        headers["X-Rta-Smriti-Token"] = token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def wait_for_url(process: subprocess.Popen[str], timeout: float = 15) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            raise RuntimeError(f"dashboard exited before startup: {stderr}")
        line = process.stdout.readline().strip() if process.stdout else ""
        if line.startswith("Rta-Smriti Operator Console: "):
            return line.split(": ", 1)[1]
    raise TimeoutError("dashboard did not emit its capability URL")


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test an installed Rta-Smriti distribution")
    parser.add_argument("--cli", required=True, type=Path)
    args = parser.parse_args()
    cli = args.cli.resolve()
    if not cli.is_file():
        raise FileNotFoundError(f"installed CLI not found: {cli}")

    with tempfile.TemporaryDirectory(prefix="rta-smriti-installed-") as tmp:
        root = Path(tmp)
        project = root / "sample-project"
        brains = root / "brains"
        project.mkdir()
        (project / "app.py").write_text("def hello():\n    return 'world'\n", encoding="utf-8")

        bootstrap = json.loads(
            run(
                [
                    str(cli), "--json", "bootstrap-project", str(project),
                    "--project", "sample", "--brain-dir", str(brains), "--write-agents",
                ],
                root,
            ).stdout
        )
        db = Path(bootstrap["db_path"])
        if not db.is_file() or bootstrap["ingest"]["indexed_files"] < 1:
            raise AssertionError("bootstrap did not create an indexed project brain")
        if bootstrap["settings"]["embedding_provider"] != "hash":
            raise AssertionError("bootstrap did not enable dependency-free hybrid retrieval")

        agent_text = Path(bootstrap["agent_file"]).read_text(encoding="utf-8")
        if "rta_brain.cli" not in agent_text or "rta_brain.mcp_server" not in agent_text:
            raise AssertionError("installed agent bridge does not use packaged module entrypoints")

        shell_kind = bootstrap["shell"]
        if shell_kind == "powershell":
            shell = shutil.which("pwsh") or shutil.which("powershell")
            shell_args = ["-NoProfile", "-NonInteractive", "-Command"]
        else:
            shell = shutil.which("sh") or "/bin/sh"
            shell_args = ["-c"]
        if not shell:
            raise FileNotFoundError(f"required {shell_kind} command shell was not found")
        bridge_command = bootstrap["next_commands"]["context_pack"].replace("<task>", "installed bridge smoke")
        bridge_pack = run([shell, *shell_args, bridge_command], project).stdout
        if "# Rta-Smriti Context Pack" not in bridge_pack:
            raise AssertionError("generated installed-package shell command did not execute")

        health = json.loads(
            run(
                [str(cli), "--db", str(db), "--json", "self-check", "--project", "sample", "--check-files"],
                project,
            ).stdout
        )
        if not health["ready"] or health["freshness"]["state"] != "fresh":
            raise AssertionError(f"installed project brain is not ready: {health}")

        pack = run(
            [str(cli), "--db", str(db), "context-pack", "explain the sample", "--project", "sample"],
            project,
        ).stdout
        if "# Rta-Smriti Context Pack" not in pack or "Project: sample" not in pack:
            raise AssertionError("installed CLI did not generate a context pack")

        checkpoint = json.loads(
            run(
                [
                    str(cli), "--db", str(db), "--json", "checkpoint", "--project", "sample",
                    "--objective", "Continue the installed-package smoke",
                    "--verified-evidence", "Wheel bootstrap and context pack passed",
                    "--remaining-gaps", "Dashboard continuation endpoint",
                    "--next-action", "Probe the authenticated endpoint",
                    "--prohibited-repetition", "Do not repeat repository discovery",
                ],
                project,
            ).stdout
        )
        if checkpoint["checkpoint"]["next_action"] != "Probe the authenticated endpoint":
            raise AssertionError("installed CLI did not persist a structured checkpoint")

        continuation = run(
            [str(cli), "--db", str(db), "continue-prompt", "--project", "sample"],
            project,
        ).stdout
        if "Canonical repository root" not in continuation or "Do not repeat repository discovery" not in continuation:
            raise AssertionError("installed CLI did not generate a grounded continuation prompt")

        freshness = json.loads(
            run(
                [str(cli), "--db", str(db), "--json", "stale-check", "--project", "sample", "--deep"],
                project,
            ).stdout
        )
        if freshness["state"] != "fresh" or freshness["details"] or not freshness["fresh_details_omitted"]:
            raise AssertionError(f"deep freshness output was not compact and fresh: {freshness}")

        mcp = json.loads(
            run(
                [str(cli), "--db", str(db), "--json", "mcp-config", "--project", "sample"],
                project,
            ).stdout
        )["config"]["mcpServers"]["rta-smriti"]
        if not Path(mcp["command"]).is_file() or mcp["args"][:3] != ["-I", "-m", "rta_brain.mcp_server"]:
            raise AssertionError(f"installed MCP command is invalid: {mcp}")
        mcp_probe = json.loads(
            run(
                [str(cli), "--db", str(db), "--json", "mcp-doctor", "--project", "sample"],
                project,
            ).stdout
        )
        if not mcp_probe["ready"] or mcp_probe["tool_count"] < 1 or not mcp_probe["fresh_task_required"]:
            raise AssertionError(f"installed MCP probe failed: {mcp_probe}")

        adapter_home = root / "adapter-home"
        adapter_home.mkdir()
        capture_policy = json.loads(run([
            str(cli), "capture", "--db", str(db), "--json", "--project", "sample",
            "--root", str(project), "policy", "create", "--id", "continuity",
            "--version", "1", "--profile", "continuity",
        ], root).stdout)
        adapter_plan = json.loads(run([
            str(cli), "capture", "--db", str(db), "--json", "--project", "sample",
            "--root", str(project), "adapter", "plan", "--adapter", "claude-code",
            "--scope", "project", "--home", str(adapter_home),
            "--policy-digest", capture_policy["policy_digest"],
        ], root).stdout)
        adapter_install = json.loads(run([
            str(cli), "capture", "--db", str(db), "--json", "--project", "sample",
            "--root", str(project), "adapter", "install", "--adapter", "claude-code",
            "--scope", "project", "--home", str(adapter_home),
            "--policy-digest", capture_policy["policy_digest"], "--confirm",
            "--confirmation-token", adapter_plan["confirmation_token"],
        ], root).stdout)
        capture_record = json.dumps({
            "source_cursor": "1", "cursor_kind": "sequence",
            "session_id": "installed-smoke-session",
            "observed_at": "2026-08-23T00:00:01Z",
            "occurred_at": "2026-08-23T00:00:00Z",
            "vendor_event": "PostToolUse",
            "payload": {
                "hook_event_name": "PostToolUse", "tool_name": "Read",
                "tool_status": "success", "duration_ms": 8,
                "tool_response": "synthetic installed smoke response",
            },
        })
        capture_emit = json.loads(run([
            str(cli), "capture", "--db", str(db), "--json", "--project", "sample",
            "--root", str(project), "emit", "--source-id", adapter_install["source_id"],
        ], root, stdin=capture_record).stdout)
        capture_service = json.loads(run([
            str(cli), "capture", "--db", str(db), "--json", "--project", "sample",
            "--root", str(project), "daemon", "start", "--interval", "0.1",
            "--batch-size", "10",
        ], root).stdout)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                capture_replay = json.loads(run([
                    str(cli), "capture", "--db", str(db), "--json",
                    "--project", "sample", "--root", str(project), "replay",
                    "--limit", "10",
                ], root).stdout)
                if capture_replay["events"]:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("installed capture daemon did not normalize the event")
            capture_doctor = json.loads(run([
                str(cli), "capture", "--db", str(db), "--json", "--project", "sample",
                "--root", str(project), "doctor",
            ], root).stdout)
        finally:
            capture_stopped = json.loads(run([
                str(cli), "capture", "--db", str(db), "--json", "--project", "sample",
                "--root", str(project), "daemon", "stop",
            ], root).stdout)
        if any((
            adapter_install["status"] != "ok",
            capture_emit["status"] != "stored",
            capture_service["state"] != "running",
            len(capture_replay["events"]) != 1,
            not capture_doctor["journal"]["chain_valid"],
            capture_stopped["state"] != "stopped",
        )):
            raise AssertionError("installed Universal Capture lifecycle failed")

        sessions = root / "sessions"
        sessions.mkdir()
        transcript = sessions / "sample-session.jsonl"
        transcript.write_text(
            json.dumps({"type": "session_meta", "payload": {"id": "sample-session", "cwd": str(project)}})
            + "\n"
            + json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user", "content": "Continue installed continuity smoke"}})
            + "\n",
            encoding="utf-8",
        )
        continuity = json.loads(
            run(
                [
                    str(cli), "--db", str(db), "--json", "continuity", "start", "--project", "sample",
                    "--root", str(project), "--sessions-root", str(sessions), "--interval", "0.2",
                    "--inactivity", "900", "--lookback-days", "0",
                ],
                root,
            ).stdout
        )
        if continuity["state"] != "running":
            raise AssertionError(f"installed continuity capture did not start: {continuity}")
        try:
            time.sleep(0.6)
            continuity_status = json.loads(
                run(
                    [str(cli), "--db", str(db), "--json", "continuity", "status", "--project", "sample"],
                    root,
                ).stdout
            )
            if continuity_status["state"] != "running":
                raise AssertionError(f"installed continuity diagnostics are not running: {continuity_status}")
        finally:
            continuity_stopped = json.loads(
                run(
                    [str(cli), "--db", str(db), "--json", "continuity", "stop", "--project", "sample"],
                    root,
                ).stdout
            )
        if continuity_stopped["state"] != "stopped":
            raise AssertionError(f"installed continuity capture did not stop: {continuity_stopped}")

        watcher = json.loads(
            run(
                [
                    str(cli), "--db", str(db), "--json", "watcher", "start", str(project),
                    "--project", "sample", "--interval", "0.2",
                ],
                root,
            ).stdout
        )
        if watcher["state"] != "running" or watcher["backend"] not in {"watchdog", "polling"}:
            raise AssertionError(f"installed background watcher did not start: {watcher}")
        try:
            (project / "app.py").write_text("def hello():\n    return 'updated-world'\n", encoding="utf-8")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                refreshed = json.loads(
                    run(
                        [str(cli), "--db", str(db), "--json", "stale-check", "--project", "sample"],
                        root,
                    ).stdout
                )
                if refreshed["state"] == "fresh":
                    break
                time.sleep(0.1)
            else:
                raise AssertionError(f"installed background watcher did not refresh the project: {refreshed}")
        finally:
            stopped = json.loads(
                run(
                    [str(cli), "--db", str(db), "--json", "watcher", "stop", "--project", "sample"],
                    root,
                ).stdout
            )
        if stopped["state"] != "stopped":
            raise AssertionError(f"installed background watcher did not stop: {stopped}")

        wrapper_dir = root / "bin"
        install = json.loads(
            run([str(cli), "--json", "install-local", "--target", str(wrapper_dir)], root).stdout
        )
        wrapper = Path(install["wrappers"][0])
        wrapper_health = json.loads(
            run([str(wrapper), "--db", str(root / "wrapper.sqlite"), "--json", "doctor"], project).stdout
        )
        if wrapper_health["status"] != "ok":
            raise AssertionError("installed wrapper did not work outside its install directory")

        benchmark_history = root / "benchmark-history.jsonl"
        benchmark_report = root / "benchmark-report.md"
        run([
            str(cli), "benchmark", "--json", "--history", str(benchmark_history),
            "--label", "installed-before",
        ], root)
        benchmark = json.loads(run([
            str(cli), "benchmark", "--json", "--history", str(benchmark_history),
            "--report", str(benchmark_report), "--label", "installed-after",
        ], root).stdout)
        if not benchmark["corpus"]["synthetic"] or benchmark["corpus"]["queries"] < 1:
            raise AssertionError("installed package did not expose the synthetic public benchmark")
        if set(benchmark["modes"]) != {"no_memory", "lexical", "hash_hybrid", "optional_semantic"}:
            raise AssertionError(f"installed benchmark modes are incomplete: {benchmark['modes']}")
        if benchmark["modes"]["optional_semantic"]["status"] != "not_requested":
            raise AssertionError("installed benchmark did not keep optional semantic retrieval opt-in")
        if benchmark["history"]["run_count"] != 2 or "Historical Comparison" not in benchmark_report.read_text(encoding="utf-8"):
            raise AssertionError("installed benchmark history or report was not created")

        passphrase = root / "snapshot.passphrase"
        encrypted = root / "brain.rtae"
        restored = root / "restored.sqlite"
        generated_passphrase = json.loads(
            run([str(cli), "--json", "snapshot", "passphrase-keygen", str(passphrase)], root).stdout
        )
        if generated_passphrase["entropy_bits"] != 256 or not passphrase.is_file():
            raise AssertionError("installed encrypted snapshot key generation failed")
        encrypted_result = json.loads(
            run([
                str(cli), "--db", str(db), "--json", "snapshot", "encrypt", str(encrypted),
                "--passphrase", str(passphrase),
            ], root).stdout
        )
        if encrypted_result["encryption"] != "AES-256-GCM":
            raise AssertionError(f"installed encrypted snapshot creation failed: {encrypted_result}")
        encrypted_verify = json.loads(
            run([
                str(cli), "--json", "snapshot", "verify-encrypted", str(encrypted),
                "--passphrase", str(passphrase),
            ], root).stdout
        )
        if not encrypted_verify["valid"]:
            raise AssertionError(f"installed encrypted snapshot verification failed: {encrypted_verify}")
        encrypted_restore = json.loads(
            run([
                str(cli), "--json", "snapshot", "restore", str(encrypted),
                "--passphrase", str(passphrase), "--output-db", str(restored),
            ], root).stdout
        )
        if not encrypted_restore["valid"] or not restored.is_file():
            raise AssertionError(f"installed encrypted snapshot restore failed: {encrypted_restore}")

        private_key = root / "snapshot-private.pem"
        public_key = root / "snapshot-public.pem"
        signed = root / "brain-signed.rta"
        json.loads(run([
            str(cli), "--json", "snapshot", "keygen", str(private_key), "--public-key", str(public_key),
        ], root).stdout)
        signed_result = json.loads(run([
            str(cli), "--db", str(db), "--json", "snapshot", "create", str(signed),
            "--private-key", str(private_key),
        ], root).stdout)
        signed_verify = json.loads(run([
            str(cli), "--json", "snapshot", "verify", str(signed), "--public-key", str(public_key),
        ], root).stdout)
        if signed_result["signature_algorithm"] != "Ed25519" or not signed_verify["valid"]:
            raise AssertionError("installed Ed25519 snapshot round trip failed")

        managed_port = free_port()
        managed = json.loads(
            run(
                [
                    str(cli), "console", "start", "--brain-dir", str(brains),
                    "--port", str(managed_port), "--no-open", "--json",
                ],
                root,
            ).stdout
        )
        if managed["state"] != "running" or managed["port"] != managed_port:
            raise AssertionError(f"installed managed console did not start: {managed}")
        try:
            managed_status = json.loads(
                run([str(cli), "console", "status", "--brain-dir", str(brains), "--json"], root).stdout
            )
            if managed_status["state"] != "running" or "url" in managed_status:
                raise AssertionError(f"managed console status is invalid or leaked capability data: {managed_status}")
            managed_open = json.loads(
                run(
                    [str(cli), "console", "open", "--brain-dir", str(brains), "--no-open", "--json"],
                    root,
                ).stdout
            )
            if managed_open["port"] != managed_port or "#token=" not in managed_open["url"]:
                raise AssertionError(f"managed console could not recover its authorized URL: {managed_open}")
        finally:
            managed_stopped = json.loads(
                run([str(cli), "console", "stop", "--brain-dir", str(brains), "--json"], root).stdout
            )
        if managed_stopped["state"] != "stopped":
            raise AssertionError(f"installed managed console did not stop: {managed_stopped}")

        port = free_port()
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        dashboard = subprocess.Popen(
            [str(cli), "dashboard", "--brain-dir", str(brains), "--host", "127.0.0.1", "--port", str(port), "--no-open"],
            cwd=project,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        try:
            url = wait_for_url(dashboard)
            token = url.split("#token=", 1)[1]
            base_url = url.split("#", 1)[0].rstrip("/")
            with urllib.request.urlopen(base_url + "/", timeout=10) as response:
                if response.status != 200 or len(response.read()) < 100:
                    raise AssertionError("installed dashboard assets did not load")
            dashboard_health = request_json(base_url + "/api/health", token)
            if dashboard_health["status"] != "ok" or len(dashboard_health["projects"]) != 1:
                raise AssertionError(f"installed dashboard health failed: {dashboard_health}")
            if "rta_brain.cli" not in dashboard_health["cli_command"]:
                raise AssertionError("installed dashboard did not expose a working CLI command bridge")
            if dashboard_health["shell"] != shell_kind:
                raise AssertionError("installed dashboard reported the wrong command shell")
            query = urlencode({"db_path": str(db), "project": "sample"})
            dashboard_prompt = request_json(base_url + "/api/continuation-prompt?" + query, token)
            rendered_prompt = dashboard_prompt["prompt"]
            if (
                "Canonical repository root" not in rendered_prompt
                or not any(value in rendered_prompt for value in (
                    "Probe the authenticated endpoint", "Continue installed continuity smoke",
                ))
            ):
                raise AssertionError(
                    f"installed dashboard did not expose grounded continuation state: {dashboard_prompt}"
                )
            try:
                request_json(base_url + "/api/health")
            except urllib.error.HTTPError as exc:
                if exc.code != 403:
                    raise
            else:
                raise AssertionError("dashboard API accepted an unauthenticated request")
        finally:
            dashboard.terminate()
            try:
                dashboard.wait(timeout=5)
            except subprocess.TimeoutExpired:
                dashboard.kill()
                dashboard.wait(timeout=5)

        print(json.dumps({"status": "ok", "checks": 28}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
