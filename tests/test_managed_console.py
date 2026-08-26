import json
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

from rta_brain.console_daemon import (
    _worker_command,
    console_paths,
    console_status,
    open_console,
    restart_console,
    start_console,
    stop_console,
)
from rta_brain.db import connect, ingest_repo, init_project, remember
from rta_brain.capture import append_event, register_policy, register_source
from rta_brain.capture_types import CapturePolicy, CaptureSource, NormalizedEvent
from rta_brain.runtime_control import (
    SpawnedWorker,
    detach_current_worker_session,
    detached_process_kwargs,
    detached_worker_bootstrap,
    process_alive,
    read_json,
    spawn_detached_worker,
    terminate_worker,
    write_json,
)

ROOT = Path(__file__).resolve().parents[1]


class RuntimeControlTests(unittest.TestCase):
    def test_startup_timeout_terminates_kills_and_reaps_a_stuck_worker(self):
        process = MagicMock()
        process.wait.side_effect = [
            subprocess.TimeoutExpired(["worker"], 0.1),
            subprocess.TimeoutExpired(["worker"], 0.1),
            1,
        ]

        terminate_worker(process, timeout=0.1)

        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 3)

    def test_startup_timeout_reaps_a_worker_that_exits_before_termination(self):
        process = MagicMock()
        process.wait.side_effect = [
            subprocess.TimeoutExpired(["worker"], 0.1),
            0,
        ]
        process.terminate.side_effect = ProcessLookupError()

        terminate_worker(process, timeout=0.1)

        process.terminate.assert_called_once_with()
        process.kill.assert_not_called()
        self.assertEqual(process.wait.call_count, 2)

    def test_source_console_worker_uses_the_minimal_entry_point(self):
        command = _worker_command(
            ROOT,
            Path("brains"),
            None,
            None,
            "127.0.0.1",
            0,
            {
                "state": Path("state.json"),
                "stop": Path("stop.request"),
                "lock": Path("launch.lock"),
                "token": Path("capability.secret"),
            },
        )
        self.assertTrue(any("rta_brain.console_worker" in part for part in command))
        self.assertNotIn("rta_brain.cli", command)

    def test_json_state_write_is_atomic_and_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "control" / "state.json"
            write_json(state, {"state": "running", "pid": os.getpid()})
            self.assertEqual(read_json(state)["state"], "running")
            self.assertEqual(list(state.parent.glob(".*.tmp")), [])

    def test_json_state_rejects_a_hard_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victim.json"
            victim.write_text('{"keep": true}\n', encoding="utf-8")
            state = Path(tmp) / "state.json"
            os.link(victim, state)
            with self.assertRaisesRegex(ValueError, "linked runtime state"):
                write_json(state, {"state": "running"})
            self.assertEqual(json.loads(victim.read_text(encoding="utf-8")), {"keep": True})

    def test_process_liveness_probe_is_non_destructive(self):
        self.assertTrue(process_alive(os.getpid()))
        self.assertFalse(process_alive(-1))

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux zombie semantics")
    def test_process_liveness_treats_a_zombie_as_stopped(self):
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        try:
            deadline = time.monotonic() + 5.0
            state = ""
            while time.monotonic() < deadline:
                stat_line = (Path("/proc") / str(child.pid) / "stat").read_text(
                    encoding="ascii"
                )
                state = stat_line[stat_line.rfind(")") + 2 :].split()[0]
                if state == "Z":
                    break
                time.sleep(0.01)
            self.assertEqual(state, "Z")
            self.assertFalse(process_alive(child.pid))
        finally:
            child.wait(timeout=5)

    def test_detached_spawn_options_are_platform_specific(self):
        options = detached_process_kwargs()
        if os.name == "nt":
            flags = options["creationflags"]
            self.assertTrue(flags & getattr(subprocess, "DETACHED_PROCESS", 0x00000008))
            self.assertTrue(flags & getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200))
            self.assertTrue(flags & getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
            self.assertNotIn("start_new_session", options)
        elif sys.platform == "darwin":
            self.assertEqual(options, {})
        else:
            self.assertTrue(options["start_new_session"])
            self.assertNotIn("creationflags", options)

    def test_macos_launch_detaches_in_fresh_worker_and_uses_posix_spawn_options(self):
        with patch("rta_brain.runtime_control.sys.platform", "darwin"):
            bootstrap = detached_worker_bootstrap("rta_brain.worker", Path("trusted-root"))
            self.assertIn("os.setsid()", bootstrap)
            self.assertIn("runpy.run_module('rta_brain.worker'", bootstrap)

    def test_macos_worker_session_detach_is_idempotent(self):
        with (
            patch("rta_brain.runtime_control.sys.platform", "darwin"),
            patch("rta_brain.runtime_control.os.getpid", return_value=41),
            patch("rta_brain.runtime_control.os.getsid", side_effect=(9, 41), create=True),
            patch("rta_brain.runtime_control.os.setsid", create=True) as setsid,
        ):
            detach_current_worker_session()
            detach_current_worker_session()
        setsid.assert_called_once_with()

    def test_macos_worker_uses_posix_spawn_with_explicit_stdio_actions(self):
        log_stream = MagicMock()
        log_stream.fileno.return_value = 72
        with (
            patch("rta_brain.runtime_control.sys.platform", "darwin"),
            patch("rta_brain.runtime_control.os.open", return_value=71),
            patch("rta_brain.runtime_control.os.close") as close,
            patch("rta_brain.runtime_control.os.posix_spawn", return_value=1234, create=True) as spawn,
            patch("rta_brain.runtime_control.os.POSIX_SPAWN_DUP2", 2, create=True),
            patch("rta_brain.runtime_control.os.POSIX_SPAWN_CLOSE", 1, create=True),
        ):
            process = spawn_detached_worker(
                ["/trusted/python", "-I", "-c", "pass"],
                log_stream,
                {"SAFE": "1"},
                Path("ignored-on-darwin"),
            )
        self.assertEqual(process.pid, 1234)
        spawn.assert_called_once_with(
            "/trusted/python",
            ["/trusted/python", "-I", "-c", "pass"],
            {"SAFE": "1"},
            file_actions=[(2, 71, 0), (2, 72, 1), (2, 72, 2), (1, 71), (1, 72)],
        )
        close.assert_called_once_with(71)

    def test_frozen_worker_uses_an_independent_pyinstaller_environment(self):
        log_stream = MagicMock()
        with (
            patch("rta_brain.runtime_control.sys.platform", "win32"),
            patch("rta_brain.runtime_control.sys.frozen", True, create=True),
            patch(
                "rta_brain.runtime_control.sys.executable",
                str(Path("release") / "rta-brain.exe"),
            ),
            patch("rta_brain.runtime_control.subprocess.Popen") as popen,
        ):
            spawn_detached_worker(
                ["rta-brain.exe", "_capture-worker"],
                log_stream,
                {"SAFE": "1"},
                Path("worker-root"),
            )

        child_env = popen.call_args.kwargs["env"]
        self.assertEqual(child_env["SAFE"], "1")
        self.assertEqual(child_env["PYINSTALLER_RESET_ENVIRONMENT"], "1")
        self.assertEqual(
            popen.call_args.kwargs["cwd"],
            (Path.cwd() / "release").resolve(),
        )

    def test_spawned_worker_reports_exit_and_forwards_signals(self):
        process = SpawnedWorker(1234)
        with (
            patch("rta_brain.runtime_control.os.WNOHANG", 1, create=True),
            patch("rta_brain.runtime_control.os.waitpid", return_value=(1234, 256)),
            patch("rta_brain.runtime_control.os.waitstatus_to_exitcode", return_value=1),
        ):
            self.assertEqual(process.poll(), 1)
            self.assertEqual(process.wait(timeout=0.1), 1)
        with patch("rta_brain.runtime_control.os.kill") as kill:
            with (
                patch("rta_brain.runtime_control.signal.SIGTERM", 15, create=True),
                patch("rta_brain.runtime_control.signal.SIGKILL", 9, create=True),
            ):
                process.terminate()
                process.kill()
        self.assertEqual(kill.call_count, 2)


class ManagedConsoleTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.brain_dir = Path(self.tempdir.name) / "brains"
        self.brain_dir.mkdir()

    def tearDown(self):
        try:
            stop_console(self.brain_dir, timeout=5.0)
        except Exception:
            pass
        self.tempdir.cleanup()

    def test_stopped_status_contains_no_capability_material(self):
        status = console_status(self.brain_dir)
        self.assertEqual(status["state"], "stopped")
        self.assertNotIn("token", json.dumps(status).lower())
        self.assertNotIn("#token=", json.dumps(status))

    def test_stop_waits_for_the_identified_worker_after_stopped_is_persisted(self):
        paths = console_paths(self.brain_dir)
        write_json(
            paths["state"],
            {
                "state": "stopped",
                "pid": 4242,
                "process_identity": "worker-birth-identity",
            },
        )
        with (
            patch(
                "rta_brain.console_daemon.process_alive",
                side_effect=(True, False),
            ) as alive,
            patch(
                "rta_brain.console_daemon.process_identity",
                return_value="worker-birth-identity",
            ) as identity,
        ):
            stopped = stop_console(self.brain_dir, timeout=1.0)

        self.assertEqual(stopped["state"], "stopped")
        self.assertEqual(alive.call_count, 2)
        identity.assert_called_once_with(4242)

    def test_stop_terminates_only_the_recorded_worker_after_grace_timeout(self):
        from rta_brain import console_daemon

        paths = console_paths(self.brain_dir)
        state = {
            "state": "running",
            "pid": 4242,
            "process_identity": "worker-birth-identity",
        }
        process = MagicMock(pid=4242)
        key = str(paths["state"])
        console_daemon._SPAWNED_PROCESSES[key] = process
        try:
            with (
                patch.object(console_daemon, "console_status", return_value=state),
                patch.object(console_daemon, "prepare_control_dir"),
                patch.object(console_daemon, "write_stop_request"),
                patch.object(console_daemon, "_worker_process_matches", return_value=True),
                patch.object(console_daemon, "terminate_worker") as terminate,
            ):
                stopped = stop_console(self.brain_dir, timeout=0.1)

            terminate.assert_called_once_with(process, timeout=1.0)
            self.assertEqual(stopped["state"], "stopped")
            self.assertNotIn(key, console_daemon._SPAWNED_PROCESSES)
        finally:
            console_daemon._SPAWNED_PROCESSES.pop(key, None)

    def test_temporal_truth_operator_api_supports_overview_history_and_mutation(self):
        root = Path(self.tempdir.name) / "repo"
        root.mkdir()
        database = self.brain_dir / "demo.sqlite"
        conn = connect(database)
        try:
            init_project(conn, "demo", str(root))
        finally:
            conn.close()
        started = start_console(
            ROOT, self.brain_dir, port=0, open_browser=False, startup_timeout=10.0
        )
        token = started["url"].split("#token=", 1)[1]
        base_url = f"http://127.0.0.1:{started['port']}"
        headers = {"X-Rta-Smriti-Token": token, "Content-Type": "application/json"}

        def post(payload):
            request = urllib.request.Request(
                base_url + "/api/truth",
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))

        def get(mode, **params):
            query = urllib.parse.urlencode({
                "db_path": str(database), "project": "demo", "mode": mode,
                **params,
            })
            request = urllib.request.Request(
                base_url + "/api/truth?" + query,
                headers={"X-Rta-Smriti-Token": token},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))

        asserted = post({
            "db_path": str(database), "project": "demo", "action": "assert",
            "claim_id": "release-status", "subject": "release:v0.7",
            "predicate": "status", "value": "candidate",
            "state": "accepted", "idempotency_key": "dashboard:assert:1",
            "expected_version": 0,
        })
        self.assertEqual(asserted["claim"]["epistemic_state"], "accepted")
        overview = get("overview")
        self.assertEqual(overview["counts"]["current_claims"], 1)
        self.assertEqual(overview["claims"][0]["claim_id"], "release-status")
        post({
            "db_path": str(database), "project": "demo", "action": "state",
            "claim_id": "release-status", "state": "stale",
            "reason": "Revalidation is due.",
            "idempotency_key": "dashboard:state:2", "expected_version": 1,
        })
        history = get("history", claim_id="release-status")
        self.assertEqual(
            [item["epistemic_state"] for item in history["versions"]],
            ["accepted", "stale"],
        )
        sensitive = post({
            "db_path": str(database), "project": "demo", "action": "assert",
            "claim_id": "private-token", "subject": "credential:service",
            "predicate": "token", "value": "must-not-enter-browser-dom",
            "privacy_class": "sensitive", "idempotency_key": "dashboard:private:1",
            "expected_version": 0,
        })
        self.assertTrue(sensitive["claim"]["redacted"])
        self.assertNotIn("must-not-enter-browser-dom", json.dumps(sensitive))
        for result in (
            get("overview"),
            get("current", claim_id="private-token"),
            get("history", claim_id="private-token"),
            get("explain", claim_id="private-token"),
        ):
            serialized = json.dumps(result)
            self.assertNotIn("must-not-enter-browser-dom", serialized)
            self.assertNotIn("credential:service", serialized)

    def test_linked_console_log_is_rejected_without_modifying_victim(self):
        paths = console_paths(self.brain_dir)
        paths["directory"].mkdir()
        victim = Path(self.tempdir.name) / "victim.log"
        victim.write_text("keep\n", encoding="utf-8")
        os.link(victim, paths["log"])
        with self.assertRaisesRegex(ValueError, "linked console log"):
            start_console(ROOT, self.brain_dir, port=0, open_browser=False)
        self.assertEqual(victim.read_text(encoding="utf-8"), "keep\n")

    def test_start_open_status_restart_and_stop_lifecycle(self):
        started = start_console(
            ROOT,
            self.brain_dir,
            port=0,
            open_browser=False,
            startup_timeout=10.0,
        )
        self.assertEqual(started["state"], "running")
        self.assertEqual(started["startup_stage"], "running")
        self.assertTrue(process_alive(started["pid"]))
        self.assertRegex(started["url"], r"^http://127\.0\.0\.1:\d+/#token=")

        status = console_status(self.brain_dir)
        self.assertEqual(status["state"], "running")
        self.assertEqual(status["port"], started["port"])
        self.assertNotIn("token", json.dumps(status).lower())
        self.assertNotIn("url", status)

        request = urllib.request.Request(
            f"http://127.0.0.1:{started['port']}/api/projects",
            headers={"X-Rta-Smriti-Token": started["url"].split("#token=", 1)[1]},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        self.assertEqual(response.status, 200)
        self.assertEqual(payload["status"], "ok")
        self.assertIsNone(response.headers.get("Set-Cookie"))

        health_request = urllib.request.Request(
            f"http://127.0.0.1:{started['port']}/api/runtime-health",
            headers={"X-Rta-Smriti-Token": started["url"].split("#token=", 1)[1]},
        )
        with urllib.request.urlopen(health_request, timeout=5) as response:
            runtime_health = json.loads(response.read().decode("utf-8"))
        self.assertEqual(runtime_health["instance_id"], started["instance_id"])

        with patch("rta_brain.console_daemon.webbrowser.open", return_value=True) as browser_open:
            opened = open_console(self.brain_dir, launch_browser=True)
        browser_open.assert_called_once_with(opened["url"])
        self.assertEqual(opened["port"], started["port"])

        restarted = restart_console(
            ROOT,
            self.brain_dir,
            port=0,
            open_browser=False,
            startup_timeout=10.0,
        )
        self.assertEqual(restarted["state"], "running")
        self.assertEqual(restarted["startup_stage"], "running")
        self.assertNotEqual(restarted["pid"], started["pid"])

        stopped = stop_console(self.brain_dir, timeout=10.0)
        self.assertEqual(stopped["state"], "stopped")

    def test_occupied_preferred_port_recovers_to_an_available_port(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        occupied = int(listener.getsockname()[1])
        try:
            started = start_console(
                ROOT,
                self.brain_dir,
                port=occupied,
                open_browser=False,
                startup_timeout=10.0,
            )
        finally:
            listener.close()
        self.assertEqual(started["state"], "running")
        self.assertNotEqual(started["port"], occupied)

    def test_unauthorized_api_request_is_rejected(self):
        started = start_console(ROOT, self.brain_dir, port=0, open_browser=False, startup_timeout=10.0)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(
                f"http://127.0.0.1:{started['port']}/api/projects",
                timeout=5,
            )
        self.assertEqual(caught.exception.code, 403)
        caught.exception.close()

    def test_console_rejects_non_object_json_without_internal_error(self):
        started = start_console(ROOT, self.brain_dir, port=0, open_browser=False, startup_timeout=10.0)
        token = started["url"].split("#token=", 1)[1]
        request = urllib.request.Request(
            f"http://127.0.0.1:{started['port']}/api/preflight",
            data=b"[]",
            headers={"X-Rta-Smriti-Token": token, "Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 400)
        payload = json.loads(caught.exception.read().decode("utf-8"))
        self.assertEqual(payload["error"]["type"], "ValueError")
        caught.exception.close()

    def test_governance_api_supports_policy_preflight_override_and_retirement(self):
        db_path = self.brain_dir / "demo.sqlite"
        conn = connect(db_path)
        try:
            init_project(conn, "demo", self.tempdir.name)
        finally:
            conn.close()
        started = start_console(ROOT, self.brain_dir, port=0, open_browser=False, startup_timeout=10.0)
        token = started["url"].split("#token=", 1)[1]
        base_url = f"http://127.0.0.1:{started['port']}"
        headers = {"X-Rta-Smriti-Token": token, "Content-Type": "application/json"}

        def post(path, payload):
            request = urllib.request.Request(
                base_url + path,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))

        project_ref = {"db_path": str(db_path), "project": "demo"}
        created = post("/api/governance-policy", {
            **project_ref,
            "action": "create",
            "kind": "constraint",
            "statement": "Do not publish without privacy proof.",
            "effect": "block",
            "action_contains": "publish",
            "pramana": "pratyaksha",
            "confidence": 1.0,
            "provenance": {"verification_status": "verified", "source_path": "SECURITY.md", "source_hash": "privacy-policy"},
        })
        policy_id = created["policy"]["id"]

        request = urllib.request.Request(
            f"{base_url}/api/governance?db_path={db_path}&project=demo",
            headers={"X-Rta-Smriti-Token": token},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            governance = json.loads(response.read().decode("utf-8"))
        self.assertEqual([item["id"] for item in governance["policies"]], [policy_id])
        self.assertEqual(governance["receipts"], [])

        blocked = post("/api/preflight", {**project_ref, "action": "Publish release"})
        self.assertEqual(blocked["decision"], "block")
        overridden = post("/api/preflight", {
            **project_ref,
            "action": "Publish release",
            "override_reason": "Owner approved this exact publication.",
            "actor": "operator",
        })
        self.assertEqual(overridden["decision"], "allow_with_override")
        self.assertIsNotNone(overridden["override_receipt"])

        retired = post("/api/governance-policy", {
            **project_ref,
            "action": "retire",
            "policy_id": policy_id,
            "reason": "Release policy replaced.",
        })
        self.assertEqual(retired["policy"]["status"], "retired")

    def test_capture_operator_api_covers_lifecycle_replay_privacy_and_deletion(self):
        root = Path(self.tempdir.name) / "capture-repo"
        root.mkdir()
        database = self.brain_dir / "capture.sqlite"
        conn = connect(database)
        policy = CapturePolicy.continuity()
        source = CaptureSource(
            source_id="codex-local",
            adapter="codex-jsonl",
            adapter_version="1",
            installation_scope="transcript",
            config_fingerprint=hashlib.sha256(b"operator-capture-source").hexdigest(),
        )
        try:
            init_project(conn, "capture-demo", str(root))
            register_policy(
                conn,
                project="capture-demo",
                active_root=root,
                policy_id="continuity",
                policy_version=1,
                policy=policy,
            )
            register_source(
                conn,
                project="capture-demo",
                active_root=root,
                source=source,
                policy_digest=policy.digest,
            )
            event = append_event(
                conn,
                project="capture-demo",
                active_root=root,
                source_id=source.source_id,
                event=NormalizedEvent(
                    event_name="turn.interrupted.v1",
                    session_id="session-a",
                    source_cursor="1",
                    observed_at="2026-08-22T09:00:01+00:00",
                    occurred_at="2026-08-22T09:00:00+00:00",
                    attributes={"reason": "restart", "summary": "Resume the verified task."},
                    actor_type="agent",
                    actor_id="operator-fixture",
                ),
                idempotency_key="operator:event:1",
                cursor_kind="sequence",
                original_bytes=100,
                redaction_count=0,
                truncation_count=0,
            )
        finally:
            conn.close()

        started = start_console(
            ROOT, self.brain_dir, port=0, open_browser=False, startup_timeout=10.0
        )
        token = started["url"].split("#token=", 1)[1]
        base_url = f"http://127.0.0.1:{started['port']}"
        headers = {"X-Rta-Smriti-Token": token, "Content-Type": "application/json"}
        project_ref = {"db_path": str(database), "project": "capture-demo"}

        def get(mode, **params):
            query = urllib.parse.urlencode({**project_ref, "mode": mode, **params})
            request = urllib.request.Request(
                f"{base_url}/api/capture?{query}",
                headers={"X-Rta-Smriti-Token": token},
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))

        def post(action, **payload):
            request = urllib.request.Request(
                f"{base_url}/api/capture",
                data=json.dumps({**project_ref, "action": action, **payload}).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))

        overview = get("overview")
        self.assertEqual(overview["sources"][0]["source_id"], "codex-local")
        self.assertEqual(overview["policies"][0]["profile"], "continuity")
        self.assertNotIn(str(root), json.dumps(overview))
        self.assertEqual(get("sources")["sources"][0]["state"], "active")
        self.assertEqual(get("policies")["policies"][0]["policy_digest"], policy.digest)
        timeline = get("timeline", limit=20)
        self.assertEqual(timeline["mode"], "chronological")
        self.assertEqual(timeline["interruption_snapshot"]["status"], "interrupted")
        replay = get("replay", replay_mode="causal", limit=20)
        self.assertEqual(replay["mode"], "causal")
        self.assertFalse(replay["executes_actions"])
        diagnostics = get("diagnostics")
        self.assertEqual(diagnostics["events"]["count"], 1)
        self.assertTrue(diagnostics["canonical_root_verified"])

        preview = post(
            "policy-preview",
            profile="metadata-only",
            privacy_ceiling="public",
            retention_seconds=3600,
        )
        self.assertEqual(preview["policy"]["profile"], "metadata-only")
        self.assertEqual(len(preview["policy_digest"]), 64)
        self.assertFalse(preview["writes_state"])

        paused = post("source-state", source_id="codex-local", state="paused")
        self.assertEqual(paused["state"], "paused")
        resumed = post("source-state", source_id="codex-local", state="active")
        self.assertEqual(resumed["state"], "active")
        bound = post(
            "bind-session",
            source_id="codex-local",
            external_session_id="session-b",
            cursor_kind="sequence",
            start_cursor="1",
        )
        self.assertEqual(bound["status"], "active")
        closed = post("close-session", binding_id=bound["binding_id"])
        self.assertEqual(closed["status"], "closed")

        retention_preview = post(
            "retention-preview",
            policy_digest=policy.digest,
            run_id="dashboard-retention-1",
            batch_size=100,
        )
        self.assertEqual(retention_preview["operation"], "preview")
        retained = post(
            "retention-confirm",
            policy_digest=policy.digest,
            run_id="dashboard-retention-1",
            batch_size=100,
            confirmation_token=retention_preview["confirmation_token"],
        )
        self.assertEqual(retained["state"], "complete")
        redaction = post("redaction-preview", privacy_ceiling="public", limit=20)
        self.assertTrue(redaction["redaction_verified"])
        self.assertFalse(redaction["payloads_included"])
        deletion_preview = post(
            "deletion-preview",
            scope="event-content",
            scope_token=event["event_id"],
            reason_class="operator-request",
            policy_digest=policy.digest,
        )
        self.assertEqual(deletion_preview["operation"], "preview")
        invalid_compaction = urllib.request.Request(
            f"{base_url}/api/capture",
            data=json.dumps({
                **project_ref,
                "action": "deletion-confirm",
                "scope": "event-content",
                "scope_token": event["event_id"],
                "reason_class": "operator-request",
                "policy_digest": policy.digest,
                "confirmation_token": deletion_preview["confirmation_token"],
                "secure_compact": "false",
            }).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as rejected:
            urllib.request.urlopen(invalid_compaction, timeout=5)
        self.assertEqual(rejected.exception.code, 400)
        self.assertEqual(
            json.loads(rejected.exception.read().decode("utf-8"))["error"]["type"],
            "TypeError",
        )
        rejected.exception.close()
        deleted = post(
            "deletion-confirm",
            scope="event-content",
            scope_token=event["event_id"],
            reason_class="operator-request",
            policy_digest=policy.digest,
            confirmation_token=deletion_preview["confirmation_token"],
        )
        self.assertEqual(deleted["operation"], "logical-delete")
        exported = post("export", privacy_ceiling="internal", limit=20)
        self.assertTrue(exported["redaction_verified"])
        self.assertEqual(exported["events"][0]["content_state"], "logically-deleted")

        running = post("daemon-start", interval=0.1, batch_size=20)
        self.assertEqual(running["state"], "running")
        try:
            with ThreadPoolExecutor(max_workers=3) as executor:
                parallel = list(executor.map(get, ("overview", "replay", "diagnostics")))
            self.assertEqual(parallel[0]["status"], "ok")
            self.assertFalse(parallel[1]["executes_actions"])
            self.assertEqual(parallel[2]["status"], "ok")
        finally:
            stopped = post("daemon-stop")
            self.assertEqual(stopped["state"], "stopped")

    def test_context_compiler_api_keeps_authority_material_off_the_wire(self):
        root = Path(self.tempdir.name) / "context-repo"
        root.mkdir()
        subprocess.run(["git", "-C", str(root), "init"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(root), "config", "user.email", "fixture@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(root), "config", "user.name", "Fixture"],
            check=True,
        )
        (root / "state.txt").write_text("ready\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "state.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-m", "fixture"],
            check=True,
            capture_output=True,
        )
        database = self.brain_dir / "context.sqlite"
        conn = connect(database)
        try:
            init_project(conn, "demo", str(root))
        finally:
            conn.close()
        started = start_console(
            ROOT, self.brain_dir, port=0, open_browser=False, startup_timeout=10.0
        )
        token = started["url"].split("#token=", 1)[1]
        endpoint = f"http://127.0.0.1:{started['port']}/api/context-compiler"
        headers = {
            "X-Rta-Smriti-Token": token,
            "Content-Type": "application/json",
        }

        def post(payload):
            request = urllib.request.Request(
                endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                self.fail(
                    f"context compiler returned HTTP {exc.code}: {body}"
                )

        project_ref = {"db_path": str(database), "project": "demo"}
        compiled = post(
            {
                **project_ref,
                "action": "authorize-and-compile",
                "profile_id": "codex",
                "max_input_tokens": 8_192,
                "objective": "Resume the verified project task.",
                "comparison_modes": ["minimal"],
                "principal_id": "codex",
                "session_id": "dashboard-task",
                "variant": "primary",
            }
        )
        compilation_id = compiled["compilation_receipt"]["compilation_id"]
        audited = post(
            {
                **project_ref,
                "action": "audit",
                "compilation_id": compilation_id,
                "session_id": "dashboard-operator-task",
            }
        )

        serialized = json.dumps({"compiled": compiled, "audited": audited})
        self.assertEqual(compiled["status"], "stable")
        self.assertTrue(audited["receipt_integrity_verified"])
        self.assertNotIn("capability_token", serialized)
        self.assertNotIn("authority_secret", serialized)
        self.assertNotIn("operator_audit", serialized)

    def test_intelligence_workspace_and_feedback_apis_use_selected_brains(self):
        api_root = Path(self.tempdir.name) / "api"
        web_root = Path(self.tempdir.name) / "web"
        api_root.mkdir()
        web_root.mkdir()
        (api_root / "service.py").write_text(
            "def helper():\n    return 1\n\ndef run():\n    return helper()\n", encoding="utf-8",
        )
        (web_root / "README.md").write_text(
            "The web client consumes the helper envelope.\n", encoding="utf-8",
        )
        api_db = self.brain_dir / "api.sqlite"
        web_db = self.brain_dir / "web.sqlite"
        api = connect(api_db)
        try:
            init_project(api, "api", str(api_root))
            ingest_repo(api, api_root, project="api")
            memory_id = remember(
                api, "Helper changes require a focused test.", project="api",
            )["memory"]["id"]
        finally:
            api.close()
        web = connect(web_db)
        try:
            init_project(web, "web", str(web_root))
            ingest_repo(web, web_root, project="web")
        finally:
            web.close()

        started = start_console(ROOT, self.brain_dir, port=0, open_browser=False, startup_timeout=10.0)
        token = started["url"].split("#token=", 1)[1]
        base_url = f"http://127.0.0.1:{started['port']}"
        headers = {"X-Rta-Smriti-Token": token, "Content-Type": "application/json"}

        def get(path):
            request = urllib.request.Request(base_url + path, headers={"X-Rta-Smriti-Token": token})
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))

        def post(path, payload):
            request = urllib.request.Request(
                base_url + path,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.loads(response.read().decode("utf-8"))

        api_query = f"db_path={api_db}&project=api"
        diagnostics = get(f"/api/retrieval-diagnostics?{api_query}&query=helper")
        self.assertEqual(diagnostics["results"][0]["path"], "service.py")
        impact = get(f"/api/graph-query?{api_query}&target=helper&type=impact&depth=2")
        self.assertTrue(impact["nodes"])

        created = post("/api/workspace", {
            "db_path": str(api_db), "action": "create", "name": "product-stack",
        })
        self.assertEqual(created["workspace"]["name"], "product-stack")
        for project, member_db in (("api", api_db), ("web", web_db)):
            post("/api/workspace", {
                "db_path": str(api_db), "action": "add", "name": "product-stack",
                "project": project, "member_db_path": str(member_db),
            })
        workspace = get(
            f"/api/workspace-search?{api_query}&workspace=product-stack&query=helper&limit=4"
        )
        self.assertEqual({item["project"] for item in workspace["results"]}, {"api", "web"})
        health = get(f"/api/workspace-health?{api_query}&workspace=product-stack")
        self.assertEqual(health["status"], "ok")
        removed = post("/api/workspace", {
            "db_path": str(api_db), "action": "remove", "name": "product-stack",
            "project": "web", "member_db_path": str(web_db),
        })
        self.assertEqual([item["project"] for item in removed["projects"]], ["api"])
        post("/api/workspace", {
            "db_path": str(api_db), "action": "add", "name": "product-stack",
            "project": "web", "member_db_path": str(web_db),
        })

        passphrase = Path(self.tempdir.name) / "snapshot.passphrase"
        passphrase.write_text("operator test passphrase", encoding="utf-8")
        encrypted = Path(self.tempdir.name) / "api.rtae"
        restored = Path(self.tempdir.name) / "api-restored.sqlite"
        created_snapshot = post("/api/snapshot", {
            "db_path": str(api_db), "project": "api", "action": "encrypt",
            "path": str(encrypted), "passphrase_path": str(passphrase),
        })
        self.assertEqual(created_snapshot["encryption"], "AES-256-GCM")
        verified_snapshot = post("/api/snapshot", {
            "db_path": str(api_db), "project": "api", "action": "verify-encrypted",
            "path": str(encrypted), "passphrase_path": str(passphrase),
        })
        self.assertTrue(verified_snapshot["valid"])
        restored_snapshot = post("/api/snapshot", {
            "db_path": str(api_db), "project": "api", "action": "restore",
            "path": str(encrypted), "passphrase_path": str(passphrase), "output_db": str(restored),
        })
        self.assertTrue(restored_snapshot["valid"])

        mcp = post("/api/mcp-doctor", {
            "db_path": str(api_db), "project": "api", "timeout": 10,
        })
        self.assertTrue(mcp["ready"])
        self.assertGreater(mcp["tool_count"], 0)

        feedback = post("/api/memory-feedback", {
            "db_path": str(api_db), "project": "api", "memory_id": memory_id,
            "outcome": "helpful", "evidence": "Operator confirmed during API test.",
        })
        self.assertEqual(feedback["outcome"], "helpful")

    def test_concurrent_starts_converge_on_one_verified_console(self):
        barrier = threading.Barrier(2)

        def launch():
            barrier.wait(timeout=5)
            return start_console(
                ROOT, self.brain_dir, port=0, open_browser=False, startup_timeout=10.0,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _index: launch(), range(2)))
        self.assertEqual({result["pid"] for result in results}, {results[0]["pid"]})
        self.assertEqual({result["instance_id"] for result in results}, {results[0]["instance_id"]})

    def test_dead_process_state_is_reported_as_stale_without_leaking_secret(self):
        paths = console_paths(self.brain_dir)
        write_json(
            paths["state"],
            {
                "state": "running",
                "pid": 999_999_999,
                "host": "127.0.0.1",
                "port": 8765,
            },
        )
        status = console_status(self.brain_dir)
        self.assertEqual(status["state"], "stale")
        self.assertNotIn("token", json.dumps(status).lower())

    def test_live_but_unverified_process_state_is_unresponsive(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        try:
            paths = console_paths(self.brain_dir)
            write_json(
                paths["state"],
                {
                    "state": "running",
                    "pid": os.getpid(),
                    "instance_id": "not-this-process",
                    "host": "127.0.0.1",
                    "port": int(listener.getsockname()[1]),
                },
            )
            status = console_status(self.brain_dir)
        finally:
            listener.close()
        self.assertEqual(status["state"], "unresponsive")

    def test_invalid_port_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "port"):
            start_console(ROOT, self.brain_dir, port=70_000, open_browser=False)


if __name__ == "__main__":
    unittest.main()
