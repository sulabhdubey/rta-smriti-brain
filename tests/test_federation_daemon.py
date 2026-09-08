import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from rta_brain import db
from rta_brain.cli import build_parser
from rta_brain.federation import store_event
from rta_brain.federation_crypto import (
    create_encrypted_event,
    create_identity,
    generate_scope_key,
)
from rta_brain.federation_daemon import (
    _worker_command,
    apply_federation_sync_daemon_operation,
    configure_federation_sync,
    federation_sync_paths,
    federation_sync_status,
    perform_federation_sync_cycle,
    preview_federation_sync_configuration,
    preview_federation_sync_daemon_operation,
    remove_federation_sync,
    start_federation_sync,
    stop_federation_sync,
)
from rta_brain.federation_governance import (
    create_scope,
    create_space,
    validate_and_accept_event,
)
from rta_brain.runtime_control import read_json, write_json, write_secret

PASSPHRASE = "correct horse battery staple"


class FederationDaemonTests(unittest.TestCase):
    def test_frozen_worker_command_is_a_registered_private_cli_entry_point(self):
        paths = federation_sync_paths(self.database, "demo")
        with patch("rta_brain.federation_daemon.sys.frozen", True, create=True):
            command = _worker_command(paths)

        parsed = build_parser().parse_args(command[1:])

        self.assertEqual(parsed.command, "_federation-sync-worker")
        self.assertEqual(Path(parsed.config_file), paths["config"])
        self.assertEqual(Path(parsed.state_file), paths["state"])
        self.assertEqual(Path(parsed.stop_file), paths["stop"])
        self.assertEqual(Path(parsed.lock_file), paths["lock"])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project_root = self.root / "project"
        self.project_root.mkdir()
        self.database = self.root / "brains" / "demo.sqlite"
        conn = db.connect(self.database)
        try:
            db.init_project(conn, "demo", self.project_root)
            self.project_id = int(
                conn.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()[0]
            )
        finally:
            conn.close()
        self.identity_root = self.root / "identity"
        self.passphrase_file = self.root / "identity-passphrase.secret"
        write_secret(
            self.passphrase_file,
            PASSPHRASE,
            label="federation identity passphrase",
        )
        self.owner = create_identity(
            self.identity_root, passphrase=PASSPHRASE.encode("utf-8")
        )
        conn = db.connect(self.database)
        try:
            self.space = create_space(
                conn,
                project_id=self.project_id,
                owner=self.owner,
                owner_key_reference="managed-local-identity",
            )
            self.scope = create_scope(
                conn,
                project_id=self.project_id,
                space_id=self.space["space_id"],
                owner=self.owner,
                kind="team",
                label="Team",
            )
        finally:
            conn.close()
        self.relay_root = self.root / "relay"
        self.relay_root.mkdir()
        self.config = {
            "db_path": str(self.database),
            "project": "demo",
            "space_id": self.space["space_id"],
            "scope_id": self.scope["scope_id"],
            "identity_dir": str(self.identity_root),
            "passphrase_file": str(self.passphrase_file),
            "relay_kind": "filesystem",
            "relay_root": str(self.relay_root),
            "transport_id": "primary-relay",
            "limit": 100,
            "interval_seconds": 30.0,
        }

    def _configure(self):
        preview = preview_federation_sync_configuration(self.config)
        self.assertFalse(preview["writes_performed"])
        return configure_federation_sync(
            self.config,
            confirmation_digest=preview["confirmation_digest"],
        )

    def _add_event(self):
        key = generate_scope_key()
        event = create_encrypted_event(
            {
                "event_type": "memory.asserted",
                "object_id": "memory-one",
                "text": "private payload",
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
            identity=self.owner,
            scope_key=key,
            space_id=self.space["space_id"],
            scope_id=self.scope["scope_id"],
            epoch=1,
            author_sequence=1,
            capability_event_id=self.space["bootstrap"]["event_id"],
            parents=(),
            received_at="2026-09-07T00:00:00+00:00",
        )
        conn = db.connect(self.database)
        try:
            store_event(conn, project_id=self.project_id, envelope=event)
            validate_and_accept_event(
                conn,
                project_id=self.project_id,
                envelope=event,
                author_signing_public_key=self.owner.signing_public_bytes,
                scope_key=key,
            )
        finally:
            conn.close()
        return event

    def test_configuration_is_private_and_status_is_path_free(self):
        configured = self._configure()
        paths = federation_sync_paths(self.database, "demo")

        self.assertEqual(configured["state"], "configured")
        self.assertTrue(paths["config"].is_file())
        stored = read_json(paths["config"])
        self.assertEqual(stored["identity_dir"], str(self.identity_root.resolve()))
        public = federation_sync_status(self.database, "demo")
        rendered = str(public)
        self.assertEqual(public["state"], "configured")
        self.assertNotIn(str(self.root), rendered)
        self.assertNotIn(PASSPHRASE, rendered)
        self.assertNotIn("private payload", rendered)

    def test_cycle_repairs_exact_scope_and_returns_bounded_path_free_receipt(self):
        event = self._add_event()
        self._configure()

        result = perform_federation_sync_cycle(self.database, "demo")

        self.assertEqual(result["state"], "healthy")
        self.assertEqual(result["pushed"], 1)
        self.assertEqual(result["relay_event_count"], 1)
        self.assertEqual(result["local_event_count"], 1)
        self.assertEqual(
            next((self.relay_root / "objects" / self.space["space_id"]).rglob("*.event")).stem,
            event.event_id,
        )
        self.assertNotIn(str(self.root), str(result))
        self.assertNotIn("private payload", str(result))

    def test_start_is_singular_and_uses_detached_worker_launcher(self):
        configured = self._configure()
        process = MagicMock()
        process.pid = 4321
        process.poll.return_value = None
        running = {
            "status": "ok",
            "state": "running",
            "pid": 4321,
            "process_identity": "test:4321:birth",
            "process_alive": True,
            "process_identity_matches": True,
            "heartbeat_at": "2026-09-07T00:00:00+00:00",
            "configuration_digest": configured["configuration_digest"],
        }
        with (
            patch("rta_brain.federation_daemon.spawn_detached_worker", return_value=process) as spawn,
            patch("rta_brain.federation_daemon.federation_sync_status", side_effect=[
                {"status": "ok", "state": "configured"},
                running,
                running,
            ]),
        ):
            first = start_federation_sync(self.database, "demo", startup_timeout=0.2)
            second = start_federation_sync(self.database, "demo", startup_timeout=0.2)

        self.assertEqual(first["state"], "running")
        self.assertEqual(second["state"], "running")
        spawn.assert_called_once()
        command = spawn.call_args.args[0]
        self.assertIn("rta_brain.federation_worker", " ".join(command))
        self.assertNotIn(str(self.identity_root), command)
        self.assertNotIn(str(self.passphrase_file), command)

    def test_start_refuses_an_existing_launch_claim_before_spawning(self):
        self._configure()
        paths = federation_sync_paths(self.database, "demo")
        write_secret(
            paths["lock"],
            "f" * 64,
            label="federation sync launch lock",
        )

        with (
            patch("rta_brain.federation_daemon.spawn_detached_worker") as spawn,
            self.assertRaisesRegex(RuntimeError, "launch.*progress"),
        ):
            start_federation_sync(self.database, "demo", startup_timeout=0.2)

        spawn.assert_not_called()

    def test_relay_failure_is_isolated_as_offline_without_leaking_paths(self):
        self._configure()
        paths = federation_sync_paths(self.database, "demo")
        capability_file = self.root / "relay-capability.secret"
        write_secret(
            capability_file,
            "relay capability with at least thirty two characters",
            label="federation relay capability",
        )
        stored = read_json(paths["config"])
        stored["relay_kind"] = "http"
        stored["relay_url"] = "http://127.0.0.1:1"
        stored["relay_capability_file"] = str(capability_file)
        stored.pop("relay_root", None)
        write_json(paths["config"], stored, label="federation sync configuration")

        result = perform_federation_sync_cycle(self.database, "demo")

        self.assertEqual(result["state"], "offline")
        self.assertEqual(result["error_class"], "FederationTransportError")
        self.assertNotIn(str(self.root), str(result))
        self.assertNotIn("127.0.0.1", str(result))

    def test_remove_requires_stopped_worker_and_deletes_only_control_configuration(self):
        self._configure()
        conn = db.connect(self.database)
        try:
            db.remember(
                conn,
                "local continuity remains available",
                project="demo",
                pramana="pratyaksha",
            )
        finally:
            conn.close()
        paths = federation_sync_paths(self.database, "demo")
        write_json(
            paths["state"],
            {"state": "running", "pid": 123, "heartbeat_at": "2026-09-07T00:00:00+00:00"},
            label="federation sync state",
        )
        with (
            patch("rta_brain.federation_daemon.federation_sync_status", return_value={"state": "running"}),
            self.assertRaisesRegex(RuntimeError, "stop"),
        ):
            remove_federation_sync(self.database, "demo")

        paths["state"].unlink()
        removed = remove_federation_sync(self.database, "demo")
        self.assertEqual(removed["state"], "not_configured")
        self.assertFalse(paths["config"].exists())
        self.assertTrue(self.database.exists())
        self.assertTrue(self.identity_root.exists())
        self.assertTrue(self.relay_root.exists())
        conn = db.connect(self.database)
        try:
            local_result = db.search(
                conn, "local continuity", project="demo", hybrid=False
            )
        finally:
            conn.close()
        self.assertEqual(local_result["memories"][0]["text"], "local continuity remains available")

    def test_daemon_operation_rejects_configuration_drift_after_preview(self):
        self._configure()
        preview = preview_federation_sync_daemon_operation(
            self.database, "demo", action="cycle"
        )
        paths = federation_sync_paths(self.database, "demo")
        stored = read_json(paths["config"])
        stored["interval_seconds"] = 60.0
        write_json(paths["config"], stored, label="federation sync configuration")

        with self.assertRaisesRegex(PermissionError, "changed after preview"):
            apply_federation_sync_daemon_operation(
                self.database,
                "demo",
                action="cycle",
                confirmation_digest=preview["confirmation_digest"],
            )

    def test_real_worker_starts_cycles_and_stops_without_a_terminal_contract(self):
        self._configure()
        started = start_federation_sync(
            self.database, "demo", startup_timeout=10.0
        )
        try:
            self.assertEqual(started["state"], "running")
            self.assertTrue(started["process_alive"])
            deadline = time.monotonic() + 10.0
            observed = started
            while time.monotonic() < deadline:
                observed = federation_sync_status(self.database, "demo")
                if int(observed.get("successful_cycles") or 0) >= 1:
                    break
                time.sleep(0.05)
            self.assertEqual(observed["sync_state"], "healthy")
            self.assertGreaterEqual(int(observed["successful_cycles"]), 1)
        finally:
            stopped = stop_federation_sync(self.database, "demo", timeout=10.0)
        self.assertEqual(stopped["state"], "configured")
        self.assertEqual(federation_sync_status(self.database, "demo")["state"], "configured")

        restarted = start_federation_sync(
            self.database, "demo", startup_timeout=10.0
        )
        try:
            self.assertEqual(restarted["state"], "running")
            self.assertTrue(restarted["process_alive"])
            self.assertNotEqual(restarted["process_identity"], started["process_identity"])
        finally:
            stopped_again = stop_federation_sync(
                self.database, "demo", timeout=10.0
            )
        self.assertEqual(stopped_again["state"], "configured")


if __name__ == "__main__":
    unittest.main()
