import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from rta_brain.db import init_schema
from rta_brain.federation import store_event
from rta_brain.federation_crypto import (
    create_encrypted_event,
    create_identity,
    generate_scope_key,
)
from rta_brain.federation_governance import (
    create_scope,
    create_space,
    rotate_scope_key,
    validate_and_accept_event,
)
from rta_brain.federation_http_relay import (
    FederationHttpRelay,
    FederationHttpRelayServer,
)
from rta_brain.federation_transport import (
    FederationTransportError,
    pull_and_validate_from_relay,
    push_to_relay,
)

PASSPHRASE = b"correct horse battery staple"


class FederationHttpRelayTests(unittest.TestCase):
    def test_http_transport_converges_through_the_common_relay_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = create_identity(root / "owner", passphrase=PASSPHRASE)
            source = sqlite3.connect(":memory:")
            source.row_factory = sqlite3.Row
            source.execute("PRAGMA foreign_keys = ON")
            init_schema(source)
            source.execute(
                "INSERT INTO projects(id, name, created_at) VALUES "
                "(1, 'atlas', '2026-09-07T00:00:00+00:00')"
            )
            self.addCleanup(source.close)
            space = create_space(
                source,
                project_id=1,
                owner=owner,
                owner_key_reference="identity/owner",
            )
            scope = create_scope(
                source,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="team",
                label="Team",
            )
            key = generate_scope_key()
            rotate_scope_key(
                source,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                scope_key=key,
            )
            destination = sqlite3.connect(":memory:")
            destination.row_factory = sqlite3.Row
            destination.execute("PRAGMA foreign_keys = ON")
            source.backup(destination)
            self.addCleanup(destination.close)
            event = create_encrypted_event(
                {
                    "event_type": "memory.asserted",
                    "object_id": "http-contract",
                    "text": "opaque transport parity",
                    "valid_from": "2026-09-07T00:00:00+00:00",
                    "privacy_class": "internal",
                    "epistemic_state": "observed",
                },
                identity=owner,
                scope_key=key,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                epoch=1,
                author_sequence=1,
                capability_event_id=space["bootstrap"]["event_id"],
                parents=(),
                received_at="2026-09-07T00:00:00+00:00",
            )
            store_event(source, project_id=1, envelope=event)
            validate_and_accept_event(
                source,
                project_id=1,
                envelope=event,
                author_signing_public_key=owner.signing_public_bytes,
                scope_key=key,
            )
            capability = "c" * 64
            server = FederationHttpRelayServer(
                root / "relay", space_capabilities={space["space_id"]: capability}
            )
            server.start()
            self.addCleanup(server.stop)
            relay = FederationHttpRelay(server.url, capability=capability)

            pushed = push_to_relay(
                source,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                actor_peer_id=owner.identity_id,
                relay=relay,
            )
            pulled = pull_and_validate_from_relay(
                destination,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                actor=owner,
                relay=relay,
                transport_id="http-contract",
            )

            self.assertEqual(pushed["event_count"], 1)
            self.assertEqual(pulled["accepted"], 1)
            self.assertEqual(
                destination.execute(
                    "SELECT validation_state FROM federation_event_validation "
                    "WHERE event_row_id = (SELECT id FROM federation_events WHERE event_id = ?)",
                    (event.event_id,),
                ).fetchone()[0],
                "accepted",
            )

    def test_loopback_relay_is_opaque_capability_gated_and_quota_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            identity = create_identity(root / "identity", passphrase=PASSPHRASE)
            space_id = "a" * 64
            scope_id = "b" * 64
            capability = "c" * 64
            server = FederationHttpRelayServer(
                root / "relay",
                space_capabilities={space_id: capability},
                max_objects_per_space=1,
            )
            server.start()
            self.addCleanup(server.stop)
            relay = FederationHttpRelay(server.url, capability=capability)
            first = create_encrypted_event(
                {"event_type": "comment.added", "text": "private fixture"},
                identity=identity,
                scope_key=generate_scope_key(),
                space_id=space_id,
                scope_id=scope_id,
                epoch=1,
                author_sequence=1,
                capability_event_id="d" * 64,
                parents=(),
                received_at="2026-09-07T00:00:00+00:00",
            )
            stored = relay.put_event(first)
            self.assertEqual(stored["state"], "stored")
            self.assertEqual(relay.inventory(space_id), [first.event_id])
            self.assertEqual(relay.get_event(space_id, first.event_id).encoded, first.encoded)
            self.assertEqual(relay.health()["state"], "healthy")

            unauthorized = FederationHttpRelay(server.url, capability="e" * 64)
            with self.assertRaisesRegex(FederationTransportError, "authorization"):
                unauthorized.inventory(space_id)

            second = create_encrypted_event(
                {"event_type": "comment.added", "text": "second private fixture"},
                identity=identity,
                scope_key=generate_scope_key(),
                space_id=space_id,
                scope_id=scope_id,
                epoch=1,
                author_sequence=2,
                capability_event_id="d" * 64,
                parents=(first.event_id,),
                received_at="2026-09-07T00:01:00+00:00",
            )
            with self.assertRaisesRegex(FederationTransportError, "quota"):
                relay.put_event(second)

            audit = str(server.audit_log)
            self.assertNotIn("private fixture", audit)
            self.assertNotIn(space_id, audit)
            self.assertNotIn(first.event_id, audit)

    def test_non_loopback_bind_requires_explicit_opt_in(self):
        with (
            tempfile.TemporaryDirectory() as tmp,
            self.assertRaisesRegex(ValueError, "non-loopback"),
        ):
            FederationHttpRelayServer(
                    Path(tmp),
                    host="0.0.0.0",
                    space_capabilities={"a" * 64: "c" * 64},
                )

    def test_client_rejects_ambiguous_or_credential_bearing_relay_urls(self):
        capability = "c" * 64
        invalid_urls = (
            "file:///tmp/relay",
            "http://user:secret@example.test",
            "http://example.test?target=other",
            "http://example.test#fragment",
            "http://",
        )
        for url in invalid_urls:
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "relay URL"):
                FederationHttpRelay(url, capability=capability)

    def test_client_does_not_forward_capability_across_redirects(self):
        destination_requests = []

        class DestinationHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                destination_requests.append(dict(self.headers))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "19")
                self.end_headers()
                self.wfile.write(b'{"state":"healthy"}')

        destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)
        destination_thread = threading.Thread(target=destination.serve_forever, daemon=True)
        destination_thread.start()

        def stop_destination():
            destination.shutdown()
            destination.server_close()
            destination_thread.join(2)

        self.addCleanup(stop_destination)
        destination_url = f"http://127.0.0.1:{destination.server_address[1]}"

        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", destination_url + "/health")
                self.send_header("Content-Length", "0")
                self.end_headers()

        source = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        source_thread = threading.Thread(target=source.serve_forever, daemon=True)
        source_thread.start()

        def stop_source():
            source.shutdown()
            source.server_close()
            source_thread.join(2)

        self.addCleanup(stop_source)
        relay = FederationHttpRelay(
            f"http://127.0.0.1:{source.server_address[1]}", capability="c" * 64
        )

        with self.assertRaisesRegex(FederationTransportError, "status 302"):
            relay.inventory("a" * 64)
        self.assertEqual(destination_requests, [])

    def test_quota_decision_and_write_are_serialized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            identity = create_identity(root / "identity", passphrase=PASSPHRASE)
            space_id = "a" * 64
            scope_id = "b" * 64
            capability = "c" * 64
            server = FederationHttpRelayServer(
                root / "relay",
                space_capabilities={space_id: capability},
                max_objects_per_space=1,
            )
            active = 0
            max_active = 0
            activity_lock = threading.Lock()
            original_put = server._relay.put_event

            def delayed_put(envelope):
                nonlocal active, max_active
                with activity_lock:
                    active += 1
                    max_active = max(max_active, active)
                try:
                    time.sleep(0.1)
                    return original_put(envelope)
                finally:
                    with activity_lock:
                        active -= 1

            server._relay.put_event = delayed_put
            server.start()
            self.addCleanup(server.stop)
            events = [
                create_encrypted_event(
                    {"event_type": "comment.added", "text": f"fixture {sequence}"},
                    identity=identity,
                    scope_key=generate_scope_key(),
                    space_id=space_id,
                    scope_id=scope_id,
                    epoch=1,
                    author_sequence=sequence,
                    capability_event_id="d" * 64,
                    parents=(),
                    received_at=f"2026-09-07T00:0{sequence}:00+00:00",
                )
                for sequence in (1, 2)
            ]

            def upload(event):
                relay = FederationHttpRelay(server.url, capability=capability)
                try:
                    relay.put_event(event)
                    return "stored"
                except FederationTransportError as exc:
                    return str(exc)

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(upload, events))

            self.assertEqual(results.count("stored"), 1)
            self.assertEqual(sum("quota" in item for item in results), 1)
            self.assertEqual(max_active, 1)
            self.assertEqual(len(server._relay.inventory(space_id)), 1)

    def test_server_exposes_and_enforces_bounded_request_workers(self):
        with tempfile.TemporaryDirectory() as tmp:
            server = FederationHttpRelayServer(
                Path(tmp),
                space_capabilities={"a" * 64: "c" * 64},
                max_workers=3,
                request_timeout=4.0,
            )
            self.addCleanup(server.stop)

            self.assertEqual(server.worker_limit, 3)
            self.assertEqual(server.request_timeout_seconds, 4.0)
            self.assertEqual(server._httpd.worker_limit, 3)


if __name__ == "__main__":
    unittest.main()
