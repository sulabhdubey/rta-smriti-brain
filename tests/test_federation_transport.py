import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain.federation_crypto import (
    create_encrypted_event,
    create_identity,
    generate_scope_key,
)
from rta_brain.federation_transport import (
    FederationTransportError,
    FilesystemFederationRelay,
)

PASSPHRASE = b"correct horse battery staple"


class FilesystemFederationRelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.identity = create_identity(root / "identity", passphrase=PASSPHRASE)
        self.relay = FilesystemFederationRelay(root / "relay")
        self.key = generate_scope_key()
        self.space_id = "a" * 64
        self.scope_id = "b" * 64

    def _event(self, sequence: int, text: str):
        return create_encrypted_event(
            {
                "event_type": "memory.asserted",
                "object_id": f"memory-{sequence}",
                "text": text,
                "valid_from": "2026-09-07T00:00:00+00:00",
                "privacy_class": "internal",
                "epistemic_state": "observed",
            },
            identity=self.identity,
            scope_key=self.key,
            space_id=self.space_id,
            scope_id=self.scope_id,
            epoch=1,
            author_sequence=sequence,
            capability_event_id="c" * 64,
            parents=(),
            received_at="2026-09-07T00:00:00+00:00",
        )

    def test_relay_is_content_addressed_idempotent_and_contains_no_plaintext(self):
        event = self._event(1, "private Atlas architecture")
        first = self.relay.put_event(event)
        second = self.relay.put_event(event)

        self.assertEqual(first["state"], "stored")
        self.assertEqual(second["state"], "already_present")
        self.assertNotIn("path", first)
        self.assertNotIn("path", second)
        self.assertEqual(self.relay.inventory(self.space_id), [event.event_id])
        encoded = self.relay.get_event(self.space_id, event.event_id).encoded
        self.assertNotIn(b"private Atlas architecture", encoded)
        self.assertNotIn(b"received_at", encoded)

    def test_inventory_and_missing_are_deterministic_and_bounded(self):
        events = [self._event(index, f"memory {index}") for index in range(1, 4)]
        for event in reversed(events):
            self.relay.put_event(event)

        expected = sorted(event.event_id for event in events)
        self.assertEqual(self.relay.inventory(self.space_id), expected)
        self.assertEqual(
            self.relay.missing(self.space_id, (events[0].event_id,)),
            sorted((events[1].event_id, events[2].event_id)),
        )
        with self.assertRaisesRegex(ValueError, "bounded"):
            self.relay.missing(self.space_id, tuple("d" * 64 for _ in range(10_001)))

    def test_corruption_and_oversized_blob_fail_closed(self):
        event = self._event(1, "integrity fixture")
        self.relay.put_event(event)
        path = self.relay._path(self.space_id, event.event_id)
        path.write_bytes(path.read_bytes()[:-1] + b"x")
        with self.assertRaisesRegex(FederationTransportError, "digest"):
            self.relay.get_event(self.space_id, event.event_id)

        tiny = FilesystemFederationRelay(Path(self.temp.name) / "tiny", max_blob_bytes=100)
        with self.assertRaisesRegex(FederationTransportError, "size limit"):
            tiny.put_event(event)

    def test_relay_rejects_path_traversal_identifiers(self):
        with self.assertRaisesRegex(ValueError, "space_id"):
            self.relay.inventory("../private")
        with self.assertRaisesRegex(ValueError, "event_id"):
            self.relay.get_event(self.space_id, "../private")

    def test_relay_rejects_linked_storage_components(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        objects = self.relay.root / "objects"
        self.relay.root.mkdir(parents=True, exist_ok=True)
        try:
            os.symlink(outside, objects, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"directory links are unavailable: {exc}")

        with self.assertRaisesRegex(FederationTransportError, "linked|reparse"):
            self.relay.put_event(self._event(1, "must remain contained"))

    def test_relay_fails_closed_when_a_storage_component_is_reparse_marked(self):
        original = self.relay._is_link_or_reparse

        def mark_objects(path):
            return path.name == "objects" or original(path)

        with (
            patch.object(self.relay, "_is_link_or_reparse", side_effect=mark_objects),
            self.assertRaisesRegex(FederationTransportError, "linked|reparse"),
        ):
            self.relay.put_event(self._event(1, "must remain contained"))


if __name__ == "__main__":
    unittest.main()
