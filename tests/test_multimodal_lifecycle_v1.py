import os
import tempfile
import unittest
from pathlib import Path

from rta_brain import db
from rta_brain.multimodal import (
    add_derivation,
    delete_media,
    export_multimodal_manifest,
    ingest_media,
    list_multimodal_derivations,
    purge_expired_media,
    redact_derivation,
    list_multimodal_evidence,
    set_media_retention,
    verify_multimodal_source,
)


class MultimodalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        self.conn = db.connect(self.base / "brain.sqlite")
        db.init_project(self.conn, "demo", str(self.root))

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def _image(self, name: str = "proof.png") -> Path:
        path = self.root / name
        path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"proof")
        return path

    def test_common_media_types_require_matching_file_signatures(self):
        fixtures = {
            "proof.pdf": b"%PDF-1.7\nfixture",
            "proof.png": b"\x89PNG\r\n\x1a\nfixture",
            "proof.wav": b"RIFF" + (16).to_bytes(4, "little") + b"WAVEfixture",
            "proof.mp4": b"\x00\x00\x00\x18ftypisomfixture",
        }
        observed = {}
        for name, payload in fixtures.items():
            path = self.root / name
            path.write_bytes(payload)
            result = ingest_media(
                self.conn, project="demo", active_root=self.root, path=path
            )
            observed[name] = result["media_kind"]
        self.assertEqual(
            observed,
            {
                "proof.pdf": "pdf",
                "proof.png": "image",
                "proof.wav": "audio",
                "proof.mp4": "video",
            },
        )
        malformed = self.root / "fake.png"
        malformed.write_bytes(b"not-a-png")
        with self.assertRaises(ValueError):
            ingest_media(
                self.conn, project="demo", active_root=self.root, path=malformed
            )
        unknown = self.root / "proof.bin"
        unknown.write_bytes(b"opaque")
        with self.assertRaises(ValueError):
            ingest_media(
                self.conn, project="demo", active_root=self.root, path=unknown
            )

    def test_traversal_links_and_oversized_sources_fail_closed(self):
        outside = self.base / "outside.png"
        outside.write_bytes(b"\x89PNG\r\n\x1a\nproof")
        with self.assertRaises(PermissionError):
            ingest_media(
                self.conn, project="demo", active_root=self.root, path=outside
            )
        oversized = self._image("large.png")
        with self.assertRaises(ValueError):
            ingest_media(
                self.conn,
                project="demo",
                active_root=self.root,
                path=oversized,
                maximum_bytes=4,
            )
        linked = self.root / "linked.png"
        try:
            os.symlink(outside, linked)
        except (OSError, NotImplementedError):
            pass
        else:
            with self.assertRaises(PermissionError):
                ingest_media(
                    self.conn, project="demo", active_root=self.root, path=linked
                )
        hardlinked = self.root / "hardlinked.png"
        try:
            os.link(outside, hardlinked)
        except (OSError, NotImplementedError):
            pass
        else:
            with self.assertRaises(PermissionError):
                ingest_media(
                    self.conn, project="demo", active_root=self.root, path=hardlinked
                )

    def test_content_drift_is_reported_without_mutating_the_source_record(self):
        path = self._image()
        source = ingest_media(
            self.conn, project="demo", active_root=self.root, path=path
        )
        current = verify_multimodal_source(
            self.conn,
            project="demo",
            active_root=self.root,
            source_id=source["source_id"],
        )
        self.assertEqual(current["state"], "current")
        before = self.conn.total_changes
        path.write_bytes(b"\x89PNG\r\n\x1a\nchanged")
        changed = verify_multimodal_source(
            self.conn,
            project="demo",
            active_root=self.root,
            source_id=source["source_id"],
        )
        self.assertEqual(changed["state"], "changed")
        self.assertEqual(self.conn.total_changes, before)
    def test_evidence_listing_reports_total_and_truncation(self):
        for index in range(3):
            ingest_media(
                self.conn,
                project="demo",
                active_root=self.root,
                path=self._image(f"proof-{index}.png"),
            )
        result = list_multimodal_evidence(self.conn, project="demo", limit=2)
        self.assertEqual(result["count"], 3)
        self.assertEqual(len(result["items"]), 2)
        self.assertTrue(result["truncated"])


    def test_redaction_export_retention_and_deletion_are_governed(self):
        public_source = ingest_media(
            self.conn,
            project="demo",
            active_root=self.root,
            path=self._image("public.png"),
            privacy_class="public",
            sharing_policy="exportable",
        )
        private_source = ingest_media(
            self.conn,
            project="demo",
            active_root=self.root,
            path=self._image("private.png"),
            privacy_class="internal",
            sharing_policy="local-only",
        )
        derivation = add_derivation(
            self.conn,
            project="demo",
            source_id=private_source["source_id"],
            derivation_id="private-caption",
            method="operator-caption",
            text="Sensitive local interpretation",
            confidence=0.9,
            verification_status="verified",
            tool_identity="operator",
            actor_type="operator",
            actor_id="operator-fixture",
        )
        with self.assertRaises(PermissionError):
            add_derivation(
                self.conn, project="demo", source_id=public_source["source_id"],
                method="spoofed-caption", text="Pretend operator verification",
                confidence=0.9, verification_status="verified",
                tool_identity="operator",
            )
        with self.assertRaises(PermissionError):
            redact_derivation(
                self.conn,
                project="demo",
                active_root=self.root,
                derivation_id=derivation["derivation_id"],
                reason="privacy request",
                actor_type="agent",
                actor_id="agent-1",
            )
        redacted = redact_derivation(
            self.conn,
            project="demo",
            active_root=self.root,
            derivation_id=derivation["derivation_id"],
            reason="privacy request",
            actor_type="operator",
            actor_id="operator-fixture",
        )
        self.assertTrue(redacted["redacted"])
        derivations = list_multimodal_derivations(
            self.conn,
            project="demo",
            source_id=private_source["source_id"],
            include_text=True,
        )
        self.assertEqual(derivations["items"][0]["text"], "[redacted]")
        public_export = export_multimodal_manifest(
            self.conn, project="demo", audience="public"
        )
        self.assertEqual(public_export["included"], 1)
        self.assertEqual(public_export["redacted"], 1)
        self.assertEqual(public_export["items"][0]["source_id"], public_source["source_id"])
        self.assertNotIn("Sensitive local interpretation", str(public_export))

        set_media_retention(
            self.conn,
            project="demo",
            active_root=self.root,
            source_id=private_source["source_id"],
            retain_until="2026-01-01T00:00:00+00:00",
            actor_type="operator",
            actor_id="operator-fixture",
        )
        preview = purge_expired_media(
            self.conn,
            project="demo",
            active_root=self.root,
            now="2026-08-25T00:00:00+00:00",
            actor_type="operator",
            actor_id="operator-fixture",
            dry_run=True,
        )
        self.assertEqual(preview["eligible"], [private_source["source_id"]])
        purged = purge_expired_media(
            self.conn,
            project="demo",
            active_root=self.root,
            now="2026-08-25T00:00:00+00:00",
            actor_type="operator",
            actor_id="operator-fixture",
            dry_run=False,
        )
        self.assertEqual(purged["deleted"], [private_source["source_id"]])
        with self.assertRaises(PermissionError):
            delete_media(
                self.conn,
                project="demo",
                active_root=self.root,
                source_id=public_source["source_id"],
                reason="cleanup",
                actor_type="agent",
                actor_id="agent-1",
            )


if __name__ == "__main__":
    unittest.main()
