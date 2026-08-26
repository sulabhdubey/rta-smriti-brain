import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


class CaptureSpoolTests(unittest.TestCase):
    def test_claim_next_does_not_materialize_or_sort_the_whole_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            self._publish(spool, "source-1", {"cursor": "1"})

            with mock.patch(
                "rta_brain.capture_spool.sorted",
                side_effect=AssertionError("queue sorting is unbounded"),
                create=True,
            ):
                claim = spool.claim_next("source-1")

            self.assertIsNotNone(claim)

    def test_usage_reader_tolerates_a_short_atomic_refresh_burst_but_remains_bounded(self):
        from rta_brain.capture_spool import SpoolUnsafeError, read_capture_spool_usage

        expected = {"total_records": 4, "total_bytes": 128, "source_count": 1}
        transient = SpoolUnsafeError(
            "capture spool usage receipt changed during inspection"
        )
        with (
            mock.patch(
                "rta_brain.capture_spool._read_capture_spool_usage_once",
                side_effect=[transient, transient, transient, transient, expected],
            ) as read_once,
            mock.patch("rta_brain.capture_spool.time.sleep"),
        ):
            self.assertEqual(read_capture_spool_usage(Path("brain.sqlite")), expected)
            self.assertEqual(read_once.call_count, 5)

        with (
            mock.patch(
                "rta_brain.capture_spool._read_capture_spool_usage_once",
                side_effect=transient,
            ) as read_once,
            mock.patch("rta_brain.capture_spool.time.sleep"),
        ):
            with self.assertRaisesRegex(SpoolUnsafeError, "changed during inspection"):
                read_capture_spool_usage(Path("brain.sqlite"))
            self.assertEqual(read_once.call_count, 8)

        with mock.patch(
            "rta_brain.capture_spool._read_capture_spool_usage_once",
            side_effect=SpoolUnsafeError("capture spool usage directory is unsafe"),
        ) as read_once:
            with self.assertRaisesRegex(SpoolUnsafeError, "directory is unsafe"):
                read_capture_spool_usage(Path("brain.sqlite"))
            self.assertEqual(read_once.call_count, 1)

    def _spool(self, tmp, **limits):
        from rta_brain.capture_spool import CaptureSpool, SpoolLimits

        return CaptureSpool(
            Path(tmp) / "brain.sqlite",
            limits=SpoolLimits(**limits),
        )

    @staticmethod
    def _publish(spool, source_id, record):
        return spool.publish(
            source_id,
            record,
            allowed_fields=frozenset(record),
        )

    def test_source_layout_is_private_and_uses_privacy_safe_token(self):
        from rta_brain.capture_spool import source_token

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            paths = spool.ensure_source("private-project/session-one")
            token = source_token("private-project/session-one")
            self.assertRegex(token, r"^[0-9a-f]{32}$")
            self.assertNotIn("private-project", paths["root"].parts)
            self.assertNotIn("session-one", paths["root"].parts)
            self.assertEqual(paths["root"].name, token)
            for name in ("inbox", "processing", "quarantine", "receipts"):
                self.assertTrue(paths[name].is_dir())
                self.assertFalse(paths[name].is_symlink())
            if os.name != "nt":
                self.assertEqual(paths["root"].stat().st_mode & 0o077, 0)

    def test_sibling_brains_use_isolated_spool_namespaces(self):
        from rta_brain.capture_spool import CaptureSpool

        with tempfile.TemporaryDirectory() as tmp:
            first = CaptureSpool(Path(tmp) / "first.sqlite")
            second = CaptureSpool(Path(tmp) / "second.sqlite")

            self.assertNotEqual(first.root, second.root)
            stored = self._publish(first, "shared-source", {"sequence": 1})
            self.assertEqual(stored.status, "stored")
            self.assertIsNone(second.claim_next("shared-source"))
            self.assertIsNotNone(first.claim_next("shared-source"))

    def test_shared_source_ids_are_isolated_by_project(self):
        from rta_brain.capture_spool import read_capture_spool_usage, source_token

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)

            first = spool.publish(
                "shared-source",
                {"sequence": 1},
                project="project-a",
                allowed_fields={"sequence"},
            )
            second = spool.publish(
                "shared-source",
                {"sequence": 2},
                project="project-b",
                allowed_fields={"sequence"},
            )

            self.assertEqual(first.status, "stored")
            self.assertEqual(second.status, "stored")
            self.assertNotEqual(
                source_token("shared-source", project="project-a"),
                source_token("shared-source", project="project-b"),
            )
            self.assertEqual(
                spool.claim_next("shared-source", project="project-a").payload,
                {"sequence": 1},
            )
            self.assertEqual(
                spool.claim_next("shared-source", project="project-b").payload,
                {"sequence": 2},
            )

            first_token = source_token("shared-source", project="project-a")
            usage = read_capture_spool_usage(
                Path(tmp) / "brain.sqlite",
                source_tokens={first_token},
            )
            self.assertEqual(usage["total_records"], 1)
            self.assertEqual(usage["source_count"], 1)
            self.assertEqual(usage["total_bytes"], first.stored_bytes)

    def test_scoped_usage_rejects_invalid_source_tokens(self):
        from rta_brain.capture_spool import read_capture_spool_usage

        with self.assertRaisesRegex(ValueError, "source tokens are invalid"):
            read_capture_spool_usage(
                Path("brain.sqlite"),
                source_tokens={"not-a-source-token"},
            )

    def test_publish_is_canonical_atomic_and_leaves_no_partial_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            receipt = self._publish(spool, "source-1", {"z": 1, "a": {"b": True}})
            self.assertEqual(receipt.status, "stored")
            paths = spool.ensure_source("source-1")
            records = list(paths["inbox"].glob("*.json"))
            self.assertEqual(len(records), 1)
            self.assertEqual(
                records[0].read_bytes(),
                b'{"a":{"b":true},"z":1}\n',
            )
            self.assertEqual(list(paths["inbox"].glob("*.tmp")), [])
            usage = json.loads((spool.root / "usage.json").read_text(encoding="utf-8"))
            self.assertEqual(usage["pending"], {})

    def test_publish_returns_bounded_receipts_for_record_and_source_budgets(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(
                tmp,
                max_record_bytes=40,
                max_source_bytes=80,
                max_source_records=1,
                max_total_bytes=80,
                max_total_records=1,
            )
            too_large = self._publish(spool, "source-1", {"text": "x" * 100})
            self.assertEqual((too_large.status, too_large.reason), ("rejected", "record_too_large"))
            first = self._publish(spool, "source-1", {"text": "ok"})
            full = self._publish(spool, "source-1", {"text": "again"})
            self.assertEqual(first.status, "stored")
            self.assertEqual((full.status, full.reason), ("full", "source_record_budget"))
            self.assertLessEqual(len(json.dumps(full.as_dict())), 512)

    def test_claim_complete_is_stable_and_writes_content_free_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            published = self._publish(spool, "source-1", {"secret": "redacted", "sequence": 1})
            claim = spool.claim_next("source-1")
            self.assertIsNotNone(claim)
            self.assertEqual(claim.record_id, published.record_id)
            self.assertEqual(claim.payload["sequence"], 1)
            receipt = spool.complete(claim)
            self.assertEqual(receipt.status, "complete")
            self.assertFalse(claim.path.exists())
            receipt_payload = json.loads(receipt.path.read_text(encoding="utf-8"))
            self.assertNotIn("secret", json.dumps(receipt_payload))
            self.assertEqual(receipt_payload["record_id"], published.record_id)

    def test_malformed_record_is_quarantined_without_payload_echo(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            paths = spool.ensure_source("source-1")
            bad = paths["inbox"] / ("a" * 32 + ".json")
            bad.write_bytes(b"\xffnot-json")
            self.assertIsNone(spool.claim_next("source-1"))
            quarantined = list(paths["quarantine"].glob("*.json"))
            self.assertEqual(len(quarantined), 1)
            diagnostics = list(paths["receipts"].glob("*.json"))
            self.assertTrue(diagnostics)
            self.assertNotIn("not-json", diagnostics[-1].read_text(encoding="utf-8"))

    def test_abandoned_processing_record_recovers_after_identity_and_age_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            self._publish(spool, "source-1", {"sequence": 1})
            claim = spool.claim_next("source-1")
            old = time.time() - 600
            os.utime(claim.path, (old, old))
            result = spool.recover_abandoned("source-1", older_than_seconds=60)
            self.assertEqual(result.recovered, 1)
            self.assertFalse(claim.path.exists())
            self.assertIsNotNone(spool.claim_next("source-1"))

    def test_linked_records_and_source_directories_are_rejected(self):
        from rta_brain.capture_spool import SpoolUnsafeError

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            paths = spool.ensure_source("source-1")
            target = Path(tmp) / "target.json"
            target.write_text("{}", encoding="utf-8")
            linked = paths["inbox"] / ("b" * 32 + ".json")
            try:
                os.link(target, linked)
            except OSError:
                self.skipTest("hardlinks unavailable")
            with self.assertRaises(SpoolUnsafeError):
                spool.claim_next("source-1")

    def test_publish_rejects_excessive_json_depth_and_cross_filesystem_move(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            nested = {}
            cursor = nested
            for _ in range(1_100):
                cursor["child"] = {}
                cursor = cursor["child"]
            with self.assertRaisesRegex(ValueError, "depth"):
                spool.publish_strict("source-1", nested, allowed_fields={"child"})
            with mock.patch(
                "rta_brain.capture_spool._replace_path",
                side_effect=OSError(errno.EXDEV, "cross-device link"),
            ):
                receipt = self._publish(spool, "source-1", {"sequence": 2})
                self.assertEqual(
                    (receipt.status, receipt.reason),
                    ("unavailable", "filesystem_unavailable"),
                )
            paths = spool.ensure_source("source-1")
            self.assertEqual(list(paths["inbox"].glob("*.tmp")), [])

    def test_claim_detects_same_stat_content_tampering_before_completion(self):
        from rta_brain.capture_spool import SpoolUnsafeError

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            self._publish(spool, "source-1", {"value": "one"})
            claim = spool.claim_next("source-1")
            before = claim.path.stat()
            original = claim.path.read_bytes()
            replacement = original.replace(b"one", b"two")
            self.assertEqual(len(original), len(replacement))
            claim.path.write_bytes(replacement)
            os.utime(claim.path, ns=(before.st_atime_ns, before.st_mtime_ns))
            with self.assertRaisesRegex(SpoolUnsafeError, "changed"):
                spool.complete(claim)

    def test_duplicate_processing_name_does_not_overwrite_claim(self):
        from rta_brain.capture_spool import SpoolUnsafeError

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            published = self._publish(spool, "source-1", {"value": 1})
            paths = spool.ensure_source("source-1")
            duplicate = paths["processing"] / f"{published.record_id}.json"
            duplicate.write_text('{"existing":true}\n', encoding="utf-8")
            with self.assertRaisesRegex(SpoolUnsafeError, "duplicate"):
                spool.claim_next("source-1")
            self.assertEqual(duplicate.read_text(encoding="utf-8"), '{"existing":true}\n')

    def test_unsafe_record_name_is_quarantined(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            paths = spool.ensure_source("source-1")
            unsafe = paths["inbox"] / "project-name.json"
            unsafe.write_text("{}\n", encoding="utf-8")
            self.assertIsNone(spool.claim_next("source-1"))
            self.assertFalse(unsafe.exists())
            self.assertEqual(len(list(paths["quarantine"].glob("*.json"))), 1)

    def test_source_directory_substitution_is_rejected(self):
        from rta_brain.capture_spool import SpoolUnsafeError

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            paths = spool.ensure_source("source-1")
            target = Path(tmp) / "outside"
            target.mkdir()
            paths["inbox"].rmdir()
            try:
                paths["inbox"].symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks unavailable")
            with self.assertRaises(SpoolUnsafeError):
                spool.ensure_source("source-1")

    @unittest.skipIf(os.name == "nt", "POSIX permission contract")
    def test_existing_world_readable_source_directory_is_rejected(self):
        from rta_brain.capture_spool import SpoolUnsafeError

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            paths = spool.ensure_source("source-1")
            paths["processing"].chmod(0o755)
            with self.assertRaisesRegex(SpoolUnsafeError, "not private"):
                spool.ensure_source("source-1")

    @unittest.skipUnless(os.name == "nt", "Windows ACL contract")
    def test_windows_spool_directories_and_records_have_private_acls(self):
        from rta_brain.capture_spool import (
            _windows_current_user_sid,
            windows_path_is_private,
        )

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            paths = spool.ensure_source("source-1")
            receipt = self._publish(spool, "source-1", {"sequence": 1})
            record = paths["inbox"] / f"{receipt.record_id}.json"
            self.assertTrue(windows_path_is_private(spool.root))
            self.assertTrue(windows_path_is_private(paths["inbox"]))
            self.assertTrue(windows_path_is_private(record))
            foreign_owner = (
                "O:S-1-5-18D:PAI"
                f"(A;OICI;FA;;;{_windows_current_user_sid()})"
                "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
            )
            with mock.patch(
                "rta_brain.capture_spool._windows_security_descriptor",
                return_value=foreign_owner,
            ):
                self.assertFalse(windows_path_is_private(paths["inbox"]))

    def test_cleanup_removes_only_old_safe_temporary_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            paths = spool.ensure_source("source-1")
            old = paths["inbox"] / ".old.tmp"
            fresh = paths["inbox"] / ".fresh.tmp"
            old.write_text("partial", encoding="utf-8")
            fresh.write_text("partial", encoding="utf-8")
            old_time = time.time() - 600
            os.utime(old, (old_time, old_time))
            removed = spool.cleanup_temporary("source-1", older_than_seconds=60)
            self.assertEqual(removed, 1)
            self.assertFalse(old.exists())
            self.assertTrue(fresh.exists())

    def test_cold_spool_uses_persisted_usage_without_full_rescan(self):
        from rta_brain.capture_spool import CaptureSpool

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp, max_source_records=100, max_total_records=100)
            for sequence in range(50):
                self.assertEqual(
                    self._publish(spool, "source-1", {"sequence": sequence}).status,
                    "stored",
                )
            with mock.patch.object(
                CaptureSpool,
                "_scan_usage",
                side_effect=AssertionError("cold publish rescanned the spool"),
            ):
                cold = self._spool(tmp, max_source_records=100, max_total_records=100)
                self.assertEqual(
                    self._publish(cold, "source-1", {"sequence": 51}).status,
                    "stored",
                )

    def test_missing_reserved_record_is_reconciled_without_budget_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(
                tmp,
                max_source_records=1,
                max_total_records=1,
            )
            paths = spool.ensure_source("source-1")
            token = paths["root"].name
            usage_path = spool.root / "usage.json"
            usage = json.loads(usage_path.read_text(encoding="utf-8"))
            usage["sources"][token] = {
                "records": 1,
                "bytes": 20,
                "inbox_mtime_ns": paths["inbox"].stat().st_mtime_ns,
                "processing_mtime_ns": paths["processing"].stat().st_mtime_ns,
            }
            usage["total_records"] = 1
            usage["total_bytes"] = 20
            usage["pending"]["f" * 32] = {
                "operation": "add",
                "source_token": token,
                "bytes": 20,
            }
            usage_path.write_text(
                json.dumps(usage, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            recovered = self._spool(
                tmp,
                max_source_records=1,
                max_total_records=1,
            )
            receipt = self._publish(recovered, "source-1", {"sequence": 1})
            self.assertEqual(receipt.status, "stored")

    def test_claim_complete_and_recovery_keep_cold_usage_accounting_current(self):
        from rta_brain.capture_spool import CaptureSpool

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp, max_source_records=2, max_total_records=2)
            self._publish(spool, "source-1", {"sequence": 1})
            self._publish(spool, "source-1", {"sequence": 2})
            claim = spool.claim_next("source-1")
            old = time.time() - 600
            os.utime(claim.path, (old, old))
            spool.recover_abandoned("source-1", older_than_seconds=60)
            claim = spool.claim_next("source-1")
            spool.complete(claim)
            with mock.patch.object(
                CaptureSpool,
                "_scan_source_usage",
                side_effect=AssertionError("cold publish rescanned after lifecycle mutation"),
            ):
                cold = self._spool(tmp, max_source_records=2, max_total_records=2)
                self.assertEqual(
                    self._publish(cold, "source-1", {"sequence": 3}).status,
                    "stored",
                )

    def test_publish_allowlists_before_redacting_nested_sensitive_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            missing = spool.publish("source-1", {"message": "hello"})
            self.assertEqual(
                (missing.status, missing.reason),
                ("rejected", "invalid_record"),
            )
            receipt = spool.publish(
                "source-1",
                {
                    "message": "token sk-abcdefghijklmnopqrstuvwxyz123456",
                    "metadata": {"authorization": "Bearer abcdefghijklmnop"},
                    "not_allowed": "must not persist",
                },
                allowed_fields={"message", "metadata"},
            )
            self.assertEqual(receipt.status, "stored")
            claim = spool.claim_next("source-1")
            self.assertNotIn("not_allowed", claim.payload)
            self.assertNotIn("sk-", claim.payload["message"])
            self.assertEqual(claim.payload["metadata"]["authorization"], "[REDACTED]")

    def test_publish_redacts_nested_credential_shaped_keys_and_rejects_collisions(self):
        sensitive_key = "Authorization: Bearer synthetic-spool-secret-123456"
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            stored = spool.publish(
                "source-1",
                {"metadata": {sensitive_key: "safe"}},
                allowed_fields={"metadata"},
            )
            self.assertEqual(stored.status, "stored")
            claim = spool.claim_next("source-1")
            self.assertEqual(claim.payload, {"metadata": {"[REDACTED]": "safe"}})
            self.assertNotIn("synthetic-spool-secret", claim.path.read_text(encoding="utf-8"))

            collision = spool.publish(
                "source-1",
                {"metadata": {sensitive_key: "first", "[REDACTED]": "second"}},
                allowed_fields={"metadata"},
            )
            self.assertEqual((collision.status, collision.reason), ("rejected", "invalid_record"))

    def test_abandoned_recovery_is_batch_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            claims = []
            for sequence in range(3):
                self._publish(spool, "source-1", {"sequence": sequence})
                claims.append(spool.claim_next("source-1"))
            old = time.time() - 600
            for claim in claims:
                os.utime(claim.path, (old, old))
            result = spool.recover_abandoned(
                "source-1",
                older_than_seconds=60,
                max_records=1,
                max_seconds=1.0,
            )
            self.assertEqual(result.recovered, 1)
            self.assertTrue(result.limited)
            paths = spool.ensure_source("source-1")
            self.assertEqual(len(list(paths["processing"].glob("*.json"))), 2)

    def test_quarantine_budget_prevents_auxiliary_disk_growth(self):
        from rta_brain.capture_spool import SpoolUnsafeError

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(
                tmp,
                max_quarantine_records=1,
                max_quarantine_bytes=1_024,
                max_receipt_records=2,
                max_receipt_bytes=2_048,
            )
            paths = spool.ensure_source("source-1")
            for name in ("a" * 32 + ".json", "b" * 32 + ".json"):
                (paths["inbox"] / name).write_bytes(b"not-json")
            with self.assertRaisesRegex(SpoolUnsafeError, "quarantine budget"):
                spool.claim_next("source-1")
            self.assertEqual(len(list(paths["quarantine"].glob("*.json"))), 1)

    def test_completed_receipts_retire_oldest_and_preserve_recent_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(
                tmp,
                max_receipt_records=2,
                max_receipt_bytes=2_048,
            )
            receipts = []
            for sequence in range(1, 4):
                self._publish(spool, "source-1", {"sequence": sequence})
                receipts.append(spool.complete(spool.claim_next("source-1")))
                if sequence < 3:
                    timestamp = time.time() - (10 - sequence)
                    os.utime(receipts[-1].path, (timestamp, timestamp))

            self.assertFalse(receipts[0].path.exists())
            self.assertTrue(receipts[1].path.exists())
            self.assertTrue(receipts[2].path.exists())
            self.assertEqual(
                len(list(receipts[2].path.parent.glob("*.json"))),
                2,
            )

    def test_completed_receipts_retire_for_byte_capacity(self):
        from rta_brain.capture_spool import CaptureSpool, SpoolLimits

        with tempfile.TemporaryDirectory() as tmp:
            probe = CaptureSpool(Path(tmp) / "probe.sqlite")
            self._publish(probe, "source-1", {"sequence": 1})
            receipt_size = probe.complete(probe.claim_next("source-1")).path.stat().st_size

            spool = CaptureSpool(
                Path(tmp) / "bounded.sqlite",
                limits=SpoolLimits(
                    max_receipt_records=10,
                    max_receipt_bytes=receipt_size * 2,
                ),
            )
            receipts = []
            for sequence in range(1, 4):
                self._publish(spool, "source-1", {"sequence": sequence})
                receipts.append(spool.complete(spool.claim_next("source-1")))
                if sequence < 3:
                    timestamp = time.time() - (10 - sequence)
                    os.utime(receipts[-1].path, (timestamp, timestamp))

            self.assertFalse(receipts[0].path.exists())
            self.assertTrue(receipts[1].path.exists())
            self.assertTrue(receipts[2].path.exists())

    def test_completion_replays_an_already_durable_current_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(
                tmp,
                max_receipt_records=1,
                max_receipt_bytes=1_024,
            )
            published = self._publish(spool, "source-1", {"sequence": 1})
            claim = spool.claim_next("source-1")
            receipt_path = spool.ensure_source("source-1")["receipts"] / (
                f"{published.record_id}.json"
            )
            receipt_path.write_text(
                json.dumps(
                    {
                        "record_id": published.record_id,
                        "source_token": claim.source_token,
                        "status": "complete",
                    }
                )
                + "\n",
                encoding="ascii",
            )

            replayed = spool.complete(claim)

            self.assertEqual(replayed.path, receipt_path)
            self.assertTrue(receipt_path.exists())
            self.assertFalse(claim.path.exists())

    def test_disposition_receipt_failure_preserves_the_active_record(self):
        from rta_brain import capture_spool

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            self._publish(spool, "source-1", {"sequence": 1})
            claim = spool.claim_next("source-1")
            original_write = capture_spool._atomic_write

            def fail_receipt(path, data, **kwargs):
                if path.parent.name == "receipts":
                    raise OSError(errno.ENOSPC, "disk full")
                return original_write(path, data, **kwargs)

            with mock.patch(
                "rta_brain.capture_spool._atomic_write",
                side_effect=fail_receipt,
            ), self.assertRaises(OSError):
                spool.complete(claim)
            self.assertTrue(claim.path.exists())

            with mock.patch(
                "rta_brain.capture_spool._atomic_write",
                side_effect=fail_receipt,
            ), self.assertRaises(OSError):
                spool.quarantine(claim, "test_failure")
            self.assertTrue(claim.path.exists())

    def test_stale_lock_metadata_cannot_wedge_a_new_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            lock_path = spool.root / ".usage.lock"
            lock_path.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "token": "a" * 32,
                        "created_ns": 1,
                    }
                ),
                encoding="utf-8",
            )
            old = time.time() - 600
            os.utime(lock_path, (old, old))
            receipt = self._publish(spool, "source-1", {"sequence": 1})
            self.assertEqual(receipt.status, "stored")

    def test_usage_lock_serializes_independent_processes(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain_path = Path(tmp) / "brain.sqlite"
            spool = self._spool(tmp)
            script = (
                "import sys,time\n"
                "from pathlib import Path\n"
                "from rta_brain.capture_spool import CaptureSpool\n"
                "spool=CaptureSpool(Path(sys.argv[1]))\n"
                "with spool._usage_lock(timeout_seconds=2.0):\n"
                " print('locked', flush=True)\n"
                " time.sleep(1.0)\n"
            )
            child = subprocess.Popen(
                [sys.executable, "-c", script, str(brain_path)],
                cwd=Path(__file__).resolve().parents[1],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(child.stdout.readline().strip(), "locked")
                blocked = self._publish(spool, "source-1", {"sequence": 1})
                self.assertEqual(
                    (blocked.status, blocked.reason),
                    ("unavailable", "spool_busy"),
                )
            finally:
                _, stderr = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertEqual(
                self._publish(spool, "source-1", {"sequence": 2}).status,
                "stored",
            )

    def test_source_and_auxiliary_budgets_are_global_across_sources(self):
        from rta_brain.capture_spool import SpoolUnsafeError

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(
                tmp,
                max_sources=2,
                max_source_records=1,
                max_total_records=1,
                max_receipt_records=1,
                max_receipt_bytes=1_024,
            )
            self.assertEqual(
                self._publish(spool, "source-1", {"sequence": 1}).status,
                "stored",
            )
            self.assertEqual(
                self._publish(spool, "source-2", {"sequence": 2}).status,
                "full",
            )
            first = spool.claim_next("source-1")
            spool.complete(first)
            self.assertEqual(
                self._publish(spool, "source-2", {"sequence": 3}).status,
                "stored",
            )
            second = spool.claim_next("source-2")
            second_receipt = spool.complete(second)
            self.assertTrue(second_receipt.path.exists())
            self.assertFalse(
                (
                    spool.ensure_source("source-1")["receipts"]
                    / f"{first.record_id}.json"
                ).exists()
            )
            with self.assertRaisesRegex(SpoolUnsafeError, "source budget"):
                spool.ensure_source("source-3")

    def test_state_json_reads_do_not_use_unbounded_path_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            with mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("unchecked pathname read"),
            ):
                state = spool._read_bounded_json(
                    spool.root / "usage.json",
                    max_bytes=2_097_152,
                )
            self.assertEqual(state["schema"], "rta-smriti.capture-usage/v1")

    def test_windows_sddl_accepts_administrators_as_private_owner(self):
        from rta_brain.capture_spool import _windows_sddl_is_private

        sid = "S-1-5-21-1000"
        alias_owner = f"O:BAD:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        canonical_owner = (
            "O:S-1-5-32-544D:P"
            f"(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        )
        self.assertTrue(_windows_sddl_is_private(alias_owner, sid))
        self.assertTrue(_windows_sddl_is_private(canonical_owner, sid))

    def test_windows_sddl_rejects_unrecognized_allow_ace_types(self):
        from rta_brain.capture_spool import _windows_sddl_is_private

        sid = "S-1-5-21-1000"
        safe = f"O:{sid}D:PAI(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        conditional_world = safe + "(XA;;FR;;;WD;(TRUE))"
        self.assertTrue(_windows_sddl_is_private(safe, sid))
        self.assertFalse(_windows_sddl_is_private(conditional_world, sid))

    @unittest.skipUnless(os.name == "nt", "Windows SDDL owner alias test")
    def test_windows_sddl_owner_alias_is_resolved_before_validation(self):
        from rta_brain import capture_spool

        sid = "S-1-5-21-1000"
        sddl = "O:LAD:P(A;;FA;;;LA)(A;;FA;;;SY)(A;;FA;;;BA)"
        with mock.patch.object(
            capture_spool,
            "_windows_sddl_alias_sid",
            return_value=sid,
        ) as resolve:
            self.assertTrue(capture_spool._windows_sddl_is_private(sddl, sid))
        self.assertEqual(resolve.call_args_list, [mock.call("LA"), mock.call("LA")])

    def test_windows_sddl_accepts_canonical_private_trustee_sids(self):
        from rta_brain.capture_spool import _windows_sddl_is_private

        sid = "S-1-5-21-1000"
        canonical = (
            f"O:{sid}D:P(A;;FA;;;{sid})"
            "(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-5-32-544)"
        )
        self.assertTrue(_windows_sddl_is_private(canonical, sid))

    def test_windows_foreign_allow_aliases_are_resolved_before_removal(self):
        from rta_brain import capture_spool

        current_sid = "S-1-5-21-1000"
        sddl = f"O:{current_sid}D:P(A;;FA;;;{current_sid})(A;;FA;;;CO)"
        with mock.patch.object(
            capture_spool,
            "_windows_sddl_alias_sid",
            return_value="S-1-3-0",
        ) as resolve:
            foreign = capture_spool._windows_foreign_allow_sids(
                sddl, current_sid
            )
        resolve.assert_called_once_with("CO")
        self.assertEqual(foreign, ("S-1-3-0",))

    @unittest.skipUnless(os.name == "nt", "Windows SDDL alias integration test")
    def test_windows_sddl_alias_resolver_handles_creator_owner(self):
        from rta_brain.capture_spool import _windows_sddl_alias_sid

        self.assertEqual(_windows_sddl_alias_sid("CO"), "S-1-3-0")

    @unittest.skipUnless(os.name == "nt", "Windows ACL hardening integration test")
    def test_windows_acl_hardening_handles_inherited_foreign_principals(self):
        from rta_brain.capture_spool import (
            ensure_windows_path_private,
            windows_path_is_private,
        )

        with tempfile.TemporaryDirectory() as tmp:
            control = Path(tmp) / "private-control"
            control.mkdir()

            ensure_windows_path_private(control)

            self.assertTrue(windows_path_is_private(control))

    @unittest.skipUnless(os.name == "nt", "Windows ACL sequencing test")
    def test_windows_acl_hardening_rechecks_after_removing_inheritance(self):
        from rta_brain import capture_spool

        sid = "S-1-5-21-1000"
        safe_after_inheritance = f"O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        events = []

        def inspect(_path):
            events.append("descriptor")
            return safe_after_inheritance

        def apply(arguments):
            if "/inheritance:r" in arguments:
                events.append("inheritance")
            elif "/setowner" in arguments:
                events.append("owner")
            else:
                events.append("grant")

        with mock.patch.object(
            capture_spool,
            "windows_path_is_private",
            side_effect=[False, True],
        ), mock.patch.object(
            capture_spool,
            "_windows_current_user_sid",
            return_value=sid,
        ), mock.patch.object(
            capture_spool,
            "_windows_security_descriptor",
            side_effect=inspect,
        ), mock.patch.object(
            capture_spool,
            "_run_icacls",
            side_effect=apply,
        ):
            capture_spool.ensure_windows_path_private(Path("private-control"))

        self.assertEqual(events[:3], ["descriptor", "inheritance", "descriptor"])

    @unittest.skipUnless(os.name == "nt", "Windows ACL ownership test")
    def test_windows_acl_hardening_sets_current_user_as_owner(self):
        from rta_brain import capture_spool

        sid = "S-1-5-21-1000"
        foreign = "O:S-1-5-18D:AI(A;;FA;;;SY)(A;;FA;;;BA)"
        safe = f"O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        calls = []
        with mock.patch.object(
            capture_spool,
            "windows_path_is_private",
            side_effect=[False, True],
        ), mock.patch.object(
            capture_spool,
            "_windows_current_user_sid",
            return_value=sid,
        ), mock.patch.object(
            capture_spool,
            "_windows_security_descriptor",
            side_effect=[foreign, safe, safe],
        ), mock.patch.object(
            capture_spool,
            "_run_icacls",
            side_effect=lambda arguments: calls.append(arguments),
        ):
            capture_spool.ensure_windows_path_private(Path("private-control"))

        self.assertIn(["private-control", "/setowner", f"*{sid}"], calls)

    @unittest.skipUnless(os.name == "nt", "Windows ACL ownership test")
    def test_windows_acl_hardening_does_not_reaffirm_current_owner(self):
        from rta_brain import capture_spool

        sid = "S-1-5-21-1000"
        inherited = f"O:{sid}D:AI(A;OICIID;FA;;;BA)(A;OICIID;FA;;;SY)(A;OICIID;0x1301bf;;;AU)"
        safe = f"O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        calls = []
        with mock.patch.object(
            capture_spool,
            "windows_path_is_private",
            return_value=False,
        ), mock.patch.object(
            capture_spool,
            "_windows_current_user_sid",
            return_value=sid,
        ), mock.patch.object(
            capture_spool,
            "_windows_security_descriptor",
            side_effect=[inherited, safe, safe],
        ), mock.patch.object(
            capture_spool,
            "_run_icacls",
            side_effect=lambda arguments: calls.append(arguments),
        ):
            capture_spool.ensure_windows_path_private(Path("private-control"))

        self.assertNotIn(["private-control", "/setowner", f"*{sid}"], calls)
        self.assertIn(["private-control", "/inheritance:r"], calls)

    @unittest.skipUnless(os.name == "nt", "Windows executable resolution test")
    def test_windows_acl_helpers_ignore_executables_in_adversarial_cwd(self):
        import ctypes
        from ctypes import wintypes

        from rta_brain import capture_spool

        buffer = ctypes.create_unicode_buffer(32_768)
        get_system_directory = ctypes.WinDLL(
            "kernel32", use_last_error=True
        ).GetSystemDirectoryW
        get_system_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        get_system_directory.restype = wintypes.UINT
        length = get_system_directory(buffer, len(buffer))
        self.assertGreater(length, 0)
        self.assertLess(length, len(buffer))
        system_directory = Path(buffer.value).resolve()

        with tempfile.TemporaryDirectory() as tmp:
            attacker_cwd = Path(tmp)
            decoy = system_directory / "where.exe"
            shutil.copy2(decoy, attacker_cwd / "whoami.exe")
            shutil.copy2(decoy, attacker_cwd / "icacls.exe")
            previous_cwd = Path.cwd()
            try:
                os.chdir(attacker_cwd)
                capture_spool._windows_current_user_sid.cache_clear()
                self.assertTrue(
                    capture_spool._windows_current_user_sid().startswith("S-1-")
                )
                with mock.patch.object(
                    capture_spool.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess([], 0, "", ""),
                ) as run:
                    capture_spool._run_icacls(["target"])
            finally:
                os.chdir(previous_cwd)
                capture_spool._windows_current_user_sid.cache_clear()

        executable = Path(run.call_args.args[0][0])
        self.assertTrue(executable.is_absolute())
        self.assertEqual(executable.resolve().parent, system_directory)
        self.assertEqual(executable.name.casefold(), "icacls.exe")

    def test_startup_recovers_old_root_atomic_write_temporaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            temporary = spool.root / (
                ".usage.json.1234." + "a" * 32 + ".tmp"
            )
            temporary.write_text("partial", encoding="utf-8")
            old = time.time() - 600
            os.utime(temporary, (old, old))
            (spool.root / "usage.json").unlink()
            recovered = self._spool(tmp)
            self.assertFalse(temporary.exists())
            self.assertTrue((recovered.root / "usage.json").is_file())

    def test_publish_contains_windows_acl_subprocess_timeouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            with mock.patch(
                "rta_brain.capture_spool._ensure_private_directory",
                side_effect=subprocess.TimeoutExpired("icacls.exe", 10),
            ):
                receipt = self._publish(spool, "source-1", {"sequence": 1})
            self.assertEqual(
                (receipt.status, receipt.reason),
                ("unavailable", "filesystem_unavailable"),
            )

    def test_post_commit_fsync_failures_reconcile_usage_from_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(
                tmp,
                max_source_records=1,
                max_total_records=1,
            )
            original_fsync = __import__(
                "rta_brain.capture_spool",
                fromlist=["_directory_fsync"],
            )._directory_fsync

            def fail_inbox(path):
                if path.name == "inbox":
                    raise OSError(errno.EIO, "post-rename fsync failed")
                return original_fsync(path)

            with mock.patch(
                "rta_brain.capture_spool._directory_fsync",
                side_effect=fail_inbox,
            ):
                first = self._publish(spool, "source-1", {"sequence": 1})
            self.assertEqual(first.status, "unavailable")
            self.assertEqual(
                self._publish(spool, "source-1", {"sequence": 2}).status,
                "full",
            )
            self.assertEqual(
                len(list(spool.ensure_source("source-1")["inbox"].glob("*.json"))),
                1,
            )

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(
                tmp,
                max_source_records=1,
                max_total_records=1,
            )
            self._publish(spool, "source-1", {"sequence": 1})
            claim = spool.claim_next("source-1")

            def fail_processing(path):
                if path.name == "processing":
                    raise OSError(errno.EIO, "post-unlink fsync failed")
                return original_fsync(path)

            with mock.patch(
                "rta_brain.capture_spool._directory_fsync",
                side_effect=fail_processing,
            ), self.assertRaises(OSError):
                spool.complete(claim)
            self.assertEqual(
                self._publish(spool, "source-1", {"sequence": 2}).status,
                "stored",
            )

    def test_claim_move_cannot_overwrite_a_racing_destination(self):
        from rta_brain import capture_spool
        from rta_brain.capture_spool import SpoolUnsafeError

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            published = self._publish(spool, "source-1", {"sequence": 1})
            paths = spool.ensure_source("source-1")
            destination = paths["processing"] / f"{published.record_id}.json"
            original_move = capture_spool._move_no_replace

            def race(source, target):
                target.write_text('{"racer":true}\n', encoding="utf-8")
                return original_move(source, target)

            with mock.patch(
                "rta_brain.capture_spool._move_no_replace",
                side_effect=race,
            ), self.assertRaisesRegex(SpoolUnsafeError, "duplicate"):
                spool.claim_next("source-1")
            self.assertEqual(destination.read_text(encoding="utf-8"), '{"racer":true}\n')

    def test_cross_directory_move_syncs_destination_before_source(self):
        from rta_brain import capture_spool

        source = Path("source") / "record.json"
        destination = Path("destination") / "record.json"
        barriers = []
        with mock.patch("rta_brain.capture_spool._replace_path") as replace, mock.patch(
            "rta_brain.capture_spool._directory_fsync",
            side_effect=lambda path: barriers.append(path),
        ):
            capture_spool._move_no_replace(source, destination)

        replace.assert_called_once_with(source, destination, replace=False)
        self.assertEqual(barriers, [destination.parent, source.parent])

    @unittest.skipIf(os.name == "nt", "POSIX hard-link crash recovery")
    def test_claim_recovers_interrupted_legacy_hard_link_move(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            published = self._publish(spool, "source-1", {"sequence": 1})
            paths = spool.ensure_source("source-1")
            inbox = paths["inbox"] / f"{published.record_id}.json"
            processing = paths["processing"] / inbox.name
            os.link(inbox, processing, follow_symlinks=False)

            claim = spool.claim_next("source-1")

            self.assertEqual(claim.record_id, published.record_id)
            self.assertFalse(inbox.exists())
            self.assertTrue(processing.is_file())
            self.assertEqual(processing.stat().st_nlink, 1)

    @unittest.skipIf(os.name == "nt", "POSIX hard-link crash recovery")
    def test_recovery_finishes_interrupted_legacy_quarantine_move(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            self._publish(spool, "source-1", {"sequence": 1})
            claim = spool.claim_next("source-1")
            paths = spool.ensure_source("source-1")
            quarantined = paths["quarantine"] / claim.path.name
            os.link(claim.path, quarantined, follow_symlinks=False)

            recovered = spool.recover_abandoned(
                "source-1",
                older_than_seconds=0,
                now=time.time() + 1,
            )

            self.assertEqual((recovered.recovered, recovered.quarantined), (0, 1))
            self.assertFalse(claim.path.exists())
            self.assertEqual(quarantined.stat().st_nlink, 1)
            usage = json.loads((spool.root / "usage.json").read_text(encoding="utf-8"))
            self.assertEqual(usage["total_records"], 0)

    def test_publish_crash_temporary_keeps_its_reservation_and_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            brain = Path(tmp) / "brain.sqlite"
            spool = self._spool(
                tmp,
                max_source_records=1,
                max_total_records=1,
            )
            child = "\n".join(
                [
                    "import os",
                    "from pathlib import Path",
                    "from rta_brain.capture_spool import CaptureSpool, SpoolLimits",
                    "import rta_brain.capture_spool as module",
                    f"spool = CaptureSpool(Path({str(brain)!r}), limits=SpoolLimits(max_source_records=1, max_total_records=1))",
                    "original = module._replace_path",
                    "def crash(source, destination, *, replace):",
                    "    if destination.parent.name == 'inbox':",
                    "        os._exit(73)",
                    "    return original(source, destination, replace=replace)",
                    "module._replace_path = crash",
                    "spool.publish_strict('source-1', {'sequence': 1}, allowed_fields={'sequence'})",
                ]
            )
            completed = subprocess.run(
                [sys.executable, "-c", child],
                cwd=Path(__file__).resolve().parents[1],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(completed.returncode, 73, completed.stderr)

            paths = spool.ensure_source("source-1")
            self.assertEqual(len(list(paths["inbox"].glob("*.tmp"))), 1)
            self.assertEqual(
                self._publish(spool, "source-1", {"sequence": 2}).status,
                "full",
            )
            usage = json.loads((spool.root / "usage.json").read_text(encoding="utf-8"))
            self.assertEqual((usage["total_records"], len(usage["pending"])), (1, 1))

    def test_abandoned_recovery_cannot_overwrite_a_racing_inbox_record(self):
        from rta_brain import capture_spool

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            self._publish(spool, "source-1", {"sequence": 1})
            claim = spool.claim_next("source-1")
            paths = spool.ensure_source("source-1")
            inbox = paths["inbox"] / claim.path.name
            original_move = capture_spool._move_no_replace

            def race(source, destination):
                if destination.parent.name == "inbox":
                    destination.write_text('{"racer":true}\n', encoding="utf-8")
                return original_move(source, destination)

            with mock.patch(
                "rta_brain.capture_spool._move_no_replace",
                side_effect=race,
            ):
                recovered = spool.recover_abandoned(
                    "source-1",
                    older_than_seconds=0,
                    now=time.time() + 1,
                )

            self.assertEqual((recovered.recovered, recovered.quarantined), (0, 1))
            self.assertEqual(inbox.read_text(encoding="utf-8"), '{"racer":true}\n')
            quarantined = list(paths["quarantine"].glob("*.json"))
            self.assertEqual(len(quarantined), 1)
            self.assertIn(b'"sequence":1', quarantined[0].read_bytes())

    def test_hard_crash_temporaries_count_toward_budgets_and_cleanup_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(
                tmp,
                max_source_records=2,
                max_total_records=2,
                max_record_bytes=1_024,
            )
            paths = spool.ensure_source("source-1")
            old = time.time() - 600
            for index in range(3):
                temporary = paths["inbox"] / (
                    f".{index:032x}.json.1234." + "a" * 32 + ".tmp"
                )
                temporary.write_bytes(b"x" * 100)
                os.utime(temporary, (old, old))
            removed = spool.cleanup_temporary(
                "source-1",
                older_than_seconds=60,
                max_records=1,
                max_seconds=1.0,
            )
            self.assertEqual(removed, 1)
            self.assertEqual(len(list(paths["inbox"].glob("*.tmp"))), 2)
            self.assertEqual(
                self._publish(spool, "source-1", {"sequence": 1}).status,
                "full",
            )

    @unittest.skipUnless(os.name == "nt", "Windows reparse contract")
    def test_windows_stable_read_does_not_follow_file_reparse_points(self):
        from rta_brain.capture_spool import SpoolUnsafeError

        with tempfile.TemporaryDirectory() as tmp:
            spool = self._spool(tmp)
            paths = spool.ensure_source("source-1")
            target = Path(tmp) / "target.json"
            target.write_text('{"private":true}\n', encoding="utf-8")
            linked = paths["inbox"] / ("c" * 32 + ".json")
            try:
                linked.symlink_to(target)
            except OSError:
                self.skipTest("file symlinks unavailable")
            with self.assertRaises(SpoolUnsafeError):
                spool._stable_read(linked)


if __name__ == "__main__":
    unittest.main()
