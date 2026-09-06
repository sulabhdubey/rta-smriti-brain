import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import rta_brain.review_bundle as review_bundle
from rta_brain.review_bundle import (
    normalize_evidence_references,
    write_review_bundle,
)


def _sealed_bundle(status: str = "ready") -> dict:
    body = {
        "schema": "rta-smriti.lifecycle-review/v1",
        "audience": "release-reviewer",
        "privacy_ceiling": "internal",
        "status": status,
        "health_axes": {},
        "evidence_reference_manifest": [],
        "redaction_manifest": [],
        "receipts": [],
    }
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return {**body, "bundle_digest": hashlib.sha256(encoded).hexdigest()}


def _leave_interrupted_transaction(base: Path) -> None:
    json_path = base.with_suffix(".json")
    markdown_path = base.with_suffix(".md")
    json_path.write_text("old-json\n", encoding="utf-8")
    markdown_path.write_text("old-markdown\n", encoding="utf-8")
    real_replace = os.replace
    json_replacements = 0
    markdown_failed = False

    def interrupt_publish_and_rollback(source, destination):
        nonlocal json_replacements, markdown_failed
        selected = Path(destination)
        if selected == markdown_path and not markdown_failed:
            markdown_failed = True
            raise OSError("second publish failed")
        if selected == json_path:
            json_replacements += 1
            if json_replacements > 1:
                raise OSError("rollback interrupted")
        return real_replace(source, destination)

    with patch(
        "rta_brain.review_bundle.os.replace",
        side_effect=interrupt_publish_and_rollback,
    ), unittest.TestCase().assertRaisesRegex(RuntimeError, "recovery"):
        write_review_bundle(_sealed_bundle("interrupted"), base)


class ReviewBundleTests(unittest.TestCase):
    def test_evidence_references_dedupe_only_exact_full_identity(self):
        first = {"kind": "receipt", "reference": "proof:one", "digest": "a" * 64}
        other_kind = {
            "kind": "snapshot",
            "reference": "proof:one",
            "digest": "a" * 64,
        }

        normalized = normalize_evidence_references([first, dict(first), other_kind])

        self.assertEqual(normalized, [first, other_kind])

    def test_evidence_references_reject_digest_conflict_for_same_identity(self):
        with self.assertRaisesRegex(ValueError, "conflicting.*digest"):
            normalize_evidence_references(
                [
                    {
                        "kind": "receipt",
                        "reference": "proof:one",
                        "digest": "a" * 64,
                    },
                    {
                        "kind": "receipt",
                        "reference": "proof:one",
                        "digest": "b" * 64,
                    },
                ]
            )

    def test_second_format_publish_failure_rolls_back_the_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / "review"
            json_path = base.with_suffix(".json")
            markdown_path = base.with_suffix(".md")
            json_path.write_text("old-json\n", encoding="utf-8")
            markdown_path.write_text("old-markdown\n", encoding="utf-8")
            real_replace = os.replace
            markdown_failed = False

            def fail_markdown_publish(source, destination):
                nonlocal markdown_failed
                if Path(destination) == markdown_path and not markdown_failed:
                    markdown_failed = True
                    raise OSError("second publish failed")
                return real_replace(source, destination)

            with patch(
                "rta_brain.review_bundle.os.replace",
                side_effect=fail_markdown_publish,
            ), self.assertRaisesRegex(OSError, "second publish failed"):
                write_review_bundle(_sealed_bundle(), base)

            self.assertEqual(json_path.read_text(encoding="utf-8"), "old-json\n")
            self.assertEqual(
                markdown_path.read_text(encoding="utf-8"), "old-markdown\n"
            )
            self.assertEqual(
                sorted(path.name for path in base.parent.iterdir()),
                ["review.json", "review.md"],
            )

    def test_second_format_failure_removes_new_first_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / "review"
            markdown_path = base.with_suffix(".md")
            real_replace = os.replace
            markdown_failed = False

            def fail_markdown_publish(source, destination):
                nonlocal markdown_failed
                if Path(destination) == markdown_path and not markdown_failed:
                    markdown_failed = True
                    raise OSError("second publish failed")
                return real_replace(source, destination)

            with patch(
                "rta_brain.review_bundle.os.replace",
                side_effect=fail_markdown_publish,
            ), self.assertRaisesRegex(OSError, "second publish failed"):
                write_review_bundle(_sealed_bundle(), base)

            self.assertEqual(list(base.parent.iterdir()), [])

    def test_interrupted_rollback_is_recovered_before_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / "review"
            json_path = base.with_suffix(".json")
            markdown_path = base.with_suffix(".md")
            json_path.write_text("old-json\n", encoding="utf-8")
            markdown_path.write_text("old-markdown\n", encoding="utf-8")
            real_replace = os.replace
            json_replacements = 0
            markdown_failed = False

            def interrupt_publish_and_rollback(source, destination):
                nonlocal json_replacements, markdown_failed
                selected = Path(destination)
                if selected == markdown_path and not markdown_failed:
                    markdown_failed = True
                    raise OSError("second publish failed")
                if selected == json_path:
                    json_replacements += 1
                    if json_replacements > 1:
                        raise OSError("rollback interrupted")
                return real_replace(source, destination)

            with patch(
                "rta_brain.review_bundle.os.replace",
                side_effect=interrupt_publish_and_rollback,
            ), self.assertRaisesRegex(RuntimeError, "recovery"):
                write_review_bundle(_sealed_bundle("first-attempt"), base)

            result = write_review_bundle(_sealed_bundle("retry-ready"), base)
            exported = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertEqual(result["status"], "ok")
            self.assertEqual(exported["status"], "retry-ready")
            self.assertIn("`retry-ready`", markdown)
            self.assertEqual(
                sorted(path.name for path in base.parent.iterdir()),
                ["review.json", "review.md"],
            )

    def test_forged_committed_journal_cannot_delete_an_unrelated_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / "review"
            victim = base.parent / "keep-me.txt"
            victim.write_text("keep me\n", encoding="utf-8")
            journal = base.with_name(
                f".{base.name}.review-bundle-transaction.json"
            )
            journal.write_text(
                json.dumps(
                    {
                        "schema": "rta-smriti.review-bundle-transaction/v1",
                        "phase": "committed",
                        "entries": [
                            {
                                "target": "review.json",
                                "staged": victim.name,
                                "backup": None,
                                "existed": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PermissionError, "journal.*invalid"):
                write_review_bundle(_sealed_bundle(), base)

            self.assertEqual(victim.read_text(encoding="utf-8"), "keep me\n")
            self.assertTrue(journal.exists())

    def test_forged_prepared_journal_cannot_replace_from_or_delete_a_sibling(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / "review"
            target = base.with_suffix(".json")
            target.write_text("original\n", encoding="utf-8")
            victim = base.parent / "keep-me.txt"
            victim.write_text("forged replacement\n", encoding="utf-8")
            staged = base.parent / "forged-stage.txt"
            staged.write_text("staged\n", encoding="utf-8")
            journal = base.with_name(
                f".{base.name}.review-bundle-transaction.json"
            )
            journal.write_text(
                json.dumps(
                    {
                        "schema": "rta-smriti.review-bundle-transaction/v1",
                        "phase": "prepared",
                        "entries": [
                            {
                                "target": target.name,
                                "staged": staged.name,
                                "backup": victim.name,
                                "existed": True,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PermissionError, "journal.*invalid"):
                review_bundle._recover_transaction(base)

            self.assertEqual(target.read_text(encoding="utf-8"), "original\n")
            self.assertEqual(
                victim.read_text(encoding="utf-8"), "forged replacement\n"
            )
            self.assertEqual(staged.read_text(encoding="utf-8"), "staged\n")
            self.assertTrue(journal.exists())

    def test_unclaimed_transaction_artifacts_fail_before_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / "review"
            transaction_dir = base.with_name(
                f".{base.name}.review-bundle-transaction"
            )
            transaction_dir.mkdir()
            unexpected = transaction_dir / "keep-me.txt"
            unexpected.write_text("keep me\n", encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "transaction.*invalid"):
                write_review_bundle(_sealed_bundle(), base)

            self.assertEqual(
                unexpected.read_text(encoding="utf-8"), "keep me\n"
            )
            self.assertFalse(base.with_suffix(".json").exists())
            self.assertFalse(base.with_suffix(".md").exists())

    def test_tampered_recovery_journal_is_rejected_without_cleanup_or_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / "review"
            _leave_interrupted_transaction(base)
            journal = review_bundle._transaction_path(base)
            before_json = base.with_suffix(".json").read_bytes()
            before_markdown = base.with_suffix(".md").read_bytes()
            payload = json.loads(journal.read_text(encoding="utf-8"))
            payload["phase"] = "committed"
            journal.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "journal.*invalid"):
                review_bundle._recover_transaction(base)

            self.assertEqual(base.with_suffix(".json").read_bytes(), before_json)
            self.assertEqual(base.with_suffix(".md").read_bytes(), before_markdown)
            self.assertTrue(journal.exists())

    def test_tampered_rollback_backup_is_rejected_before_target_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / "review"
            _leave_interrupted_transaction(base)
            journal = review_bundle._transaction_path(base)
            payload = json.loads(journal.read_text(encoding="utf-8"))
            transaction_dir = review_bundle._transaction_directory(base)
            backup_name = next(
                item["backup"] for item in payload["entries"] if item["backup"]
            )
            backup = transaction_dir / backup_name
            backup.write_text("tampered rollback bytes\n", encoding="utf-8")
            before_json = base.with_suffix(".json").read_bytes()
            before_markdown = base.with_suffix(".md").read_bytes()

            with self.assertRaisesRegex(PermissionError, "artifact.*invalid"):
                review_bundle._recover_transaction(base)

            self.assertEqual(base.with_suffix(".json").read_bytes(), before_json)
            self.assertEqual(base.with_suffix(".md").read_bytes(), before_markdown)

    def test_recovery_revalidates_private_transaction_directory_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve() / "review"
            _leave_interrupted_transaction(base)
            real_prepare = review_bundle.prepare_control_dir

            with patch.object(
                review_bundle,
                "prepare_control_dir",
                wraps=real_prepare,
            ) as prepare:
                review_bundle._recover_transaction(base)

            prepare.assert_any_call(
                review_bundle._transaction_directory(base),
                label="review-bundle transaction",
            )


if __name__ == "__main__":
    unittest.main()
