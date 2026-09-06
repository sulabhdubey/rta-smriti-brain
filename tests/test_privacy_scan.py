import hashlib
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rta_brain.privacy import find_sensitive_text, redact_sensitive_text
from scripts.privacy_scan import load_approved_media_digests, scan


ROOT = Path(__file__).resolve().parents[1]


class PrivacyScanTests(unittest.TestCase):
    def test_approved_svg_checkout_encodings_are_explicit(self):
        data = (ROOT / "launch-site" / "favicon.svg").read_bytes()
        lf = data.replace(b"\r\n", b"\n")
        crlf = lf.replace(b"\n", b"\r\n")
        approved = load_approved_media_digests(
            ROOT / "constraints" / "release-media.sha256"
        )

        self.assertEqual(
            {
                hashlib.sha256(lf).hexdigest(),
                hashlib.sha256(crlf).hexdigest(),
            }
            & approved,
            {
                hashlib.sha256(lf).hexdigest(),
                hashlib.sha256(crlf).hexdigest(),
            },
        )

    def test_missing_file_and_empty_release_roots_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            missing = parent / "missing"
            file_root = parent / "artifact.txt"
            file_root.write_text("artifact", encoding="utf-8")
            empty = parent / "empty"
            empty.mkdir()

            self.assertIn((".", "missing-release-root"), scan(missing, []))
            self.assertIn((".", "invalid-release-root"), scan(file_root, []))
            self.assertIn((".", "empty-release-root"), scan(empty, []))

    def test_privacy_scan_runs_as_a_direct_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / "README.md").write_text("# Public artifact\n", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(Path(__file__).parents[1] / "scripts" / "privacy_scan.py"), "--root", str(root)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shared_detector_covers_release_secret_and_generic_path_patterns(self):
        values = {
            "aws-access-key": "AK" + "IA" + "Q" * 16,
            "google-api-key": "AI" + "za" + "Q" * 35,
            "stripe-secret-key": "sk_" + "live_" + "Q" * 24,
            "private-key": "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nfixture",
            "jwt": ".".join(("eyJ" + "a" * 12, "b" * 12, "c" * 12)),
            "unc-path": "\\\\server\\share\\private\\file.txt",
            "windows-absolute-path": "D:" + "\\private\\workspace\\file.txt",
            # Keep this split so the repository privacy scan does not mistake
            # its own synthetic absolute-path fixture for private operator data.
            "posix-absolute-path": "/" + "/".join(  # noqa: FLY002
                ("srv", "private", "workspace", "file.txt")
            ),
        }
        findings = find_sensitive_text("\n".join(values.values()))
        labels = {finding.label for finding in findings}
        self.assertTrue(set(values).issubset(labels))

    def test_shared_detector_covers_root_level_absolute_paths(self):
        values = {
            "windows-absolute-path": "C:" + "\\PrivateRoot",
            "posix-absolute-path": "/secret.txt",
        }
        findings = find_sensitive_text("\n".join(values.values()))
        labels = {finding.label for finding in findings}
        self.assertTrue(set(values).issubset(labels))
        for value in values.values():
            redacted, count = redact_sensitive_text(value)
            self.assertGreaterEqual(count, 1)
            self.assertNotIn(value, redacted)

    def test_free_text_provider_credentials_are_redacted_without_sensitive_field_names(self):
        credentials = (
            "AI" + "za" + "A" * 35,
            "sk_" + "live_" + "B" * 24,
        )

        for credential in credentials:
            value = f"Use the provider credential {credential} for the local request."
            findings = find_sensitive_text(value)
            redacted, count = redact_sensitive_text(value)
            self.assertTrue(findings)
            self.assertGreaterEqual(count, 1)
            self.assertNotIn(credential, redacted)

    def test_detects_user_path_in_command_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            private_path = "C:" + r"\Users\Private User\project\run.py"
            (root / "launch.cmd").write_text(f'python "{private_path}"', encoding="utf-8")
            self.assertIn(("launch.cmd", "windows-user-path"), scan(root, []))

    def test_detects_utf16_path_in_media_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            metadata = ("C:" + r"\Users\Sulabh Kumar\Videos\launch.mp4").encode("utf-16-le")
            (root / "poster.png").write_bytes(b"PNG" + metadata)
            self.assertIn(("poster.png", "windows-user-path"), scan(root, []))

    def test_detects_extended_unc_paths_in_utf8_and_utf16_artifacts(self):
        extended_unc = "\\\\?\\UNC\\private-host\\private-share\\proof.txt"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.txt").write_text(extended_unc, encoding="utf-8")
            (root / "metadata.bin").write_bytes(extended_unc.encode("utf-16-le"))

            findings = scan(root, [])

        self.assertIn(("config.txt", "unc-path"), findings)
        self.assertIn(("metadata.bin", "unc-path"), findings)

    def test_privacy_module_is_not_exempt_from_user_path_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            module = root / "rta_brain" / "privacy.py"
            module.parent.mkdir()
            private_path = "C:" + r"\Users\Private User\project\proof.txt"
            module.write_text(f'LEAKED_FIXTURE = r"{private_path}"\n', encoding="utf-8")

            self.assertIn(("rta_brain/privacy.py", "windows-user-path"), scan(root, []))

    def test_known_detector_definition_lines_are_narrowly_suppressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            source_root = Path(__file__).parents[1]
            scanner = root / "scripts" / "privacy_scan.py"
            scanner.parent.mkdir()
            scanner_line = next(
                line for line in (source_root / "scripts" / "privacy_scan.py").read_text(encoding="utf-8").splitlines()
                if line.strip().startswith("prefixes.extend")
            )
            scanner.write_text(scanner_line + "\n", encoding="utf-8")
            detector = root / "rta_brain" / "privacy.py"
            detector.parent.mkdir()
            detector_line = next(
                line for line in (source_root / "rta_brain" / "privacy.py").read_text(encoding="utf-8").splitlines()
                if line.strip().startswith('"unc-path"')
            )
            detector.write_text(detector_line + "\n", encoding="utf-8")

            self.assertEqual(scan(root, []), [])

    def test_scans_plain_artifact_directory_without_git_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private_path = "C:" + r"\Users\Private User\project\proof.txt"
            (root / "release.txt").write_text(private_path, encoding="utf-8")

            self.assertIn(("release.txt", "windows-user-path"), scan(root, []))

    def test_scans_explicit_ignored_artifact_directory_inside_git_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkout = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
            (checkout / ".gitignore").write_text("release-artifacts\n", encoding="utf-8")
            artifacts = checkout / "release-artifacts"
            artifacts.mkdir()
            (artifacts / "SHA256SUMS.txt").write_text(
                "fixture  rta-smriti-linux-x64\n", encoding="utf-8",
            )

            self.assertEqual(scan(artifacts, []), [])

    def test_large_release_binary_requires_an_explicit_bounded_scan_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private_path = "C:" + r"\Users\Private User\project\proof.txt"
            payload = b"binary-prefix\x00" + private_path.encode("utf-8")
            (root / "rta-brain").write_bytes(payload)

            with patch("scripts.privacy_scan.MAX_SCAN_BYTES", 16):
                default_findings = scan(root, [])
                release_findings = scan(root, [], max_file_bytes=128)

            self.assertIn(("rta-brain", "unscanned-file-over-16-bytes"), default_findings)
            self.assertIn(("rta-brain", "windows-user-path"), release_findings)

    def test_large_release_binary_limit_is_hard_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rta-brain").write_bytes(b"binary")

            findings = scan(root, [], max_file_bytes=129 * 1024 * 1024)

            self.assertEqual(findings, [(".", "invalid-max-file-bytes")])

    def test_git_deleted_paths_are_not_treated_as_release_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            deleted = root / "deleted.txt"
            deleted.write_text("historical", encoding="utf-8")
            subprocess.run(["git", "add", "deleted.txt"], cwd=root, check=True)
            deleted.unlink()
            (root / "README.md").write_text("# Candidate\n", encoding="utf-8")

            findings = scan(root, [])

            self.assertNotIn(("deleted.txt", "unreadable-release-file"), findings)

    def test_scans_wheel_members_instead_of_only_compressed_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel = root / "rta_fixture-1.0-py3-none-any.whl"
            private_path = "C:" + r"\Users\Private User\project\proof.txt"
            with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("rta_fixture/config.py", f'PATH = r"{private_path}"\n')

            self.assertIn(
                ("rta_fixture-1.0-py3-none-any.whl!rta_fixture/config.py", "windows-user-path"),
                scan(root, []),
            )

    def test_renamed_visual_media_still_requires_digest_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload = b"\x89PNG\r\n\x1a\n" + b"unapproved-pixel-fixture"
            (root / "preview.bin").write_bytes(payload)

            findings = scan(
                root,
                [],
                require_approved_media=True,
                approved_media_digests=set(),
            )

            self.assertIn(("preview.bin", "unapproved-visual-media"), findings)
            approved = scan(
                root,
                [],
                require_approved_media=True,
                approved_media_digests={hashlib.sha256(payload).hexdigest()},
            )
            self.assertNotIn(("preview.bin", "unapproved-visual-media"), approved)

    def test_archived_visual_media_requires_digest_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel = root / "rta_fixture-1.0-py3-none-any.whl"
            payload = b"\x89PNG\r\n\x1a\n" + b"archived-pixel-fixture"
            with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("rta_fixture/static/preview.png", payload)

            findings = scan(
                root,
                [],
                require_approved_media=True,
                approved_media_digests=set(),
            )

            member = "rta_fixture-1.0-py3-none-any.whl!rta_fixture/static/preview.png"
            self.assertIn((member, "unapproved-visual-media"), findings)
            approved = scan(
                root,
                [],
                require_approved_media=True,
                approved_media_digests={hashlib.sha256(payload).hexdigest()},
            )
            self.assertNotIn((member, "unapproved-visual-media"), approved)

    def test_unc_detector_rejects_binary_noise_with_invalid_share_component(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "release.exe").write_bytes(b"prefix\\\\E\\ S suffix")

            self.assertNotIn(("release.exe", "unc-path"), scan(root, []))

    def test_packaged_detector_definition_is_still_narrowly_suppressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            detector = root / "wheel" / "rta_brain" / "privacy.py"
            detector.parent.mkdir(parents=True)
            source_root = Path(__file__).parents[1]
            detector_line = next(
                line for line in (source_root / "rta_brain" / "privacy.py").read_text(encoding="utf-8").splitlines()
                if line.strip().startswith('"unc-path"')
            )
            detector.write_text(detector_line + "\n", encoding="utf-8")

            self.assertEqual(scan(root, []), [])

    def test_hard_linked_artifact_is_rejected_without_following_the_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / "release"
            root.mkdir()
            source = parent / "outside.txt"
            source.write_text("private source outside release root", encoding="utf-8")
            alias = root / "artifact.txt"
            os.link(source, alias)

            self.assertIn(("artifact.txt", "linked-release-file"), scan(root, []))

    def test_broken_and_directory_links_are_rejected_before_target_filtering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "release"
            target = Path(tmp) / "outside"
            root.mkdir()
            target.mkdir()
            try:
                os.symlink(target, root / "directory-link", target_is_directory=True)
                os.symlink(Path(tmp) / "missing", root / "broken-link")
            except OSError as exc:
                self.skipTest(f"symbolic links are unavailable: {exc}")

            findings = scan(root, [])
            self.assertIn(("directory-link", "linked-release-file"), findings)
            self.assertIn(("broken-link", "linked-release-file"), findings)

    def test_archive_directory_payload_and_link_entries_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "release.zip"
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("hidden/", b"payload")
                linked = zipfile.ZipInfo("linked-dir/")
                linked.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(linked, b"outside")

            findings = scan(root, [])
            self.assertIn(("release.zip!hidden/", "payload-bearing-archive-directory"), findings)
            self.assertIn(("release.zip!linked-dir/", "linked-archive-entry"), findings)

    def test_nested_and_renamed_zip_payloads_are_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private_path = "C:" + r"\Users\Private User\project\proof.txt"
            nested_buffer = io.BytesIO()
            with zipfile.ZipFile(nested_buffer, "w", compression=zipfile.ZIP_DEFLATED) as nested:
                nested.writestr("private.txt", private_path)
            with zipfile.ZipFile(root / "outer.zip", "w", compression=zipfile.ZIP_DEFLATED) as outer:
                outer.writestr("nested.bin", nested_buffer.getvalue())
            (root / "renamed.jar").write_bytes(nested_buffer.getvalue())

            findings = scan(root, [])
            self.assertIn(("outer.zip!nested.bin!private.txt", "windows-user-path"), findings)
            self.assertIn(("renamed.jar!private.txt", "windows-user-path"), findings)

    def test_archive_paths_use_platform_neutral_safety_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with zipfile.ZipFile(root / "release.zip", "w") as archive:
                archive.writestr("C:/escape.txt", "escape")
                archive.writestr("\\\\server\\share\\escape.txt", "escape")

            findings = scan(root, [])
            self.assertIn(("release.zip!C:/escape.txt", "unsafe-archive-path"), findings)
            self.assertIn(("release.zip!//server/share/escape.txt", "unsafe-archive-path"), findings)

    def test_unc_redaction_consumes_the_complete_share_and_path(self):
        value = "prefix " + "\\\\" + r"server\R&D\private\file.txt suffix"

        redacted, count = redact_sensitive_text(value)

        self.assertEqual(count, 1)
        self.assertEqual(redacted, "prefix [REDACTED]")
        self.assertNotIn("R&D", redacted)
        self.assertNotIn("private", redacted)

    def test_plain_text_bypasses_expensive_sensitive_regexes(self):
        class UnexpectedPattern:
            def finditer(self, _value):
                raise AssertionError("plain text should not reach sensitive regexes")

            def subn(self, _replacement, _value):
                raise AssertionError("plain text should not reach sensitive regexes")

        with patch(
            "rta_brain.privacy.SENSITIVE_TEXT_PATTERNS",
            {"unexpected": UnexpectedPattern()},
        ):
            self.assertEqual(find_sensitive_text("ordinary event summary"), [])
            self.assertEqual(
                redact_sensitive_text("ordinary event summary"),
                ("ordinary event summary", 0),
            )

    def test_scan_wide_file_budget_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "one.txt").write_text("one", encoding="utf-8")
            (root / "two.txt").write_text("two", encoding="utf-8")

            with patch("scripts.privacy_scan.MAX_SCAN_FILES", 1, create=True):
                findings = scan(root, [])

            self.assertIn((".", "scan-over-1-files"), findings)


if __name__ == "__main__":
    unittest.main()
