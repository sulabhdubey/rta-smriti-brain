import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.package_pilot_bundle import package_pilot, source_identity


class PilotBundleTests(unittest.TestCase):
    def fixture(self, root):
        artifacts = root / "artifacts"
        artifacts.mkdir()
        names = ["rta-brain-1.1.0a5-windows-x86_64.exe", "rta_smriti_brain-1.1.0a5-py3-none-any.whl"]
        checksums = []
        for name in names:
            (artifacts / name).write_bytes(b"synthetic artifact")
            checksums.append(f"{hashlib.sha256(b'synthetic artifact').hexdigest()}  {name}\n")
        (artifacts / "SHA256SUMS.txt").write_text("".join(checksums))
        return artifacts

    @patch("scripts.package_pilot_bundle.source_identity", return_value={"base_commit": "a" * 40, "source_sha256": "b" * 64, "uncommitted": True})
    def test_allowlist_manifest_and_checksums(self, identity):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = package_pilot(self.fixture(root), root / "pilot.zip")
            with zipfile.ZipFile(root / "pilot.zip") as archive:
                names = archive.namelist()
                self.assertIn("PILOT_GUIDE.md", names)
                self.assertIn("atlas-demo/README.md", names)
                manifest = json.loads(archive.read("PILOT_MANIFEST.json"))
                self.assertEqual(manifest["status"], "packaged_candidate")
                self.assertIn("does not establish publication", manifest["publication"])
                self.assertFalse(manifest["host_activation_verified"])
                for line in archive.read("SHA256SUMS.txt").decode().splitlines():
                    digest, name = line.split("  ", 1)
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), digest)
                self.assertFalse(any("sqlite" in name or name.startswith(".git") for name in names))
            self.assertEqual(result["sha256"], hashlib.sha256((root / "pilot.zip").read_bytes()).hexdigest())

    def test_rejects_tampered_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = self.fixture(root)
            next(artifacts.glob("*.exe")).write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                package_pilot(artifacts, root / "pilot.zip")
            self.assertFalse((root / "pilot.zip").exists())

    def test_rejects_unexpected_private_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = self.fixture(root)
            (artifacts / "brain.sqlite").write_bytes(b"private")
            with self.assertRaisesRegex(ValueError, "unexpected"):
                package_pilot(artifacts, root / "pilot.zip")

    def test_never_overwrites_existing_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "pilot.zip"
            target.write_bytes(b"keep")
            with self.assertRaises(FileExistsError):
                package_pilot(self.fixture(root), target)
            self.assertEqual(target.read_bytes(), b"keep")

    def test_source_identity_is_bounded_to_git_candidate(self):
        identity = source_identity()
        self.assertEqual(len(identity["base_commit"]), 40)
        self.assertEqual(len(identity["source_sha256"]), 64)
        self.assertNotIn("root", identity)
