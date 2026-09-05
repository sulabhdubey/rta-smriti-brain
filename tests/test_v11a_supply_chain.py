import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.privacy_scan import scan


ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def _job(workflow: str, name: str, next_name: str | None = None) -> str:
    start = workflow.index(f"  {name}:\n")
    end = workflow.index(f"  {next_name}:\n", start) if next_name else len(workflow)
    return workflow[start:end]


class V11ASupplyChainTests(unittest.TestCase):
    def test_release_builds_do_not_hold_oidc_or_attestation_authority(self):
        binaries = _workflow("binaries.yml")
        pages = _workflow("pages.yml")

        binary_build = _job(binaries, "build", "attest")
        pages_build = _job(pages, "build", "attest")
        for build in (binary_build, pages_build):
            self.assertIn("permissions:\n      contents: read", build)
            self.assertNotIn("id-token: write", build)
            self.assertNotIn("attestations: write", build)
            self.assertNotIn("artifact-metadata: write", build)
            self.assertNotIn("actions/attest@", build)

        binary_attest = _job(binaries, "attest")
        pages_attest = _job(pages, "attest", "deploy")
        for attest in (binary_attest, pages_attest):
            self.assertIn("id-token: write", attest)
            self.assertIn("attestations: write", attest)
            self.assertIn("artifact-metadata: write", attest)
            self.assertIn("actions/download-artifact@", attest)
            self.assertIn("actions/attest@", attest)
            self.assertNotIn("actions/checkout@", attest)
            self.assertNotIn("setup-python", attest)
            self.assertNotIn("setup-node", attest)
            self.assertNotIn("pip install", attest)
            self.assertNotIn("npm ci", attest)

    def test_python_release_installs_are_platform_locked_and_hash_required(self):
        for workflow_name in ("ci.yml", "binaries.yml"):
            workflow = _workflow(workflow_name)
            self.assertIn("--require-hashes", workflow)
            self.assertNotIn("PIP_CONSTRAINT: constraints/release.txt", workflow)
            self.assertIn("lock:", workflow)

        locks = (
            "release-linux-py311.txt",
            "release-linux-py312.txt",
            "release-linux-py313.txt",
            "release-macos-py311.txt",
            "release-macos-py312.txt",
            "release-windows-py311.txt",
            "release-windows-py312.txt",
        )
        for filename in locks:
            lock = ROOT / "constraints" / filename
            requirements = [
                line
                for line in lock.read_text(encoding="utf-8").splitlines()
                if line and not line.startswith(("#", " ", "\t"))
            ]
            self.assertTrue(requirements, filename)
            for requirement in requirements:
                self.assertIn("==", requirement)
                self.assertIn("--hash=sha256:", requirement)
            locked_text = lock.read_text(encoding="utf-8")
            self.assertIn("typing_extensions==", locked_text)
            self.assertIn("pytest==", locked_text)
            self.assertIn("iniconfig==", locked_text)
            self.assertIn("pluggy==", locked_text)
            if "windows" in filename:
                self.assertIn("colorama==", locked_text)
        self.assertIn("macholib==", (ROOT / "constraints" / "release-macos-py311.txt").read_text(encoding="utf-8"))
        self.assertIn("macholib==", (ROOT / "constraints" / "release-macos-py312.txt").read_text(encoding="utf-8"))
        self.assertIn("python -m pytest -q", _workflow("ci.yml"))

    def test_vite_disables_implicit_public_copy_and_rejects_linked_assets(self):
        if shutil.which("node") is None:
            self.skipTest("Node.js is unavailable")
        config = (ROOT / "vite.launch.config.js").read_text(encoding="utf-8")
        self.assertIn("publicDir: false", config)
        self.assertIn("copyPublicTreeSafely", config)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "public"
            destination = root / "dist"
            outside = root / "outside.txt"
            source.mkdir()
            destination.mkdir()
            outside.write_text("private", encoding="utf-8")
            linked = source / "linked.txt"
            try:
                linked.symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")

            script = (
                "import {copyPublicTreeSafely} from "
                + repr((ROOT / "vite.launch.config.js").as_uri())
                + "; await copyPublicTreeSafely(process.argv[1], process.argv[2]);"
            )
            result = subprocess.run(
                ["node", "--input-type=module", "-e", script, str(source), str(destination)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("linked public asset", (result.stderr + result.stdout).lower())
            self.assertFalse((destination / "linked.txt").exists())

    def test_host_lifecycle_state_is_ignored_everywhere(self):
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("**/.rta-smriti-host-lifecycle/", ignore)

    def test_ci_has_pinned_checksum_verified_actionlint_gate(self):
        workflow = _workflow("ci.yml")
        lint = _job(workflow, "workflow-lint", "supply-chain-scan")
        self.assertIn("ACTIONLINT_VERSION: 1.7.12", lint)
        self.assertIn(
            "ACTIONLINT_SHA256: 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
            lint,
        )
        self.assertIn("sha256sum --check", lint)
        self.assertIn("./actionlint", lint)

    def test_visual_media_requires_an_explicit_approved_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            media = root / "product.png"
            media.write_bytes(b"\x89PNG\r\n\x1a\nsynthetic-public-image")
            digest = hashlib.sha256(media.read_bytes()).hexdigest()

            self.assertIn(
                ("product.png", "unapproved-visual-media"),
                scan(root, [], require_approved_media=True, approved_media_digests=set()),
            )
            self.assertEqual(
                scan(root, [], require_approved_media=True, approved_media_digests={digest}),
                [],
            )

    def test_publication_workflows_enforce_media_hash_gate_without_claiming_ocr(self):
        for workflow_name in ("ci.yml", "pages.yml", "binaries.yml"):
            workflow = _workflow(workflow_name)
            self.assertIn("--require-approved-media", workflow)
            self.assertIn("constraints/release-media.sha256", workflow)
        scanner = (ROOT / "scripts" / "privacy_scan.py").read_text(encoding="utf-8")
        self.assertIn("pixel contents are not OCR-scanned", scanner)


if __name__ == "__main__":
    unittest.main()
