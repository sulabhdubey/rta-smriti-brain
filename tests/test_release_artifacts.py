import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.package_release_artifacts import (
    assert_wheel_static_assets,
    file_sha256,
    referenced_static_assets,
    stage_artifacts,
    stage_sbom,
)


class ReleaseArtifactTests(unittest.TestCase):
    def test_wheel_assets_must_exactly_match_dashboard_index(self):
        references = referenced_static_assets()
        self.assertTrue(references)
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "candidate.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                for reference in references:
                    archive.writestr(reference, b"current")
            assert_wheel_static_assets(wheel)

            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr("rta_brain/static/assets/obsolete.js", b"stale")
            with self.assertRaisesRegex(RuntimeError, "stale=.*obsolete.js"):
                assert_wheel_static_assets(wheel)

    def test_sbom_must_be_bounded_unlinked_cyclonedx_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output"
            output.mkdir()
            sbom = root / "candidate.cdx.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "metadata": {
                            "component": {
                                "type": "application",
                                "name": "rta-smriti-brain",
                                "version": "0.9.0a1",
                                "properties": [
                                    {"name": "supplier:reviewed", "value": "true"},
                                    {
                                        "name": "rta-smriti:release-artifact-sha256:stale.bin",
                                        "value": "c" * 64,
                                    },
                                ],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            artifact_digests = {
                "rta-brain-0.9.0a1-linux-x86_64": "a" * 64,
                "rta_smriti_brain-0.9.0a1-py3-none-any.whl": "b" * 64,
            }

            staged = stage_sbom(
                sbom,
                output,
                version="0.9.0a1",
                artifact_digests=artifact_digests,
            )
            self.assertTrue(staged.name.startswith("rta-smriti-brain-0.9.0a1-"))
            payload = json.loads(staged.read_text(encoding="utf-8"))
            component = payload["metadata"]["component"]
            self.assertEqual(component["type"], "application")
            self.assertEqual(component["name"], "rta-smriti-brain")
            self.assertEqual(component["version"], "0.9.0a1")
            properties = {item["name"]: item["value"] for item in component["properties"]}
            for name, digest in artifact_digests.items():
                self.assertEqual(properties[f"rta-smriti:release-artifact-sha256:{name}"], digest)
            self.assertEqual(properties["supplier:reviewed"], "true")
            self.assertNotIn("rta-smriti:release-artifact-sha256:stale.bin", properties)
            release_set = json.dumps(artifact_digests, sort_keys=True, separators=(",", ":")).encode("ascii")
            self.assertEqual(
                properties["rta-smriti:release-set-sha256"],
                hashlib.sha256(release_set).hexdigest(),
            )

            invalid = root / "invalid.json"
            invalid.write_text('{"bomFormat":"SPDX"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "CycloneDX"):
                stage_sbom(
                    invalid,
                    output,
                    version="0.9.0a1",
                    artifact_digests=artifact_digests,
                )

            linked = root / "linked.cdx.json"
            linked.hardlink_to(sbom)
            with self.assertRaisesRegex(ValueError, "hard linked"):
                stage_sbom(
                    linked,
                    output,
                    version="0.9.0a1",
                    artifact_digests=artifact_digests,
                )

            symbolic = root / "symbolic.cdx.json"
            try:
                symbolic.symlink_to(sbom)
            except OSError:
                pass
            else:
                with self.assertRaises(FileNotFoundError):
                    stage_sbom(
                        symbolic,
                        output,
                        version="0.9.0a1",
                        artifact_digests=artifact_digests,
                    )

    def test_sbom_rejects_conflicting_root_component_and_invalid_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "output"
            output.mkdir()
            sbom = root / "candidate.cdx.json"
            sbom.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "specVersion": "1.6",
                        "metadata": {
                            "component": {
                                "type": "application",
                                "name": "different-project",
                                "version": "0.9.0a1",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "root component name"):
                stage_sbom(
                    sbom,
                    output,
                    version="0.9.0a1",
                    artifact_digests={"release.whl": "a" * 64},
                )

            sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                stage_sbom(
                    sbom,
                    output,
                    version="0.9.0a1",
                    artifact_digests={"release.whl": "not-a-digest"},
                )

    def test_staged_sbom_binding_matches_binary_and_checksum_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dist = root / "dist"
            dist.mkdir()
            source_name = "rta-brain.exe" if os.name == "nt" else "rta-brain"
            (dist / source_name).write_bytes(b"reviewed release bytes")
            sbom = root / "source.cdx.json"
            sbom.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}', encoding="utf-8")
            output = root / "release-artifacts"

            with (
                patch("scripts.package_release_artifacts.ROOT", root),
                patch("scripts.package_release_artifacts.project_version", return_value="0.9.0a1"),
                patch("scripts.package_release_artifacts.platform_label", return_value="test-os"),
                patch("scripts.package_release_artifacts.architecture_label", return_value="test-arch"),
                patch(
                    "scripts.package_release_artifacts.run",
                    return_value=SimpleNamespace(stdout="rta-brain 0.9.0a1\n"),
                ),
            ):
                result = stage_artifacts(output, include_wheel=False, sbom=sbom)

            binary = output / f"rta-brain-0.9.0a1-test-os-test-arch{'.exe' if os.name == 'nt' else ''}"
            staged_sbom = output / "rta-smriti-brain-0.9.0a1-test-os-test-arch.cdx.json"
            component = json.loads(staged_sbom.read_text(encoding="utf-8"))["metadata"]["component"]
            properties = {item["name"]: item["value"] for item in component["properties"]}
            self.assertEqual(
                properties[f"rta-smriti:release-artifact-sha256:{binary.name}"],
                file_sha256(binary),
            )
            self.assertEqual(result["artifacts"][binary.name], file_sha256(binary))
            manifest = (output / "SHA256SUMS.txt").read_text(encoding="ascii")
            self.assertIn(binary.name, manifest)
            self.assertIn(staged_sbom.name, manifest)

    def test_release_workflows_scan_final_staging_and_pin_supply_chain_actions(self):
        root = Path(__file__).resolve().parents[1]
        workflows = {
            name: (root / ".github" / "workflows" / name).read_text(encoding="utf-8")
            for name in ("ci.yml", "binaries.yml", "pages.yml")
        }
        gitleaks = "gitleaks/gitleaks-action@e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e"
        for workflow in workflows.values():
            self.assertIn(gitleaks, workflow)

        ci = workflows["ci.yml"]
        self.assertLess(ci.index("python scripts/package_release_artifacts.py"), ci.index("Privacy-scan staged release artifacts"))
        self.assertLess(ci.index("Privacy-scan staged release artifacts"), ci.index("Upload release artifacts"))
        self.assertLess(ci.index("Run packaged public benchmark"), ci.index("Privacy-scan staged public benchmark"))
        self.assertLess(ci.index("Privacy-scan staged public benchmark"), ci.index("name: public-benchmark-result"))

        binaries = workflows["binaries.yml"]
        self.assertLess(binaries.index("python scripts/package_release_artifacts.py"), binaries.index("Privacy-scan staged release artifacts"))
        self.assertLess(binaries.index("Privacy-scan staged release artifacts"), binaries.index("Upload release artifacts"))
        self.assertLess(binaries.index("Upload release artifacts"), binaries.index("Attest release artifacts"))

        pages = workflows["pages.yml"]
        self.assertLess(pages.index("Build static launch package"), pages.index("Privacy-scan staged Pages artifact"))
        self.assertLess(pages.index("Privacy-scan staged Pages artifact"), pages.index("Upload Pages artifact"))
        self.assertIn("actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26", binaries)
        self.assertIn("actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26", pages)

    def test_python_workflows_use_reviewed_hash_locked_requirements(self):
        root = Path(__file__).resolve().parents[1]
        workflows = {
            name: (root / ".github" / "workflows" / name).read_text(encoding="utf-8")
            for name in ("ci.yml", "binaries.yml")
        }
        for workflow in workflows.values():
            self.assertIn("--require-hashes -r ${{ matrix.lock }}", workflow)
            self.assertIn("--no-build-isolation --no-deps", workflow)
        linux_lock = (root / "constraints" / "release-linux-py311.txt").read_text(encoding="utf-8")
        self.assertIn("pip-audit==2.10.1 --hash=sha256:", linux_lock)

    def test_release_constraints_are_exact_and_hashed_for_reviewed_packages(self):
        constraints = Path(__file__).resolve().parents[1] / "constraints" / "release-linux-py311.txt"
        requirements = [
            line.strip()
            for line in constraints.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertTrue(requirements)
        for requirement in requirements:
            self.assertIn("==", requirement)
            self.assertIn("--hash=sha256:", requirement)
            self.assertNotIn(">=", requirement)
            self.assertNotIn("~=", requirement)
        joined = "\n".join(requirements)
        self.assertIn("tree-sitter-language-pack==1.14.3", joined)
        self.assertIn("cryptography==50.0.0", joined)
        self.assertIn("watchdog==6.0.0", joined)
        self.assertIn("pyinstaller==6.22.1", joined)



if __name__ == "__main__":
    unittest.main()
