import json
import tomllib
import unittest
from pathlib import Path

from rta_brain import __version__

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON_VERSION = "1.0.2a1"
EXPECTED_DISPLAY_VERSION = "1.0.2-alpha"
PUBLISHED_BASELINE = "v1.0.1-alpha"
PUBLISHED_BASELINE_COMMIT = "c2dff01b368bdb4d2b759e7a077d07ae0985a966"


class ReleaseMetadataTests(unittest.TestCase):
    def test_v1_release_surfaces_are_consistent(self):
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        package_lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
        binary_smoke = (ROOT / "scripts" / "smoke_binary.py").read_text(encoding="utf-8")
        dashboard = (ROOT / "dashboard-src" / "src" / "main.jsx").read_text(encoding="utf-8")
        citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        roadmap = (ROOT / "ROADMAP.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        fact_sheet = (ROOT / "launch-assets" / "press" / "PRODUCT_FACT_SHEET.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        contributors = (ROOT / "CONTRIBUTORS.md").read_text(encoding="utf-8")
        launch_site = (ROOT / "launch-site" / "src" / "main.jsx").read_text(encoding="utf-8")
        usage = (ROOT / "docs" / "USAGE_GUIDE.md").read_text(encoding="utf-8")
        architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
        release_notes = (ROOT / "docs" / "RELEASE_NOTES_v1.0.2-alpha.md").read_text(encoding="utf-8")
        release_verification = (ROOT / "docs" / "RELEASE_VERIFICATION.md").read_text(encoding="utf-8")
        threat_model = (ROOT / "docs" / "security" / "v1.0-cognition-threat-model.md").read_text(encoding="utf-8")

        self.assertEqual(__version__, EXPECTED_PYTHON_VERSION)
        self.assertEqual(pyproject["project"]["version"], EXPECTED_PYTHON_VERSION)
        self.assertEqual(package["version"], EXPECTED_DISPLAY_VERSION)
        self.assertEqual(package_lock["version"], EXPECTED_DISPLAY_VERSION)
        self.assertEqual(package_lock["packages"][""]["version"], EXPECTED_DISPLAY_VERSION)
        self.assertIn("expected_version = str(tomllib.loads", binary_smoke)
        self.assertIn("expected_version not in version", binary_smoke)
        self.assertNotIn('"0.9.1a1" not in version', binary_smoke)
        self.assertLess(binary_smoke.index("root = Path(__file__)"), binary_smoke.index("expected_version = str(tomllib.loads"))
        self.assertIn("v1.0.2 Alpha Operator Console", dashboard)
        self.assertIn("version: 1.0.2-alpha", citation)
        self.assertIn("## Published v1.0.2-alpha", roadmap)
        self.assertIn("## Published v1.0.1-alpha", roadmap)
        self.assertIn("## Published v1.0.0-alpha", roadmap)
        self.assertIn("## Published v0.9.1-alpha", roadmap)
        self.assertIn("## [1.0.2-alpha] - 2026-08-26", changelog)
        self.assertIn("**Current public prerelease:** [`v1.0.2-alpha`]", fact_sheet)
        self.assertIn("**Release bundle:** SHA-256 checksums", fact_sheet)
        self.assertIn("## v1.0.2-alpha", readme)
        self.assertIn("Current release: v1.0.2-alpha", readme)
        self.assertIn("Project Reality", launch_site)
        self.assertIn("project-reality-v1.0.2.png", launch_site)
        self.assertNotIn("Creator-Brief", readme + fact_sheet + launch_site)
        self.assertIn("/releases/tag/v1.0.2-alpha", launch_site)
        self.assertNotIn("v1.0.2-alpha Candidate", roadmap + readme)
        self.assertNotIn("v1.0.1-alpha remains the current public prerelease", roadmap + readme + release_notes)
        self.assertIn("## Project Reality In v1", usage)
        self.assertIn("--json cognition --project", usage)
        self.assertIn("--json media list --project", usage)
        self.assertIn("## Project Cognition Layer", architecture)
        self.assertIn("## Local Multimodal Evidence", architecture)
        self.assertIn("## Stable Interfaces", architecture)
        self.assertIn("Alpha prerelease", release_notes)
        self.assertIn("operator-hardening patch", release_notes)
        self.assertIn("## Published v1.0.2-alpha Verification", release_verification)
        self.assertIn("## Published v1.0.1-alpha Verification", release_verification)
        self.assertIn("c2dff01b368bdb4d2b759e7a077d07ae0985a966", release_verification)
        self.assertIn("## Published v1.0.0-alpha Verification", release_verification)
        self.assertIn("a1b05022aff6df3a066ae5abcad3877f6407eafb", release_verification)
        self.assertIn("/releases/tag/v1.0.0-alpha", release_verification)
        self.assertNotIn("Pending the approved `v1.0.0-alpha` tag workflow", release_verification)
        self.assertNotIn("Pending formal publication", release_verification)
        self.assertIn("# v1 Project Cognition Threat Model", threat_model)

        self.assertIn("Conceived and researched by [Sulabh Dubey]", readme)
        self.assertIn("[OpenAI Codex](https://openai.com/codex/)", readme)
        self.assertIn("Rta-Smriti Brain was conceived, researched, and product-directed", contributors)
        self.assertIn("does not imply that OpenAI endorses", contributors)
        self.assertIn("Built with <a href=\"https://openai.com/codex/\">OpenAI Codex</a>", launch_site)
        self.assertIn("conceived, researched, and product-directed by Sulabh", release_notes)
        self.assertNotIn("given-names: OpenAI", citation)
        self.assertNotIn("zero Python runtime dependencies", fact_sheet)

    def test_v1_interfaces_are_documented_and_exposed(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cli = (ROOT / "rta_brain" / "cli.py").read_text(encoding="utf-8")
        mcp = (ROOT / "rta_brain" / "mcp_server.py").read_text(encoding="utf-8")
        sdk = (ROOT / "rta_brain" / "sdk.py").read_text(encoding="utf-8")

        self.assertIn("v1 Project Reality CLI", readme)
        self.assertIn('"cognition"', cli)
        self.assertIn('"media"', cli)
        self.assertIn("brain_cognition_snapshot", mcp)
        self.assertIn("brain_multimodal_list", mcp)
        self.assertIn("class BrainClient", sdk)

    def test_tag_workflow_stages_the_documented_release_bundle(self):
        workflow = (ROOT / ".github" / "workflows" / "binaries.yml").read_text(encoding="utf-8")

        self.assertIn("scripts/package_release_artifacts.py", workflow)
        self.assertIn("--include-wheel", workflow)
        self.assertIn("release-artifacts/", workflow)
        self.assertIn("SHA256SUMS.txt", workflow)
        self.assertIn("pip-audit==2.10.1", workflow)
        self.assertIn("--format cyclonedx-json", workflow)
        self.assertIn("--sbom release-sbom.cdx.json", workflow)

    def test_installed_upgrade_smoke_uses_the_previous_public_release(self):
        smoke = (ROOT / "scripts" / "build_installed_smoke.py").read_text(encoding="utf-8")

        self.assertIn(f'BASELINE_REF = "{PUBLISHED_BASELINE}"', smoke)
        self.assertIn(f'BASELINE_COMMIT = "{PUBLISHED_BASELINE_COMMIT}"', smoke)
        self.assertIn("baseline_version == expected_version", smoke)
        self.assertIn("baseline and candidate package versions are identical", smoke)
        self.assertNotIn('"--force-reinstall", str(wheel)', smoke)


if __name__ == "__main__":
    unittest.main()