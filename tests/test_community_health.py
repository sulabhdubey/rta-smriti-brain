import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CommunityHealthTests(unittest.TestCase):
    def test_readme_invites_feedback_and_first_contributions(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("### Share What Happened", readme)
        self.assertIn("/discussions/categories/q-a", readme)
        self.assertIn('label%3A%22good+first+issue%22', readme)

    def test_contributing_has_a_bounded_first_contribution_path(self):
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")

        self.assertIn("## A 15-Minute First Contribution", contributing)
        self.assertIn("## Pull Request Scope", contributing)
        self.assertIn("private vulnerability reporting", contributing)

    def test_issue_router_uses_discussions_and_private_security_reporting(self):
        config = (
            ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml"
        ).read_text(encoding="utf-8")

        self.assertIn("blank_issues_enabled: false", config)
        self.assertIn(
            "https://github.com/sulabhdubey/rta-smriti-brain/discussions/categories/q-a",
            config,
        )
        self.assertIn(
            "https://github.com/sulabhdubey/rta-smriti-brain/security/advisories/new",
            config,
        )

    def test_zed_recipe_uses_generated_config_and_verification(self):
        recipe = (ROOT / "docs" / "ZED_MCP.md").read_text(encoding="utf-8")

        self.assertIn("https://zed.dev/docs/ai/mcp", recipe)
        self.assertIn("context_servers", recipe)
        self.assertIn("mcp-config --project", recipe)
        self.assertIn("mcp-config --brain-dir", recipe)
        self.assertIn("mcp-doctor --project", recipe)
        self.assertIn("validates only the generated single-project command", recipe)
        self.assertIn("read-only, project-scoped call", recipe)
        self.assertIn("is not visible or active", recipe)
        self.assertNotIn("Existing tasks cannot acquire", recipe)

        installation = (ROOT / "docs" / "INSTALLATION.md").read_text(encoding="utf-8")
        self.assertIn("follow that host's documented activation lifecycle", installation)
        self.assertIn("only when the host requires it", installation)
        self.assertNotIn("Restart the host completely", installation)
        self.assertIn("Tested scope:", recipe)
        self.assertIn("Zed 1.16.3 stable", recipe)
        self.assertIn("completed a fresh Agent Panel `brain_search` call", recipe)
        self.assertIn("returning `README.md`", recipe)
        self.assertIn("No private repository or user", recipe)


if __name__ == "__main__":
    unittest.main()
