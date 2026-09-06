import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import cli
from scripts import installed_distribution_smoke, smoke_binary

EXPECTED_ACTIONS = {
    "inspect",
    "plan",
    "apply",
    "verify",
    "repair",
    "stop",
    "remove",
}
EXPECTED_PROFILES = {
    "claude-code",
    "codex",
    "cursor",
    "gemini-cli",
    "opencode",
    "zed",
}


def valid_evidence() -> dict:
    return {
        "lifecycle": {
            "actions": sorted(EXPECTED_ACTIONS),
            "apply_state": "complete",
            "verify_state": "verified",
            "repair_state": "verified",
            "stop_state": "complete",
            "remove_state": "removed",
        },
        "mcp_profiles": sorted(EXPECTED_PROFILES),
        "retrieval": {
            "stages": ["index", "timeline", "evidence"],
            "handle_consistent": True,
            "snapshot_consistent": True,
        },
        "review": {
            "schema": "rta-smriti.trusted-lifecycle-review/v1",
            "summary_authority": "non_authoritative",
            "bundle_digest": "a" * 64,
        },
    }


class V11AcceptanceSmokeTests(unittest.TestCase):
    def test_frozen_lifecycle_authority_uses_stable_executable_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "bin" / "rta-brain.exe"
            executable.parent.mkdir()
            with (
                patch.object(cli.sys, "frozen", True, create=True),
                patch.object(cli.sys, "executable", str(executable)),
            ):
                self.assertEqual(cli.lifecycle_tool_root(), executable.parent.resolve())

    def test_lifecycle_authority_environment_excludes_frozen_runtime_noise(self):
        environment = {
            "APPDATA": "stable-appdata",
            "PATH": "stable-path",
            "_PYI_APPLICATION_HOME_DIR": "ephemeral-onefile-root",
            "TMP": "ephemeral-temp",
        }
        with patch.dict(cli.os.environ, environment, clear=True):
            self.assertEqual(
                cli.lifecycle_authority_environment(),
                {"APPDATA": "stable-appdata"},
            )

    def test_both_smoke_runners_accept_complete_v11_evidence(self):
        evidence = valid_evidence()

        installed_distribution_smoke.assert_v11_acceptance(evidence)
        smoke_binary.assert_v11_acceptance(evidence)

    def test_both_smoke_runners_reject_an_incomplete_contract(self):
        mutations = (
            ("missing lifecycle action", lambda value: value["lifecycle"]["actions"].remove("repair")),
            ("missing Gemini profile", lambda value: value["mcp_profiles"].remove("gemini-cli")),
            ("unstable retrieval handle", lambda value: value["retrieval"].update(handle_consistent=False)),
            ("unsealed review", lambda value: value["review"].update(bundle_digest="not-a-digest")),
        )
        for label, mutate in mutations:
            for module in (installed_distribution_smoke, smoke_binary):
                with self.subTest(label=label, module=module.__name__):
                    evidence = copy.deepcopy(valid_evidence())
                    mutate(evidence)
                    with self.assertRaises(AssertionError):
                        module.assert_v11_acceptance(evidence)


if __name__ == "__main__":
    unittest.main()
