import copy
import json
import subprocess
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
    def test_native_bridge_evaluator_checks_success_and_refusal_causes(self):
        good_context = {"hookSpecificOutput": {"additionalContext": "Atlas native handoff"}}
        host_results = [
            {"context": "Atlas native handoff", "plan_digest": "a" * 64},
            {},
            good_context,
            {"systemMessage": "invalid_input"},
            {},
            {"systemMessage": "not_enabled"},
        ]
        cases = [("valid", None, None)] + [
            ("missing selection", 0, {"context": "wrong", "plan_digest": "a" * 64}),
            ("omitted field leaked", 2, {"hookSpecificOutput": {
                "additionalContext": "Atlas native handoff Omitted checkpoint field"}}),
            ("unrelated input failure", 3, {"systemMessage": "timeout"}),
            ("revocation still supplies context", 5, good_context),
            ("unrelated revocation failure", 5, {"systemMessage": "unavailable"}),
        ]
        for label, index, replacement in cases:
            with self.subTest(case=label):
                responses = copy.deepcopy(host_results)
                if index is not None:
                    responses[index] = replacement
                results = [{}, *responses, *copy.deepcopy(host_results)]
                completed = [subprocess.CompletedProcess([], 0, json.dumps(item), "") for item in results]
                with patch.object(smoke_binary, "run", side_effect=completed) as run:
                    if index is None:
                        evidence = smoke_binary.verify_continuity_bridge(
                            Path("fictional-cli"), Path("brain.sqlite"), "atlas", Path("."))
                        self.assertEqual(evidence["hosts"], ["codex", "claude-code"])
                        self.assertEqual(run.call_count, 13)
                    else:
                        with self.assertRaises(AssertionError):
                            smoke_binary.verify_continuity_bridge(
                                Path("fictional-cli"), Path("brain.sqlite"), "atlas", Path("."))

    def test_smoke_commands_require_the_exact_expected_exit_code(self):
        for module in (installed_distribution_smoke, smoke_binary):
            arguments = (["fictional-cli"], Path(".")) if module is installed_distribution_smoke else (Path("fictional-cli"),)
            for actual in (0, 1, 2):
                result = subprocess.CompletedProcess("fictional-cli", actual, "{}", "")
                with self.subTest(module=module.__name__, actual=actual), patch.object(module.subprocess, "run", return_value=result):
                    if actual == 1:
                        self.assertIs(module.run(*arguments, expected_returncode=1), result)
                    else:
                        with self.assertRaises(RuntimeError):
                            module.run(*arguments, expected_returncode=1)
                    if actual == 0:
                        self.assertIs(module.run(*arguments), result)
                    else:
                        with self.assertRaises(RuntimeError):
                            module.run(*arguments)

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
