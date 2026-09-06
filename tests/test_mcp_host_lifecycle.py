import hashlib
import io
import json
import sys
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from rta_brain import mcp_host_lifecycle
from rta_brain.cli import main
from rta_brain.mcp_host_lifecycle import (
    apply_host_configuration,
    host_profile,
    host_profiles,
    plan_host_configuration,
    record_fresh_session_proof,
)
from rta_brain.platform_paths import canonicalize_system_root_alias


class McpHostLifecycleTests(unittest.TestCase):
    def setUp(self):
        self._authority_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._authority_directory.cleanup)
        authority_patch = patch(
            "rta_brain.mcp_host_lifecycle._host_authority_root",
            return_value=Path(self._authority_directory.name),
        )
        authority_patch.start()
        self.addCleanup(authority_patch.stop)

    @staticmethod
    def _canonical_python_server(**extra):
        return {
            "command": str(Path(sys.executable).resolve()),
            "args": ["-I", "-m", "rta_brain.mcp_server"],
            **extra,
        }

    @staticmethod
    def _target_for_profile(base: Path, profile_id: str) -> Path:
        targets = {
            "codex": base / ".codex" / "config.toml",
            "claude-code": base / ".mcp.json",
            "cursor": base / ".cursor" / "mcp.json",
            "zed": base / "zed" / "settings.json",
            "opencode": base / "opencode.json",
            "gemini-cli": base / ".gemini" / "settings.json",
        }
        target = targets[profile_id]
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def test_supported_profiles_have_reviewed_activation_and_proof_contracts(self):
        profiles = host_profiles()
        expected_activation_states = {
            "codex": "restart_required",
            "claude-code": "approval_check_required",
            "cursor": "activation_check_required",
            "zed": "server_panel_check_required",
            "opencode": "enablement_check_required",
            "gemini-cli": "restart_required",
        }

        self.assertEqual(set(profiles), set(expected_activation_states))
        for profile_id, profile in profiles.items():
            self.assertIn("https://", profile["official_documentation"])
            self.assertRegex(profile["reviewed_on"], r"^20\d\d-\d\d-\d\d$")
            self.assertIn("stdio", profile["transports"])
            self.assertTrue(profile["activation_steps"])
            self.assertTrue(profile["fresh_session_proof"])
            self.assertIn(profile["format"], {"json", "toml"})
            scope = profile["scope_guidance"]
            self.assertIn(scope["default"], scope["options"])
            self.assertEqual(set(scope["options"]), set(scope["configuration_targets"]))
            configuration = profile["configuration_guidance"]
            self.assertEqual(configuration["format"], profile["format"])
            self.assertEqual(configuration["container"], profile["container"])
            self.assertIn("registration_command", configuration)
            self.assertTrue(configuration["server_fields"])
            self.assertTrue(configuration["server_alias_pattern"])
            activation = profile["activation_guidance"]
            self.assertEqual(activation["steps"], profile["activation_steps"])
            self.assertEqual(
                activation["post_write_state"],
                expected_activation_states[profile_id],
            )
            self.assertTrue(activation["inspection_steps"])
            tool_filter = profile["tool_filter_guidance"]
            self.assertTrue(tool_filter["controls"])
            self.assertTrue(tool_filter["default_policy"])

        gemini = profiles["gemini-cli"]
        self.assertEqual(gemini["scope_guidance"]["options"], ["user", "project"])
        self.assertEqual(gemini["container"], "mcpServers")
        self.assertEqual(gemini["transports"], ["stdio", "sse", "http"])
        self.assertTrue(
            {"trust", "includeTools"}
            <= set(gemini["configuration_guidance"]["server_fields"])
        )
        self.assertEqual(
            gemini["tool_filter_guidance"]["controls"],
            ["trust", "includeTools"],
        )
        opencode = profiles["opencode"]
        self.assertEqual(opencode["container"], "mcp")
        self.assertEqual(
            opencode["official_documentation"],
            "https://opencode.ai/docs/mcp-servers/",
        )

    def test_gemini_cli_configuration_preserves_supported_server_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".gemini" / "settings.json"
            server = {
                "command": "python",
                "args": ["-m", "rta_brain.mcp_server"],
                "trust": False,
                "includeTools": ["brain_capabilities", "brain_search"],
            }

            plan = plan_host_configuration(
                "gemini-cli", target, "rta-smriti", server
            )
            profile = host_profile("gemini-cli")
            for guidance in (
                "scope_guidance",
                "configuration_guidance",
                "activation_guidance",
                "tool_filter_guidance",
            ):
                self.assertEqual(plan[guidance], profile[guidance])
            installed = apply_host_configuration(
                plan,
                {"approved": True, "plan_digest": plan["plan_digest"]},
            )

            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["mcpServers"]["rta-smriti"],
                self._canonical_python_server(
                    trust=False,
                    includeTools=["brain_capabilities", "brain_search"],
                ),
            )
            self.assertEqual(installed["activation_state"], "restart_required")
            self.assertNotIn(str(target), json.dumps(plan))
            self.assertNotIn(str(target), json.dumps(installed))

    def test_gemini_cli_alias_with_underscore_fails_closed_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".gemini" / "settings.json"

            with self.assertRaisesRegex(
                ValueError, "Gemini CLI.*underscore"
            ):
                plan_host_configuration(
                    "gemini-cli",
                    target,
                    "rta_smriti",
                    {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
                )

            self.assertFalse(target.exists())

    def test_apply_derives_activation_state_from_selected_profile(self):
        expected = {
            "codex": "restart_required",
            "claude-code": "approval_check_required",
            "cursor": "activation_check_required",
            "zed": "server_panel_check_required",
            "opencode": "enablement_check_required",
            "gemini-cli": "restart_required",
        }
        server = {"command": "python", "args": ["-m", "rta_brain.mcp_server"]}

        with tempfile.TemporaryDirectory() as tmp:
            for profile_id, activation_state in expected.items():
                with self.subTest(profile_id=profile_id):
                    target = self._target_for_profile(Path(tmp) / profile_id, profile_id)
                    plan = plan_host_configuration(
                        profile_id, target, "rta-smriti", server
                    )
                    installed = apply_host_configuration(
                        plan,
                        {"approved": True, "plan_digest": plan["plan_digest"]},
                    )

                    self.assertEqual(installed["activation_state"], activation_state)
                    receipt = json.loads(
                        Path(installed["receipt_path"]).read_text(encoding="utf-8")
                    )
                    self.assertEqual(receipt["activation_state"], activation_state)

    def test_json_host_install_and_remove_are_previewed_backed_up_and_confirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / ".cursor" / "mcp.json"
            target.parent.mkdir()
            target.write_text(
                json.dumps({"mcpServers": {"existing": {"command": "keep"}}}),
                encoding="utf-8",
            )
            server = {"command": "python", "args": ["-m", "rta_brain.mcp_server"]}

            install = plan_host_configuration(
                "cursor", target, "rta-smriti", server, action="install"
            )
            self.assertTrue(install["backup_required"])
            self.assertNotIn(str(target), json.dumps(install))
            installed = apply_host_configuration(
                install,
                {"approved": True, "plan_digest": install["plan_digest"]},
            )

            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(payload["mcpServers"]["existing"]["command"], "keep")
            self.assertEqual(
                payload["mcpServers"]["rta-smriti"],
                self._canonical_python_server(),
            )
            self.assertTrue(Path(installed["backup_path"]).is_file())
            self.assertEqual(installed["activation_state"], "activation_check_required")
            self.assertEqual(installed["fresh_session_proof"], "pending")
            remove = plan_host_configuration(
                "cursor", target, "rta-smriti", server, action="remove"
            )
            removed = apply_host_configuration(
                remove,
                {"approved": True, "plan_digest": remove["plan_digest"]},
            )
            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertNotIn("rta-smriti", payload["mcpServers"])
            self.assertEqual(removed["state"], "removed")

    def test_json_collision_requires_explicit_preview_and_remove_restores_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            original = (
                b'{\n  "theme": "dark",\n  "mcpServers": {\n'
                b'    "rta-smriti": {"command": "legacy", "args": ["--keep"]}\n'
                b"  }\n}\n"
            )
            target.write_bytes(original)
            replacement = {
                "command": "python",
                "args": ["-m", "rta_brain.mcp_server"],
            }

            with self.assertRaisesRegex(ValueError, "unmanaged.*collision"):
                plan_host_configuration("cursor", target, "rta-smriti", replacement)

            install = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                replacement,
                replace_existing=True,
            )
            self.assertEqual(install["collision_state"], "explicit_replace_required")
            with self.assertRaisesRegex(PermissionError, "replacement approval"):
                apply_host_configuration(
                    install,
                    {"approved": True, "plan_digest": install["plan_digest"]},
                )
            apply_host_configuration(
                install,
                {
                    "approved": True,
                    "plan_digest": install["plan_digest"],
                    "replace_existing": True,
                },
            )

            remove = plan_host_configuration(
                "cursor", target, "rta-smriti", replacement, action="remove"
            )
            self.assertEqual(remove["restore_mode"], "managed_backup_exact")
            apply_host_configuration(
                remove,
                {"approved": True, "plan_digest": remove["plan_digest"]},
            )
            self.assertEqual(target.read_bytes(), original)

    def test_remove_rejects_a_forged_adjacent_restore_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            installed = apply_host_configuration(
                plan, {"approved": True, "plan_digest": plan["plan_digest"]}
            )
            forged = Path(installed["receipt_path"]).parent / "zzzz-forged.json"
            forged.write_text(
                json.dumps(
                    {
                        "schema": mcp_host_lifecycle.HOST_LIFECYCLE_SCHEMA,
                        "state": "installed",
                        "profile_id": "cursor",
                        "server_name": "rta-smriti",
                        "target_name": target.name,
                        "target_fingerprint": hashlib.sha256(
                            str(target).encode("utf-8")
                        ).hexdigest()[:16],
                        "after_digest": hashlib.sha256(
                            target.read_bytes()
                        ).hexdigest(),
                        "before_digest": "a" * 64,
                        "plan_digest": "b" * 64,
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "receipt authentication"):
                plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
                    action="remove",
                )

    def test_toml_collision_is_structured_validated_and_exactly_reversible(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".codex" / "config.toml"
            target.parent.mkdir()
            original = (
                b'model = "gpt-5"\n\n'
                b'[mcp_servers."rta-smriti"]\n'
                b'command = "legacy"\n'
                b'args = ["--keep"]\n\n'
                b'[mcp_servers.other]\ncommand = "other"\n'
            )
            target.write_bytes(original)
            replacement = {
                "command": "python",
                "args": ["-m", "rta_brain.mcp_server"],
                "enabled": True,
                "startup_timeout_sec": 15,
            }

            with self.assertRaisesRegex(ValueError, "unmanaged.*collision"):
                plan_host_configuration("codex", target, "rta-smriti", replacement)

            install = plan_host_configuration(
                "codex",
                target,
                "rta-smriti",
                replacement,
                replace_existing=True,
            )
            apply_host_configuration(
                install,
                {
                    "approved": True,
                    "plan_digest": install["plan_digest"],
                    "replace_existing": True,
                },
            )
            parsed = tomllib.loads(target.read_text(encoding="utf-8"))
            self.assertEqual(
                parsed["mcp_servers"]["rta-smriti"],
                self._canonical_python_server(
                    enabled=True,
                    startup_timeout_sec=15,
                ),
            )
            self.assertEqual(parsed["mcp_servers"]["other"]["command"], "other")

            remove = plan_host_configuration(
                "codex", target, "rta-smriti", replacement, action="remove"
            )
            apply_host_configuration(
                remove,
                {"approved": True, "plan_digest": remove["plan_digest"]},
            )
            self.assertEqual(target.read_bytes(), original)

    def test_plan_rejects_linked_or_oversized_host_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            target.write_bytes(b"x" * (1_048_576 + 1))
            with self.assertRaisesRegex(ValueError, "size limit"):
                plan_host_configuration(
                    "cursor", target, "rta-smriti", {"command": "python"}
                )

    def test_plan_rejects_oversized_generated_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            with self.assertRaisesRegex(ValueError, "size limit"):
                plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    {"command": "python", "args": ["x" * 1_048_576]},
                )

    def test_profile_lookup_rejects_unknown_host(self):
        with self.assertRaisesRegex(ValueError, "unsupported MCP host profile"):
            host_profile("unknown-host")

    def test_cli_previews_then_installs_without_printing_private_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            output = io.StringIO()
            arguments = [
                "mcp-host",
                "plan-install",
                "--profile",
                "cursor",
                "--target",
                str(target),
                "--command",
                "python",
                "--arg=-m",
                "--arg=rta_brain.mcp_server",
                "--json",
            ]
            with redirect_stdout(output):
                self.assertEqual(main(arguments), 0)
            plan = json.loads(output.getvalue())
            self.assertNotIn(str(target), output.getvalue())

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    main([
                        "mcp-host",
                        "install",
                        "--profile",
                        "cursor",
                        "--target",
                        str(target),
                        "--command",
                        "python",
                        "--arg=-m",
                        "--arg=rta_brain.mcp_server",
                        "--confirm-plan-digest",
                        plan["plan_digest"],
                        "--json",
                    ]),
                    0,
                )
            installed = json.loads(output.getvalue())
            self.assertEqual(installed["state"], "installed")
            self.assertNotIn(str(target), output.getvalue())
            self.assertTrue(target.is_file())

    def test_cli_issues_challenge_and_seals_only_server_observed_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            installed = apply_host_configuration(
                plan, {"approved": True, "plan_digest": plan["plan_digest"]}
            )
            receipt = Path(installed["receipt_path"])
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    main(
                        [
                            "mcp-host",
                            "challenge",
                            "--receipt",
                            str(receipt),
                            "--confirm-plan-digest",
                            plan["plan_digest"],
                            "--json",
                        ]
                    ),
                    0,
                )
            challenge = json.loads(output.getvalue())
            token = challenge["challenge_token"]
            self.assertTrue(token.startswith("rta_"))
            common = {
                "fresh_session_id": "server-session",
                "host_version": "cursor:2026.09",
                "tool_names": ["brain_capabilities", "brain_search"],
            }
            mcp_host_lifecycle.record_server_observed_tool_event(
                receipt,
                token,
                {
                    **common,
                    "tool_name": "brain_capabilities",
                    "status": "ok",
                    "capability": "mutating-tools-disabled",
                },
            )
            mcp_host_lifecycle.record_server_observed_tool_event(
                receipt,
                token,
                {
                    **common,
                    "tool_name": "brain_search",
                    "status": "ok",
                    "project": "atlas-demo",
                },
            )

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    main(
                        [
                            "mcp-host",
                            "prove",
                            "--receipt",
                            str(receipt),
                            "--challenge-token",
                            token,
                            "--confirm-plan-digest",
                            plan["plan_digest"],
                            "--json",
                        ]
                    ),
                    0,
                )
            proof = json.loads(output.getvalue())
            self.assertEqual(proof["state"], "protocol_verified")
            self.assertEqual(proof["verification_level"], "protocol_verified")
            self.assertFalse(proof["host_verified"])
            self.assertNotIn(token, output.getvalue())

    def test_completed_host_configuration_plan_is_terminal_against_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            confirmation = {"approved": True, "plan_digest": plan["plan_digest"]}

            first = apply_host_configuration(plan, confirmation)
            self.assertFalse(first["idempotent_replay"])
            with self.assertRaisesRegex(PermissionError, "completed.*terminal"):
                apply_host_configuration(plan, confirmation)

            target.write_bytes(plan._original)
            with self.assertRaisesRegex(PermissionError, "completed.*terminal"):
                apply_host_configuration(plan, confirmation)

    def test_approved_host_configuration_plan_rejects_post_confirmation_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            confirmation = {"approved": True, "plan_digest": plan["plan_digest"]}
            plan["action"] = "remove"

            with self.assertRaisesRegex(PermissionError, "changed after approval"):
                apply_host_configuration(plan, confirmation)

    def test_approved_host_configuration_plan_rejects_private_payload_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            confirmation = {"approved": True, "plan_digest": plan["plan_digest"]}
            plan._proposed = b'{}\n'

            with self.assertRaisesRegex(PermissionError, "changed after approval"):
                apply_host_configuration(plan, confirmation)

    def test_plan_enforces_profile_target_and_command_constraints(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            arbitrary = base / "mcp.json"
            with self.assertRaisesRegex(ValueError, "target.*Cursor"):
                plan_host_configuration(
                    "cursor",
                    arbitrary,
                    "rta-smriti",
                    {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
                )

            target = base / ".cursor" / "mcp.json"
            target.parent.mkdir()
            with self.assertRaisesRegex(ValueError, "launcher"):
                plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    {"command": "powershell.exe", "args": ["-Command", "whoami"]},
                )
            with self.assertRaisesRegex(ValueError, "unsupported.*field"):
                plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    {
                        "command": "python",
                        "args": ["-m", "rta_brain.mcp_server"],
                        "unexpected": True,
                    },
                )

    def test_plan_canonicalizes_and_binds_the_current_python_launcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()

            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            proposed = json.loads(plan._proposed.decode("utf-8"))
            installed_server = proposed["mcpServers"]["rta-smriti"]
            launcher = plan["effective_configuration_change"]["launcher"]

            self.assertEqual(installed_server, self._canonical_python_server())
            self.assertEqual(launcher["source"], "canonical-absolute-path")
            self.assertRegex(launcher["content_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn(str(Path(sys.executable).resolve()), json.dumps(plan))

    def test_plan_rejects_a_lookalike_launcher_outside_trusted_runtime_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / ".cursor" / "mcp.json"
            target.parent.mkdir()
            lookalike = base / "rta-brain.exe"
            lookalike.write_bytes(b"not-the-installed-launcher")

            with self.assertRaisesRegex(ValueError, "trusted runtime root"):
                plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    {"command": str(lookalike), "args": []},
                )

    def test_apply_revalidates_launcher_identity_after_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / ".cursor" / "mcp.json"
            target.parent.mkdir()
            launcher = base / "rta-brain.exe"
            launcher.write_bytes(b"trusted-launcher-v1")
            with patch(
                "rta_brain.mcp_host_lifecycle._trusted_launcher_roots",
                return_value=(base.resolve(),),
            ):
                plan = plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    {"command": str(launcher), "args": []},
                )
                launcher.write_bytes(b"untrusted-launcher-v2")

                with self.assertRaisesRegex(
                    PermissionError, "launcher identity changed"
                ):
                    apply_host_configuration(
                        plan,
                        {"approved": True, "plan_digest": plan["plan_digest"]},
                    )
            with self.assertRaisesRegex(ValueError, "control character"):
                plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    {
                        "command": "python",
                        "args": ["-m", "rta_brain.mcp_server", "bad\nargument"],
                    },
                )
            with self.assertRaisesRegex(ValueError, "only isolated mode"):
                plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    {
                        "command": "python",
                        "args": [
                            "-c",
                            "print('untrusted')",
                            "-m",
                            "rta_brain.mcp_server",
                        ],
                    },
                )

    def test_preview_exposes_redacted_effective_change_and_target_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            private_brain = str(Path(tmp) / "private" / "brain")
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {
                    "command": "python",
                    "args": [
                        "-m",
                        "rta_brain.mcp_server",
                        "--brain-dir",
                        private_brain,
                        f"--db={private_brain}.sqlite",
                    ],
                    "env": {"PRIVATE_TOKEN": "never-print-this"},
                },
            )

            serialized = json.dumps(plan, sort_keys=True)
            self.assertEqual(plan["target"]["classification"], "project")
            self.assertEqual(plan["target"]["policy"], ".cursor/mcp.json")
            self.assertEqual(
                plan["effective_configuration_change"]["container"], "mcpServers"
            )
            preview = plan["effective_configuration_change"]["server"]
            self.assertEqual(preview["command"], "<canonical-launcher>")
            self.assertEqual(
                preview["args"][:4],
                ["-I", "-m", "rta_brain.mcp_server", "--brain-dir"],
            )
            self.assertRegex(preview["args"][4], r"^<redacted-local-value:[0-9a-f]{12}>$")
            self.assertRegex(
                preview["args"][5],
                r"^--db=<redacted-local-value:[0-9a-f]{12}>$",
            )
            launcher = plan["effective_configuration_change"]["launcher"]
            self.assertEqual(launcher["executable"], "python")
            self.assertEqual(launcher["source"], "canonical-absolute-path")
            self.assertRegex(launcher["path_fingerprint"], r"^[0-9a-f]{64}$")
            self.assertRegex(launcher["content_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn(str(target), serialized)
            self.assertNotIn(private_brain, serialized)
            self.assertNotIn("never-print-this", serialized)
            self.assertEqual(preview["env"]["keys"], ["PRIVATE_TOKEN"])
            self.assertEqual(preview["env"]["values"], "<redacted>")

    def test_versioned_python_runtime_name_is_canonicalized_as_python(self):
        with tempfile.TemporaryDirectory() as tmp, patch(
            "rta_brain.mcp_host_lifecycle.sys.executable",
            "/usr/bin/python3.12",
        ), patch("rta_brain.mcp_host_lifecycle.os.path.samefile", return_value=True), patch(
            "rta_brain.mcp_host_lifecycle._stable_file_binding",
            return_value={
                "canonical_path": "/usr/bin/python3.12",
                "path_fingerprint": "a" * 64,
                "content_sha256": "b" * 64,
                "identity_fingerprint": "c" * 64,
                "size": 1,
            },
        ):
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {
                    "command": "/usr/bin/python3.12",
                    "args": ["-I", "-m", "rta_brain.mcp_server"],
                },
            )

        self.assertEqual(
            plan["effective_configuration_change"]["launcher"]["executable"],
            "python",
        )

    def test_opencode_adapter_emits_current_documented_mcp_name_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "opencode.json"
            plan = plan_host_configuration(
                "opencode",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            apply_host_configuration(
                plan,
                {"approved": True, "plan_digest": plan["plan_digest"]},
            )

            payload = json.loads(target.read_text(encoding="utf-8"))
            self.assertNotIn("servers", payload["mcp"])
            self.assertEqual(
                payload["mcp"]["rta-smriti"],
                {
                    "type": "local",
                    "command": [
                        str(Path(sys.executable).resolve()),
                        "-I",
                        "-m",
                        "rta_brain.mcp_server",
                    ],
                    "enabled": True,
                },
            )

    def test_apply_rejects_same_content_target_identity_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            original = b'{"mcpServers": {}}\n'
            target.write_bytes(original)
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )

            replacement = target.with_suffix(".replacement")
            replacement.write_bytes(original)
            replacement.replace(target)

            with self.assertRaisesRegex(PermissionError, "identity changed"):
                apply_host_configuration(
                    plan,
                    {"approved": True, "plan_digest": plan["plan_digest"]},
                )

    def test_apply_rechecks_target_identity_immediately_before_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            canonical_target = canonicalize_system_root_alias(target)
            original = b'{"mcpServers": {}}\n'
            target.write_bytes(original)
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            real_atomic_write = mcp_host_lifecycle._atomic_write
            swapped = False

            def swap_before_target_write(path, content, **kwargs):
                nonlocal swapped
                if path == canonical_target and content == plan._proposed and not swapped:
                    swapped = True
                    replacement = canonical_target.with_suffix(".replacement")
                    replacement.write_bytes(original)
                    replacement.replace(canonical_target)
                return real_atomic_write(path, content, **kwargs)

            with (
                patch(
                    "rta_brain.mcp_host_lifecycle._atomic_write",
                    side_effect=swap_before_target_write,
                ),
                self.assertRaisesRegex(PermissionError, "identity changed"),
            ):
                apply_host_configuration(
                    plan,
                    {"approved": True, "plan_digest": plan["plan_digest"]},
                )

    def test_apply_rejects_parent_directory_identity_swap(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / ".cursor" / "mcp.json"
            target.parent.mkdir()
            original = b'{"mcpServers": {}}\n'
            target.write_bytes(original)
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )

            moved_parent = base / ".cursor-original"
            target.parent.rename(moved_parent)
            target.parent.mkdir()
            target.write_bytes(original)

            with self.assertRaisesRegex(PermissionError, "parent identity changed"):
                apply_host_configuration(
                    plan,
                    {"approved": True, "plan_digest": plan["plan_digest"]},
                )

    def test_apply_rechecks_digest_immediately_before_replace(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            canonical_target = canonicalize_system_root_alias(target)
            target.write_bytes(b'{"mcpServers": {}}\n')
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            real_atomic_write = mcp_host_lifecycle._atomic_write
            mutated = False

            def mutate_before_target_write(path, content, **kwargs):
                nonlocal mutated
                if path == canonical_target and content == plan._proposed and not mutated:
                    mutated = True
                    canonical_target.write_bytes(b'{"mcpServers": {"other": {}}}\n')
                return real_atomic_write(path, content, **kwargs)

            with (
                patch(
                    "rta_brain.mcp_host_lifecycle._atomic_write",
                    side_effect=mutate_before_target_write,
                ),
                self.assertRaisesRegex(PermissionError, "configuration changed before write"),
            ):
                apply_host_configuration(
                    plan,
                    {"approved": True, "plan_digest": plan["plan_digest"]},
                )

    def test_receipt_failure_restores_original_host_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir()
            original = b'{"mcpServers":{"existing":{"command":"keep"}}}\n'
            target.write_bytes(original)
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            real_atomic_write = mcp_host_lifecycle._atomic_write

            def fail_receipt(path, content, **kwargs):
                if path.parent.name == "receipts":
                    raise OSError("receipt storage unavailable")
                return real_atomic_write(path, content, **kwargs)

            with (
                patch(
                    "rta_brain.mcp_host_lifecycle._atomic_write",
                    side_effect=fail_receipt,
                ),
                self.assertRaisesRegex(OSError, "receipt storage unavailable"),
            ):
                apply_host_configuration(
                    plan,
                    {"approved": True, "plan_digest": plan["plan_digest"]},
                )

            self.assertEqual(target.read_bytes(), original)

    def test_fresh_session_proof_requires_nonce_bound_server_observations(self):
        self.assertTrue(
            hasattr(mcp_host_lifecycle, "issue_fresh_session_challenge"),
            "nonce challenge API is missing",
        )
        self.assertTrue(
            hasattr(mcp_host_lifecycle, "record_server_observed_tool_event"),
            "server observation API is missing",
        )
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            installed = apply_host_configuration(
                plan, {"approved": True, "plan_digest": plan["plan_digest"]}
            )
            receipt_path = Path(installed["receipt_path"])
            confirmation = {
                "approved": True,
                "configuration_plan_digest": plan["plan_digest"],
            }

            self_attested = record_fresh_session_proof(
                receipt_path,
                {
                    "fresh_session_id": "claimed-session",
                    "started_after_configuration": True,
                    "tool_names": ["brain_capabilities", "brain_search"],
                    "search_status": "ok",
                    "denied_capability_status": "denied",
                },
                confirmation,
            )
            self.assertEqual(self_attested["state"], "unverified")
            self.assertIn("nonce_challenge_missing", self_attested["reason_codes"])

            challenge = mcp_host_lifecycle.issue_fresh_session_challenge(
                receipt_path,
                confirmation,
            )
            token = challenge["challenge_token"]
            common = {
                "fresh_session_id": "opaque-session-1",
                "host_version": "cursor-2026.09",
                "configuration_digest": installed["after_digest"],
                "tool_names": [
                    "brain_capabilities",
                    "brain_search",
                    "brain_memory_record",
                ],
            }
            first = mcp_host_lifecycle.record_server_observed_tool_event(
                receipt_path,
                token,
                {
                    **common,
                    "tool_name": "brain_search",
                    "status": "ok",
                    "project": "atlas-demo",
                },
            )
            self.assertEqual(first["state"], "observed")
            mcp_host_lifecycle.record_server_observed_tool_event(
                receipt_path,
                token,
                {
                    **common,
                    "tool_name": "brain_memory_record",
                    "status": "denied",
                    "capability": "write-memory",
                },
            )

            proof = record_fresh_session_proof(
                receipt_path,
                {"challenge_token": token},
                confirmation,
            )
            self.assertEqual(proof["state"], "protocol_verified")
            self.assertEqual(proof["verification_level"], "protocol_verified")
            self.assertFalse(proof["host_verified"])
            serialized = json.dumps(proof)
            self.assertNotIn(token, serialized)
            self.assertNotIn("opaque-session-1", serialized)
            self.assertNotIn("cursor-2026.09", serialized)
            self.assertTrue(proof["evidence"]["atlas_search_observed"])
            self.assertTrue(proof["evidence"]["denied_capability_observed"])

            with self.assertRaisesRegex(PermissionError, "sealed"):
                mcp_host_lifecycle.record_server_observed_tool_event(
                    receipt_path,
                    token,
                    {
                        **common,
                        "tool_name": "brain_search",
                        "status": "ok",
                        "project": "atlas-demo",
                    },
                )

            with self.assertRaisesRegex(PermissionError, "consumed"):
                record_fresh_session_proof(
                    receipt_path,
                    {"challenge_token": token},
                    confirmation,
                )

    def test_fresh_session_challenge_expires_before_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            issued_at = datetime(2026, 9, 5, 10, 0, tzinfo=UTC)
            with patch(
                "rta_brain.mcp_host_lifecycle._utc_now",
                return_value=issued_at,
            ):
                plan = plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
                )
                installed = apply_host_configuration(
                    plan, {"approved": True, "plan_digest": plan["plan_digest"]}
                )
                receipt_path = Path(installed["receipt_path"])
                confirmation = {
                    "approved": True,
                    "configuration_plan_digest": plan["plan_digest"],
                }
                challenge = mcp_host_lifecycle.issue_fresh_session_challenge(
                    receipt_path, confirmation
                )

            with (
                patch(
                    "rta_brain.mcp_host_lifecycle._utc_now",
                    return_value=issued_at + timedelta(minutes=6),
                ),
                self.assertRaisesRegex(PermissionError, "expired"),
            ):
                mcp_host_lifecycle.record_server_observed_tool_event(
                    receipt_path,
                    challenge["challenge_token"],
                    {
                        "fresh_session_id": "expired-session",
                        "host_version": "cursor-2026.09",
                        "configuration_digest": installed["after_digest"],
                        "tool_names": ["brain_search"],
                        "tool_name": "brain_search",
                        "status": "ok",
                        "project": "atlas-demo",
                    },
                )

    def test_server_observation_rejects_wrong_nonce_and_binding_drift(self):
        self.assertTrue(hasattr(mcp_host_lifecycle, "issue_fresh_session_challenge"))
        self.assertTrue(hasattr(mcp_host_lifecycle, "record_server_observed_tool_event"))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            installed = apply_host_configuration(
                plan, {"approved": True, "plan_digest": plan["plan_digest"]}
            )
            receipt_path = Path(installed["receipt_path"])
            confirmation = {
                "approved": True,
                "configuration_plan_digest": plan["plan_digest"],
            }
            challenge = mcp_host_lifecycle.issue_fresh_session_challenge(
                receipt_path, confirmation
            )
            event = {
                "fresh_session_id": "session-a",
                "host_version": "cursor-2026.09",
                "configuration_digest": installed["after_digest"],
                "tool_names": ["brain_capabilities", "brain_search"],
                "tool_name": "brain_search",
                "status": "ok",
                "project": "atlas-demo",
            }

            with self.assertRaisesRegex(PermissionError, "challenge"):
                mcp_host_lifecycle.record_server_observed_tool_event(
                    receipt_path, "wrong-token", event
                )

            mcp_host_lifecycle.record_server_observed_tool_event(
                receipt_path, challenge["challenge_token"], event
            )
            with self.assertRaisesRegex(ValueError, "session binding"):
                mcp_host_lifecycle.record_server_observed_tool_event(
                    receipt_path,
                    challenge["challenge_token"],
                    {**event, "fresh_session_id": "session-b"},
                )
            with self.assertRaisesRegex(ValueError, "configuration binding"):
                mcp_host_lifecycle.record_server_observed_tool_event(
                    receipt_path,
                    challenge["challenge_token"],
                    {**event, "configuration_digest": "f" * 64},
                )

    def test_fresh_session_proof_rejects_oversized_receipt_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            plan = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            installed = apply_host_configuration(
                plan, {"approved": True, "plan_digest": plan["plan_digest"]}
            )
            receipt_path = Path(installed["receipt_path"])
            confirmation = {
                "approved": True,
                "configuration_plan_digest": plan["plan_digest"],
            }
            challenge = mcp_host_lifecycle.issue_fresh_session_challenge(
                receipt_path, confirmation
            )
            valid_event = {
                "fresh_session_id": "opaque-session-1",
                "host_version": "cursor-2026.09",
                "configuration_digest": installed["after_digest"],
                "tool_names": ["brain_capabilities", "brain_search"],
                "tool_name": "brain_search",
                "status": "ok",
                "project": "atlas-demo",
            }

            with self.assertRaisesRegex(ValueError, "session identity.*limit"):
                mcp_host_lifecycle.record_server_observed_tool_event(
                    receipt_path,
                    challenge["challenge_token"],
                    {**valid_event, "fresh_session_id": "x" * 257},
                )
            with self.assertRaisesRegex(ValueError, "tool catalog.*limit"):
                mcp_host_lifecycle.record_server_observed_tool_event(
                    receipt_path,
                    challenge["challenge_token"],
                    {**valid_event, "tool_names": [f"tool-{i}" for i in range(257)]},
                )

            receipt_path.write_bytes(b"x" * (1_048_576 + 1))
            with self.assertRaisesRegex(ValueError, "receipt.*size limit"):
                record_fresh_session_proof(
                    receipt_path,
                    {"challenge_token": challenge["challenge_token"]},
                    confirmation,
                )

    def test_fresh_session_proof_rejects_a_forged_unbound_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipts = Path(tmp) / "invented-control" / "receipts"
            receipts.mkdir(parents=True)
            plan_digest = "a" * 64
            receipt_path = receipts / f"{plan_digest}.json"
            receipt_path.write_text(
                json.dumps({
                    "schema": mcp_host_lifecycle.HOST_LIFECYCLE_SCHEMA,
                    "state": "installed",
                    "profile_id": "zed",
                    "server_name": "rta-smriti",
                    "plan_digest": plan_digest,
                    "target_fingerprint": "b" * 16,
                    "after_digest": "c" * 64,
                    "activation_state": "restart_required",
                    "fresh_session_proof": "pending",
                }),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "receipt authentication"):
                record_fresh_session_proof(
                    receipt_path,
                    {
                        "fresh_session_id": "forged-session",
                        "started_after_configuration": True,
                        "server_name": "rta-smriti",
                        "tool_names": ["brain_capabilities", "brain_search"],
                        "search_status": "ok",
                        "denied_capability_status": "denied",
                    },
                    {
                        "approved": True,
                        "configuration_plan_digest": plan_digest,
                    },
                )


if __name__ == "__main__":
    unittest.main()
