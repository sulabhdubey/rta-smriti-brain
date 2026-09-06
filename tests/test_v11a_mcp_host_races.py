import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import mcp_host_lifecycle
from rta_brain.mcp_host_lifecycle import (
    apply_host_configuration,
    plan_host_configuration,
)
from rta_brain.platform_paths import canonicalize_system_root_alias


class McpHostLifecycleRaceTests(unittest.TestCase):
    def setUp(self):
        self._authority_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._authority_directory.cleanup)
        self.authority_root = Path(self._authority_directory.name)
        authority_patch = patch(
            "rta_brain.mcp_host_lifecycle._host_authority_root",
            return_value=self.authority_root,
        )
        authority_patch.start()
        self.addCleanup(authority_patch.stop)

    @staticmethod
    def _server(*, marker: str = "current") -> dict[str, object]:
        return {
            "command": str(Path(sys.executable).resolve()),
            "args": ["-I", "-m", "rta_brain.mcp_server", "--project", marker],
        }

    @staticmethod
    def _approval(plan, *, replace_existing: bool = False) -> dict[str, object]:
        return {
            "approved": True,
            "plan_digest": plan["plan_digest"],
            "replace_existing": replace_existing,
        }

    def test_project_target_keeps_backups_and_receipts_in_private_authority_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            target = project / ".cursor" / "mcp.json"
            target.parent.mkdir(parents=True)
            original = json.dumps(
                {
                    "privateEndpoint": "https://internal.example.invalid",
                    "mcpServers": {"existing": {"command": "keep"}},
                }
            ).encode("utf-8")
            target.write_bytes(original)

            plan = plan_host_configuration(
                "cursor", target, "rta-smriti", self._server()
            )
            result = apply_host_configuration(plan, self._approval(plan))

            receipt = Path(result["receipt_path"])
            backup = Path(result["backup_path"])
            self.assertTrue(receipt.is_relative_to(self.authority_root))
            self.assertTrue(backup.is_relative_to(self.authority_root))
            self.assertIn(plan["target_fingerprint"], receipt.parts)
            self.assertIn(plan["target_fingerprint"], backup.parts)
            self.assertEqual(backup.read_bytes(), original)
            self.assertFalse((target.parent / ".rta-smriti-host-lifecycle").exists())
            self.assertNotIn(str(target), json.dumps(result))

    def test_concurrent_apply_has_one_target_scoped_winner(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir(parents=True)
            canonical_target = canonicalize_system_root_alias(target)
            plan = plan_host_configuration(
                "cursor", target, "rta-smriti", self._server()
            )
            entered_target_write = threading.Event()
            release_target_write = threading.Event()
            real_atomic_write = mcp_host_lifecycle._atomic_write
            results: list[object] = []

            def blocking_atomic_write(path, content, **kwargs):
                if path == canonical_target and not entered_target_write.is_set():
                    entered_target_write.set()
                    if not release_target_write.wait(timeout=5):
                        raise TimeoutError("test did not release target write")
                return real_atomic_write(path, content, **kwargs)

            def apply_once():
                try:
                    results.append(
                        apply_host_configuration(plan, self._approval(plan))
                    )
                except PermissionError as exc:
                    results.append(exc)

            with patch(
                "rta_brain.mcp_host_lifecycle._atomic_write",
                side_effect=blocking_atomic_write,
            ):
                first = threading.Thread(target=apply_once)
                first.start()
                self.assertTrue(entered_target_write.wait(timeout=5))
                second = threading.Thread(target=apply_once)
                second.start()
                second.join(timeout=5)
                release_target_write.set()
                first.join(timeout=5)

            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertEqual(sum(isinstance(item, dict) for item in results), 1)
            failures = [item for item in results if isinstance(item, BaseException)]
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], PermissionError)
            self.assertIn("already in progress", str(failures[0]))

    def test_remove_skips_managed_predecessor_and_restores_pre_managed_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir(parents=True)

            first = plan_host_configuration(
                "cursor", target, "rta-smriti", self._server(marker="first")
            )
            apply_host_configuration(first, self._approval(first))

            second = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                self._server(marker="second"),
                replace_existing=True,
            )
            apply_host_configuration(
                second,
                self._approval(second, replace_existing=True),
            )

            remove = plan_host_configuration(
                "cursor",
                target,
                "rta-smriti",
                self._server(marker="second"),
                action="remove",
            )
            self.assertEqual(remove["restore_mode"], "managed_backup_exact")
            apply_host_configuration(remove, self._approval(remove))

            self.assertFalse(target.exists())

    def test_remove_rejects_ambiguous_authenticated_restore_heads(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / ".cursor" / "mcp.json"
            target.parent.mkdir(parents=True)
            install = plan_host_configuration(
                "cursor", target, "rta-smriti", self._server()
            )
            result = apply_host_configuration(install, self._approval(install))
            receipt = Path(result["receipt_path"])
            receipt.with_name("duplicate.json").write_bytes(receipt.read_bytes())

            with self.assertRaisesRegex(ValueError, "restore head is ambiguous"):
                plan_host_configuration(
                    "cursor",
                    target,
                    "rta-smriti",
                    self._server(),
                    action="remove",
                )

    def test_toml_removal_ignores_header_text_inside_multiline_string(self):
        original = b'''note = """
[mcp_servers."rta-smriti"]
This is documentation, not a table.
"""

[mcp_servers."rta-smriti"]
command = "python"
args = []

[mcp_servers.keep]
command = "keep"
args = []
'''

        updated = mcp_host_lifecycle._toml_update(
            original,
            "rta-smriti",
            {},
            "remove",
        )

        parsed = mcp_host_lifecycle._parse_toml(updated)
        self.assertIn('[mcp_servers."rta-smriti"]', parsed["note"])
        self.assertEqual(parsed["mcp_servers"], {"keep": {"command": "keep", "args": []}})

    def test_equivalent_windows_target_spellings_share_one_fingerprint(self):
        first = Path(r"C:\Workspace\Example\.codex\config.toml")
        second = Path(r"c:\workspace\example\.CODEX\CONFIG.TOML")

        with patch.object(
            mcp_host_lifecycle.os.path,
            "normcase",
            side_effect=lambda value: str(value).replace("/", "\\").casefold(),
        ):
            self.assertEqual(
                mcp_host_lifecycle._target_fingerprint(first),
                mcp_host_lifecycle._target_fingerprint(second),
            )


if __name__ == "__main__":
    unittest.main()
