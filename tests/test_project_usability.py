import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rta_brain.db import connect, init_project
from rta_brain.platform_paths import canonicalize_system_root_alias
from rta_brain.project import agent_file_text, install_local, mcp_config_payload


ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "rta-brain.py"


def run_cli(*args, cwd=None):
    return subprocess.run([sys.executable, str(CLI), *args], text=True, capture_output=True, cwd=cwd or ROOT)


class RtaBrainProjectUsabilityTests(unittest.TestCase):
    def test_standalone_setup_commands_do_not_open_the_default_brain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            (repo / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            inaccessible_default = root / "blocked" / "brain.sqlite"

            bootstrap = run_cli(
                "--db", str(inaccessible_default),
                "--json", "bootstrap-project", str(repo),
                "--project", "demo", "--brain-dir", str(root / "brains"),
            )
            self.assertEqual(bootstrap.returncode, 0, bootstrap.stderr)

            install = run_cli(
                "--db", str(inaccessible_default),
                "--json", "install-local", "--target", str(root / "bin"),
            )
            self.assertEqual(install.returncode, 0, install.stderr)
            self.assertFalse(inaccessible_default.exists())
    def test_bootstrap_project_creates_brain_indexes_repo_and_writes_agent_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "demo-repo"
            repo.mkdir()
            (repo / "main.py").write_text("def memory_gate():\n    return 'fresh'\n", encoding="utf-8")
            brain_dir = Path(tmp) / "brains"

            result = run_cli(
                "--json",
                "bootstrap-project",
                str(repo),
                "--project",
                "demo",
                "--brain-dir",
                str(brain_dir),
                "--write-agents",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "ok")
            self.assertTrue(Path(payload["db_path"]).exists())
            self.assertGreaterEqual(payload["ingest"]["indexed_files"], 1)
            self.assertTrue((repo / "AGENTS.rta-smriti.md").exists())
            self.assertTrue((repo / "AGENTS.md").exists())
            self.assertIn("Rta-Smriti Local Brain", (repo / "AGENTS.md").read_text(encoding="utf-8"))
            self.assertIn("agent_index_file", payload)
            self.assertIn("context-pack", payload["next_commands"]["context_pack"])
            self.assertEqual(payload["shell"], "powershell" if os.name == "nt" else "posix")
            if os.name == "nt":
                self.assertTrue(payload["next_commands"]["context_pack"].startswith("& '"))
            else:
                self.assertFalse(payload["next_commands"]["context_pack"].startswith("& "))

            self_check = run_cli("--db", payload["db_path"], "--json", "self-check", "--project", "demo")
            self.assertEqual(self_check.returncode, 0, self_check.stderr)
            health = json.loads(self_check.stdout)
            self.assertTrue(health["ready"])
            self.assertGreaterEqual(health["sources"], 1)
            self.assertEqual(health["freshness"]["mode"], "summary")

            self_check_full = run_cli("--db", payload["db_path"], "--json", "self-check", "--project", "demo", "--check-files")
            self.assertEqual(self_check_full.returncode, 0, self_check_full.stderr)
            full_health = json.loads(self_check_full.stdout)
            self.assertEqual(full_health["freshness"]["mode"], "file-hash")
            self.assertEqual(full_health["freshness"]["state"], "fresh")
            self.assertEqual(full_health["freshness"]["changed"], 0)
            self.assertEqual(full_health["freshness"]["added"], 0)

    def test_projects_list_reports_registered_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "brain.sqlite"
            init = run_cli("--db", str(db), "init", "--project", "demo", "--root", tmp)
            self.assertEqual(init.returncode, 0, init.stderr)
            result = run_cli("--db", str(db), "--json", "projects-list")
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["projects"][0]["name"], "demo")

    def test_bootstrap_refuses_agent_file_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "linked-repo"
            repo.mkdir()
            (repo / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            victim = Path(tmp) / "victim.md"
            victim.write_text("keep me", encoding="utf-8")
            try:
                (repo / "AGENTS.md").symlink_to(victim)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            result = run_cli(
                "--json", "bootstrap-project", str(repo), "--project", "linked",
                "--brain-dir", str(Path(tmp) / "brains"), "--write-agents",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep me")
            self.assertFalse((repo / "AGENTS.rta-smriti.md").exists())

    def test_bootstrap_refuses_hard_linked_agent_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "hard-linked-repo"
            repo.mkdir()
            (repo / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            victim = Path(tmp) / "victim.md"
            victim.write_text("keep me", encoding="utf-8")
            try:
                (repo / "AGENTS.md").hardlink_to(victim)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            result = run_cli(
                "--json", "bootstrap-project", str(repo), "--project", "linked",
                "--brain-dir", str(Path(tmp) / "brains"), "--write-agents",
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep me")
            self.assertFalse((repo / "AGENTS.rta-smriti.md").exists())

    def test_bootstrap_refuses_hard_linked_brain_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            (repo / "main.py").write_text("VALUE = 1\n", encoding="utf-8")
            brain_dir = Path(tmp) / "brains"
            brain_dir.mkdir()
            victim = Path(tmp) / "victim.sqlite"
            victim.write_text("keep me", encoding="utf-8")
            (brain_dir / "demo.sqlite").hardlink_to(victim)
            result = run_cli("--json", "bootstrap-project", str(repo), "--project", "demo", "--brain-dir", str(brain_dir))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("hard-linked brain database", result.stderr)
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep me")

    def test_install_local_creates_wrappers_that_work_from_another_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "bin"
            result = run_cli("--json", "install-local", "--target", str(target))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "ok")
            suffix = ".cmd" if os.name == "nt" else ""
            wrapper = target / f"rta-brain{suffix}"
            mcp_wrapper = target / f"rta-brain-mcp{suffix}"
            self.assertTrue(wrapper.exists())
            self.assertTrue(mcp_wrapper.exists())

            doctor = subprocess.run(
                [str(wrapper), "--db", str(Path(tmp) / "brain.sqlite"), "--json", "doctor"],
                text=True,
                capture_output=True,
                cwd=tmp,
            )
            self.assertEqual(doctor.returncode, 0, doctor.stderr)
            self.assertEqual(json.loads(doctor.stdout)["status"], "ok")

    def test_installed_distribution_uses_module_commands_when_source_wrappers_are_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            installed_package_root = root / "site-packages"
            installed_package_root.mkdir()
            db = root / "brains" / "demo.sqlite"
            repo = root / "repo"
            repo.mkdir()
            conn = connect(db)
            try:
                init_project(conn, "demo", str(repo))
            finally:
                conn.close()

            agent_text = agent_file_text(installed_package_root, db, "demo")
            self.assertIn("rta_brain.cli", agent_text)
            self.assertIn("rta_brain.mcp_server", agent_text)
            self.assertNotIn("site-packages\\rta-brain.cmd", agent_text)
            self.assertNotIn("site-packages/rta-brain", agent_text)

            mcp = mcp_config_payload(str(db), "demo", "rta-smriti", installed_package_root)
            server = mcp["config"]["mcpServers"]["rta-smriti"]
            self.assertEqual(Path(server["command"]), Path(sys.executable))
            self.assertEqual(server["args"][:3], ["-I", "-m", "rta_brain.mcp_server"])

            target = root / "bin"
            install_local(target, installed_package_root)
            suffix = ".cmd" if os.name == "nt" else ""
            cli_wrapper = (target / f"rta-brain{suffix}").read_text(encoding="utf-8")
            mcp_wrapper = (target / f"rta-brain-mcp{suffix}").read_text(encoding="utf-8")
            self.assertIn("-I", cli_wrapper)
            self.assertIn("-I", mcp_wrapper)
            self.assertIn("rta_brain.cli", cli_wrapper)
            self.assertIn("rta_brain.mcp_server", mcp_wrapper)
            self.assertNotIn("site-packages\\rta-brain.py", cli_wrapper)

    def test_install_local_emits_posix_shell_wrappers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "bin"
            installed_package_root = root / "site-packages"
            installed_package_root.mkdir()

            payload = install_local(target, installed_package_root, shell="posix")
            agent_text = agent_file_text(installed_package_root, root / "brain.sqlite", "demo", shell="posix")

            self.assertEqual(payload["shell"], "posix")
            self.assertEqual(Path(payload["wrappers"][0]).name, "rta-brain")
            self.assertEqual(Path(payload["wrappers"][1]).name, "rta-brain-mcp")
            wrapper = (target / "rta-brain").read_text(encoding="utf-8")
            self.assertTrue(wrapper.startswith("#!/bin/sh\n"))
            self.assertIn("-I -m rta_brain.cli", wrapper)
            self.assertNotIn(".cmd", payload["shell_command"])
            self.assertIn("```bash", agent_text)
            self.assertNotIn("```powershell", agent_text)

    def test_install_local_refuses_a_linked_target_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            destination = root / "destination"
            destination.mkdir()
            target = root / "bin"
            try:
                target.symlink_to(destination, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            with self.assertRaisesRegex(ValueError, "safe directory"):
                install_local(target, root / "site-packages")

            self.assertEqual(list(destination.iterdir()), [])

    def test_install_local_refuses_a_hard_linked_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "bin"
            target.mkdir()
            suffix = ".cmd" if os.name == "nt" else ""
            wrapper = target / f"rta-brain{suffix}"
            victim = root / "keep-me.txt"
            victim.write_text("keep me\n", encoding="utf-8")
            try:
                wrapper.hardlink_to(victim)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")

            with self.assertRaisesRegex(ValueError, "hard-linked"):
                install_local(target, root / "site-packages")

            self.assertEqual(victim.read_text(encoding="utf-8"), "keep me\n")

    def test_install_local_validates_both_wrappers_before_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "bin"
            target.mkdir()
            suffix = ".cmd" if os.name == "nt" else ""
            cli_wrapper = target / f"rta-brain{suffix}"
            cli_wrapper.write_text("old wrapper\n", encoding="utf-8")
            mcp_wrapper = target / f"rta-brain-mcp{suffix}"
            victim = root / "keep-me.txt"
            victim.write_text("keep me\n", encoding="utf-8")
            try:
                mcp_wrapper.hardlink_to(victim)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")

            with self.assertRaisesRegex(ValueError, "hard-linked"):
                install_local(target, root / "site-packages")

            self.assertEqual(
                cli_wrapper.read_text(encoding="utf-8"), "old wrapper\n"
            )
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep me\n")

    def test_install_local_refuses_a_non_regular_wrapper_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "bin"
            target.mkdir()
            suffix = ".cmd" if os.name == "nt" else ""
            wrapper = target / f"rta-brain{suffix}"
            wrapper.mkdir()

            with self.assertRaisesRegex(ValueError, "regular file"):
                install_local(target, root / "site-packages")

            self.assertTrue(wrapper.is_dir())

    def test_install_local_refuses_a_reparse_target_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "bin"
            target.mkdir()
            canonical_target = canonicalize_system_root_alias(target)
            real_lstat = Path.lstat

            def report_target_as_reparse(path):
                info = real_lstat(path)
                if path == canonical_target:
                    return SimpleNamespace(
                        st_mode=info.st_mode,
                        st_file_attributes=0x400,
                    )
                return info

            with patch.object(
                Path, "lstat", autospec=True, side_effect=report_target_as_reparse
            ), self.assertRaisesRegex(ValueError, "safe directory"):
                install_local(target, root / "site-packages")

            self.assertEqual(list(target.iterdir()), [])

    def test_install_local_atomically_replaces_regular_wrappers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "bin"
            target.mkdir()
            suffix = ".cmd" if os.name == "nt" else ""
            wrapper = target / f"rta-brain{suffix}"
            wrapper.write_text("old wrapper\n", encoding="utf-8")

            result = install_local(target, root / "site-packages")

            self.assertEqual(result["status"], "ok")
            self.assertNotEqual(
                wrapper.read_text(encoding="utf-8"), "old wrapper\n"
            )


if __name__ == "__main__":
    unittest.main()
