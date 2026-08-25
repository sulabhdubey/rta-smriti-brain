import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import chdir
from pathlib import Path
from unittest.mock import patch

from rta_brain import repository
from rta_brain.hooks import _cli_invocation


def _shell_command(*parts: Path | str) -> str:
    values = [str(part).replace("\\", "/") for part in parts]
    if sys.platform == "win32":
        return " ".join(f'"{value}"' for value in values)
    return " ".join(shlex.quote(value) for value in values)


@unittest.skipUnless(shutil.which("git"), "Git is required")
class GitProcessSecurityTests(unittest.TestCase):
    def _init_repository(self, root: Path) -> None:
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)

    def _write_probe(self, root: Path) -> Path:
        probe = root.parent / "hostile_git_probe.py"
        probe.write_text(
            "from pathlib import Path\n"
            "import sys\n"
            "Path(sys.argv[1]).write_text('executed', encoding='utf-8')\n"
            "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
            encoding="utf-8",
        )
        return probe

    def test_repository_state_disables_hostile_fsmonitor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            self._init_repository(root)
            probe = self._write_probe(root)
            marker = Path(tmp) / "fsmonitor-executed.txt"
            command = _shell_command(sys.executable, probe, marker)
            subprocess.run(["git", "-C", str(root), "config", "core.fsmonitor", command], check=True)

            state = repository.repository_state(root)

            self.assertTrue(state["is_git_repo"])
            self.assertFalse(marker.exists(), "repository inspection executed core.fsmonitor")

    def test_git_inspection_disables_hostile_clean_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            self._init_repository(root)
            (root / ".gitattributes").write_text("payload.txt filter=HostileCase\n", encoding="utf-8")
            (root / "payload.txt").write_text("safe\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", ".gitattributes", "payload.txt"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)

            probe = self._write_probe(root)
            marker = Path(tmp) / "filter-executed.txt"
            command = _shell_command(sys.executable, probe, marker)
            subprocess.run(["git", "-C", str(root), "config", "filter.HostileCase.clean", command], check=True)
            subprocess.run(["git", "-C", str(root), "config", "filter.HostileCase.required", "true"], check=True)
            (root / "payload.txt").write_text("changed\n", encoding="utf-8")

            result = repository.run_git_inspection(
                root, "hash-object", "--path", "payload.txt", "payload.txt",
            )

            self.assertIsNotNone(result)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists(), "repository inspection executed a clean filter")

    def test_git_inspection_fails_closed_when_executable_config_cannot_be_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            self._init_repository(root)
            with patch("rta_brain.repository._configured_command_keys", return_value=None):
                self.assertIsNone(repository.run_git_inspection(root, "status", "--short"))

    def test_repository_views_do_not_report_a_failed_status_probe_as_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            self._init_repository(root)

            with patch("rta_brain.repository._git", return_value=None):
                state = repository.repository_state(root)
                inspection = repository.inspect_repository(root)

            self.assertTrue(state["is_git_repo"])
            self.assertIsNone(state["dirty_files"])
            self.assertTrue(inspection.is_git_repo)
            self.assertIsNone(inspection.dirty_files)

    def test_git_clean_validator_is_unavailable_when_status_is_unknown(self):
        from rta_brain.temporal_validators import evaluate_validator

        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "rta_brain.temporal_validators.git_anchor_state",
                return_value={"commit": "a" * 40, "dirty_files": None},
            ):
                outcome, evidence = evaluate_validator(
                    "git_clean_state",
                    {"clean": True},
                    active_root=Path(tmp),
                    allow_command=False,
                    trusted_executables=[],
                )

        self.assertEqual(outcome, "unavailable")
        self.assertEqual(evidence["reason"], "git_status_unknown")

    def test_git_inspection_stops_a_process_when_combined_output_exceeds_the_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "chunks-written.txt"
            producer = root / "produce_output.py"
            producer.write_text(
                "import os\n"
                "import sys\n"
                "import time\n"
                "from pathlib import Path\n"
                "marker = Path(sys.argv[1])\n"
                "for index in range(4):\n"
                "    marker.write_text(str(index + 1), encoding='utf-8')\n"
                "    os.write(1, b'x' * 4096)\n"
                "    time.sleep(0.25)\n",
                encoding="utf-8",
            )
            command = [sys.executable, str(producer), str(marker)]
            with (
                patch(
                    "rta_brain.repository.trusted_git_candidates",
                    return_value=[Path(sys.executable)],
                ),
                patch("rta_brain.repository._git_command", return_value=command),
            ):
                result = repository.run_git_inspection(
                    root, "status", max_output_bytes=1_024
                )

            self.assertIsNone(result)
            self.assertTrue(marker.exists())
            written = marker.read_text(encoding="utf-8").strip()
            self.assertLess(
                int(written) if written else 0,
                4,
                "bounded Git inspection consumed the complete oversized stream",
            )

    def test_executable_config_inspection_does_not_use_unbounded_run_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "rta_brain.repository.subprocess.run",
                side_effect=AssertionError("unbounded capture was used"),
            ):
                result = repository._configured_command_keys(
                    Path(sys.executable), Path(tmp), os.environ.copy()
                )
        self.assertIsNone(result)

    def test_executable_config_inspection_fails_closed_on_oversized_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch(
                "rta_brain.repository._run_bounded_capture", return_value=None
            ):
                result = repository._configured_command_keys(
                    Path(sys.executable), Path(tmp), os.environ.copy()
                )
        self.assertIsNone(result)

    @unittest.skipUnless(repository.trusted_git_candidates(), "Trusted Git is required")
    def test_context_benchmark_ignores_project_local_git_shadow(self):
        from rta_brain.benchmark import run_context_compiler_benchmark

        with tempfile.TemporaryDirectory() as tmp:
            hostile_root = Path(tmp)
            if sys.platform == "win32":
                shutil.copy2(sys.executable, hostile_root / "git.exe")
            else:
                shadow = hostile_root / "git"
                shadow.write_text("#!/bin/sh\nexit 91\n", encoding="utf-8")
                shadow.chmod(0o755)
            hostile_path = f"{hostile_root}{os.pathsep}{os.environ.get('PATH', '')}"
            with patch.dict(os.environ, {"PATH": hostile_path}), chdir(hostile_root):
                result = run_context_compiler_benchmark()

        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["candidate"]["continuation_success"], 1.0)

    def test_hook_cli_resolution_ignores_project_local_shadow_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shadow = root / "rta_brain"
            shadow.mkdir()
            marker = root / "shadow-imported.txt"
            (shadow / "__init__.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            invocation = shlex.split(_cli_invocation(), posix=True)

            result = subprocess.run(
                [*invocation, "--version"], cwd=root, capture_output=True, text=True, timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("rta-brain", result.stdout)
            self.assertFalse(marker.exists(), "hook imported a project-local shadow package")


if __name__ == "__main__":
    unittest.main()
