import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from scripts import build_installed_smoke
from scripts import installed_distribution_smoke


class InstalledSmokeSecurityTests(unittest.TestCase):
    def test_private_smoke_directory_rejects_group_or_world_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "brains"

            installed_distribution_smoke.create_private_directory(target)

            self.assertTrue(target.is_dir())
            if sys.platform != "win32":
                self.assertEqual(target.stat().st_mode & 0o077, 0)

    def test_extraction_rejects_windows_escape_paths(self):
        unc_member = "\\" * 2 + r"server\share\escape.txt"
        for member in (r"..\..\escape.txt", r"C:\escape.txt", unc_member):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive_path = root / "baseline.zip"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr(member, "escape")

                with self.assertRaisesRegex(RuntimeError, "unsafe entry"):
                    build_installed_smoke.extract_git_archive(archive_path, root / "source")

    def test_baseline_archive_uses_trusted_git_and_pinned_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "baseline.zip"
            resolved = type("Result", (), {
                "returncode": 0,
                "stdout": build_installed_smoke.BASELINE_COMMIT + "\n",
                "stderr": "",
            })()
            archived = type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            def trusted_git(*args, **kwargs):
                if "archive" in args:
                    output.write_bytes(b"PK")
                    return archived
                return resolved
            with patch(
                "scripts.build_installed_smoke.run_git_inspection",
                side_effect=trusted_git,
            ) as git:
                build_installed_smoke.build_baseline_archive(output)

        self.assertEqual(git.call_args_list[0].args[1:3], ("rev-parse", "--verify"))
        self.assertIn(build_installed_smoke.BASELINE_REF, git.call_args_list[0].args[3])
        self.assertIn(build_installed_smoke.BASELINE_COMMIT, git.call_args_list[1].args)


if __name__ == "__main__":
    unittest.main()
