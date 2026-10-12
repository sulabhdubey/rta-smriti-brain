import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from rta_brain.autostart import (
    _entry_text,
    _launch_parts,
    autostart_status,
    disable_autostart,
    enable_autostart,
)

ROOT = Path(__file__).resolve().parents[1]


class AutostartTests(unittest.TestCase):
    def test_installed_startup_uses_isolated_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parts = _launch_parts(root / "installed", root / "brains")
            self.assertEqual(parts[1:4], ["-I", "-m", "rta_brain.cli"])

    def test_installed_startup_ignores_environment_and_cwd_package_shadowing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "rta_brain"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "cli.py").write_text(
                'print("UNTRUSTED_STARTUP_PACKAGE")\n', encoding="utf-8"
            )
            parts = _launch_parts(root / "installed", root / "brains")
            # Exercise the actual module prefix without starting real services.
            prefix = parts[:parts.index("supervisor")]
            result = subprocess.run(
                [*prefix, "--help"], cwd=root,
                env={**os.environ, "PYTHONPATH": str(root)},
                capture_output=True, text=True, timeout=20, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("UNTRUSTED_STARTUP_PACKAGE", result.stdout)
            self.assertIn("context-pack", result.stdout)

    def test_windows_startup_entry_is_reversible_and_never_opens_browser(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            appdata = Path(tmp) / "AppData" / "Roaming"
            brain_dir = Path(tmp) / "brains with spaces"
            enabled = enable_autostart(
                ROOT, brain_dir, platform_name="win32", home=home,
                environment={"APPDATA": str(appdata)},
            )
            entry = Path(enabled["entry_path"])
            self.assertTrue(entry.is_file())
            self.assertEqual(entry.suffix, ".vbs")
            text = entry.read_text(encoding="utf-8")
            self.assertIn('""supervisor"" ""start""', text)
            self.assertIn("--no-open", text)
            self.assertIn("RtaSmritiStartup.ShowWindow = 0", text)
            self.assertIn("Win32_Process", text)
            self.assertIn(str(brain_dir.resolve()), text)
            self.assertTrue(autostart_status(brain_dir, platform_name="win32", home=home, environment={"APPDATA": str(appdata)})["enabled"])
            disabled = disable_autostart(brain_dir, platform_name="win32", home=home, environment={"APPDATA": str(appdata)})
            self.assertFalse(disabled["enabled"])
            self.assertFalse(entry.exists())

    def test_windows_enable_migrates_legacy_visible_console_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            appdata = Path(tmp) / "AppData" / "Roaming"
            brain_dir = Path(tmp) / "brains"
            startup = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            startup.mkdir(parents=True)
            autostart = __import__("rta_brain.autostart", fromlist=["_key"])
            legacy = startup / f"Rta-Smriti-{autostart._key(brain_dir)}.cmd"
            legacy.write_text("@echo off\n", encoding="utf-8")

            before = autostart_status(
                brain_dir, platform_name="win32", home=home,
                environment={"APPDATA": str(appdata)},
            )
            self.assertTrue(before["enabled"])
            self.assertEqual(before["reason"], "legacy-visible-console")

            enabled = enable_autostart(
                ROOT, brain_dir, platform_name="win32", home=home,
                environment={"APPDATA": str(appdata)},
            )
            self.assertEqual(Path(enabled["entry_path"]).suffix, ".vbs")
            self.assertFalse(legacy.exists())

    def test_macos_launch_agent_uses_program_arguments_without_a_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            brain_dir = home / "brains & memory"
            payload = enable_autostart(ROOT, brain_dir, platform_name="darwin", home=home, environment={})
            text = Path(payload["entry_path"]).read_text(encoding="utf-8")
            self.assertIn("<key>ProgramArguments</key>", text)
            self.assertIn("<string>supervisor</string>", text)
            self.assertIn("<string>--no-open</string>", text)
            self.assertIn("brains &amp; memory", text)
            self.assertNotIn("<key>Shell", text)

    def test_linux_desktop_entry_is_generated_only_for_supported_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            brain_dir = home / "brains"
            supported = enable_autostart(
                ROOT, brain_dir, platform_name="linux", home=home,
                environment={"DISPLAY": ":0", "XDG_CONFIG_HOME": str(home / ".config")},
            )
            text = Path(supported["entry_path"]).read_text(encoding="utf-8")
            self.assertIn("Type=Application", text)
            self.assertIn('"supervisor" "start"', text)
            self.assertIn("--no-open", text)

            unsupported = autostart_status(
                brain_dir, platform_name="linux", home=home,
                environment={"WSL_DISTRO_NAME": "Ubuntu"},
            )
            self.assertFalse(unsupported["supported"])
            self.assertEqual(unsupported["reason"], "wsl")

    def test_linked_autostart_entry_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            appdata = Path(tmp) / "AppData" / "Roaming"
            brain_dir = Path(tmp) / "brains"
            first = enable_autostart(
                ROOT, brain_dir, platform_name="win32", home=home,
                environment={"APPDATA": str(appdata)},
            )
            entry = Path(first["entry_path"])
            entry.unlink()
            victim = Path(tmp) / "victim.cmd"
            victim.write_text("keep\n", encoding="utf-8")
            entry.hardlink_to(victim)
            with self.assertRaisesRegex(ValueError, "linked autostart entry"):
                enable_autostart(
                    ROOT, brain_dir, platform_name="win32", home=home,
                    environment={"APPDATA": str(appdata)},
                )
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep\n")

    @unittest.skipUnless(sys.platform == "win32", "Windows Script Host behavior")
    def test_windows_startup_entry_preserves_metacharacters_without_injection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recorder = root / "record args.py"
            output = root / "captured.json"
            injected = root / "injected.txt"
            recorder.write_text(
                "import json, pathlib, sys\n"
                "pathlib.Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:]), encoding='utf-8')\n",
                encoding="utf-8",
            )
            adversarial = f"brain & echo owned>{injected} %PATH% ^ caret"
            entry = root / "startup.vbs"
            entry.write_text(
                _entry_text("windows", [sys.executable, str(recorder), str(output), adversarial], "fixture"),
                encoding="utf-8",
            )

            subprocess.run(
                ["cscript.exe", "//B", "//NoLogo", str(entry)],
                check=True,
                cwd=root,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            deadline = time.monotonic() + 10
            while not output.exists() and time.monotonic() < deadline:
                time.sleep(0.05)

            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), [adversarial])
            self.assertFalse(injected.exists(), "startup argument escaped into a second command")


if __name__ == "__main__":
    unittest.main()
