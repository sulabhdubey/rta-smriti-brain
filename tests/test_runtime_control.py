import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain.runtime_control import read_json, runtime_executable


class RuntimeControlTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX virtual environments use symlinks")
    def test_runtime_executable_preserves_a_virtual_environment_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "python-base"
            target.write_text("runtime", encoding="utf-8")
            launcher = root / "venv" / "bin" / "python"
            launcher.parent.mkdir(parents=True)
            launcher.symlink_to(target)

            with patch("rta_brain.runtime_control.sys.executable", str(launcher)):
                selected = runtime_executable()

            self.assertEqual(selected, launcher.absolute())
            self.assertNotEqual(selected, target.resolve())

    def test_read_json_retries_a_transiently_unavailable_state_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "worker.json"
            state_file.write_text(json.dumps({"state": "running"}), encoding="utf-8")

            with patch(
                "rta_brain.runtime_control.is_safe_regular_file",
                side_effect=[False, True],
            ), patch("rta_brain.runtime_control.time.sleep") as sleep:
                payload = read_json(state_file)

            self.assertEqual(payload, {"state": "running"})
            sleep.assert_called_once()

    def test_read_json_remains_fail_closed_for_an_unsafe_state_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "worker.json"
            state_file.write_text(json.dumps({"state": "running"}), encoding="utf-8")

            with patch(
                "rta_brain.runtime_control.is_safe_regular_file",
                return_value=False,
            ):
                self.assertIsNone(read_json(state_file))


if __name__ == "__main__":
    unittest.main()
