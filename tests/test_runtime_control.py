import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain.runtime_control import read_json


class RuntimeControlTests(unittest.TestCase):
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
