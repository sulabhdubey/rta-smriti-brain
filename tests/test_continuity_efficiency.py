import json
import os
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import continuity_daemon as daemon


class ContinuityEfficiencyTests(unittest.TestCase):
    def test_depth_guard_matches_bytewise_oracle_for_malformed_and_escaped_inputs(self):
        from rta_brain.continuity import json_nesting_exceeds

        def oracle(frame, maximum):
            depth, in_string, escaped = 0, False, False
            for byte in frame:
                if in_string:
                    if escaped:
                        escaped = False
                    elif byte == 92:
                        escaped = True
                    elif byte == 34:
                        in_string = False
                elif byte == 34:
                    in_string = True
                elif byte in (91, 123):
                    depth += 1
                    if depth > maximum:
                        return True
                elif byte in (93, 125):
                    depth = max(0, depth - 1)
            return False

        rng = random.Random(1042026)
        cases = [b'"' + b"x" * 200_000 + b'"', b'"\\"[[["', b'"\\\\"[[[', b'"\\\n"[[[']
        cases.extend(bytes(rng.choices(b'"\\[]{} xyz\n\xff', k=rng.randrange(200))) for _ in range(5000))
        for frame in cases:
            for limit in (0, 1, 4, 64):
                self.assertEqual(json_nesting_exceeds(frame, limit), oracle(frame, limit))

    def test_depth_guard_skips_ordinary_transcript_bytes_in_native_scanner(self):
        from rta_brain import continuity
        with patch.object(continuity.re, "finditer", wraps=continuity.re.finditer) as scanner:
            self.assertFalse(continuity.json_nesting_exceeds(b'{"text":"' + b"x" * 200_000 + b'"}'))
            self.assertEqual(scanner.call_count, 1)

    def test_capture_idle_delay_is_bounded_and_resets_for_pending_work(self):
        from rta_brain.capture_daemon import _capture_wait_seconds
        self.assertEqual(_capture_wait_seconds(1, 0), 2)
        self.assertEqual(_capture_wait_seconds(1, 2), 8)
        self.assertEqual(_capture_wait_seconds(1, 20), 10)
        self.assertEqual(_capture_wait_seconds(1, 0, pending=True), 1)
        self.assertEqual(_capture_wait_seconds(30, 20), 30)

    def test_binding_cache_reuses_only_unchanged_bounded_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "session.jsonl"
            path.write_text(json.dumps({"type": "session_meta", "payload": {
                "id": "test", "cwd": str(root)}}) + "\n")
            cache = daemon.SessionBindingCache()
            with patch.object(daemon, "_session_binding", wraps=daemon._session_binding) as binding:
                self.assertIsNotNone(cache.lookup(path, root, now=0))
                self.assertIsNotNone(cache.lookup(path, root, now=10))
                self.assertEqual(binding.call_count, 1)
                self.assertIsNotNone(cache.lookup(path, root, now=301))
                self.assertEqual(binding.call_count, 2)
                with path.open("a") as stream:
                    stream.write(json.dumps({"type": "turn_context", "payload": {
                        "cwd": str(root.parent)}}) + "\n")
                self.assertIsNone(cache.lookup(path, root, now=302))
                self.assertEqual(binding.call_count, 3)
                self.assertIsNone(cache.lookup(path, root, now=303))
                self.assertEqual(binding.call_count, 3)

    def test_cache_is_root_bound_and_rejects_new_hardlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "session.jsonl"
            path.write_text(json.dumps({"type": "session_meta", "payload": {
                "id": "test", "cwd": str(root)}}) + "\n")
            cache = daemon.SessionBindingCache()
            self.assertIsNotNone(cache.lookup(path, root, now=0))
            child = root / "other"
            child.mkdir()
            self.assertIsNone(cache.lookup(path, child, now=1))
            os.link(path, root / "linked.jsonl")
            self.assertIsNone(cache.lookup(path, root, now=2))

    def test_binding_scan_yields_and_is_interruptible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "session.jsonl"
            path.write_text(json.dumps({"type": "session_meta", "payload": {
                "id": "test", "cwd": str(root)}}) + "\n" + "{}\n" * 100)
            calls = []
            self.assertIsNotNone(daemon._session_binding(path, root,
                work_checkpoint=lambda: calls.append(True)))
            self.assertGreater(len(calls), 100)
            with self.assertRaises(InterruptedError):
                daemon._session_binding(path, root,
                    work_checkpoint=lambda: (_ for _ in ()).throw(InterruptedError()))


if __name__ == "__main__":
    unittest.main()
