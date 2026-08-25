import unittest

from scripts.performance_probe import run_probe


class PerformanceProbeTests(unittest.TestCase):
    def test_small_probe_is_bounded_private_and_exercises_hybrid_retrieval(self):
        report = run_probe([8], assert_bounds=True)

        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["fixture"], "synthetic-python-repository")
        self.assertNotIn("hostname", report["environment"])
        profile = report["profiles"][0]
        self.assertEqual(profile["files"], 8)
        self.assertGreater(profile["database_bytes"], 0)
        self.assertGreater(profile["peak_python_allocation_bytes"], 0)
        self.assertLessEqual(profile["largest_context_pack_bytes"], 32_000)
        self.assertGreaterEqual(profile["indexed_symbols"], 8)
        self.assertEqual(profile["search_latency_ms"]["samples"], 30)
        self.assertEqual(profile["context_pack_latency_ms"]["samples"], 15)
        self.assertEqual(profile["cognition_snapshot_latency_ms"]["samples"], 20)
        self.assertLessEqual(profile["cognition_snapshot_latency_ms"]["p95"], 750)
        self.assertLessEqual(profile["largest_cognition_snapshot_bytes"], 512 * 1024)


if __name__ == "__main__":
    unittest.main()
