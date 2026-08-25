import unittest

from rta_brain.benchmark import default_public_benchmark_path, run_public_benchmark


class CognitionBenchmarkTests(unittest.TestCase):
    def test_public_benchmark_includes_v1_cognition_quality_gates(self):
        result = run_public_benchmark(default_public_benchmark_path())

        gates = result["quality_gates"]
        self.assertEqual(gates["decision_debt_detection"], 1.0)
        self.assertEqual(gates["evidence_authority_abstention"], 1.0)
        self.assertEqual(gates["cognition_context_inclusion"], 1.0)
        self.assertEqual(result["corpus"]["synthetic"], True)


if __name__ == "__main__":
    unittest.main()
