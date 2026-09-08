import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "benchmarks" / "v1.1-capability-baseline.json"


class V11BaselineContractTests(unittest.TestCase):
    def test_machine_readable_baseline_is_frozen_and_honest(self):
        payload = json.loads(BASELINE.read_text(encoding="utf-8"))

        self.assertEqual(payload["schema"], "rta-smriti.v1.1-capability-baseline/v1")
        self.assertEqual(payload["source_commit"], "aa0a9859ce897171902b494c645a1cdb6464036c")
        self.assertEqual(payload["package_version"], "1.1.0a1")
        self.assertTrue(payload["privacy"]["passed"])
        self.assertEqual(payload["recovery"]["tests_passed"], 81)
        self.assertEqual(payload["recovery"]["subtests_passed"], 15)

        host_evidence = payload["mcp_host_evidence"]
        self.assertEqual(host_evidence["codex"]["state"], "protocol_verified")
        for host in ("claude-code", "cursor", "zed", "opencode", "gemini-cli"):
            self.assertEqual(host_evidence[host]["state"], "recipe_available")
            self.assertFalse(host_evidence[host]["native_receipt_present"])

        benchmark = payload["benchmark"]
        self.assertTrue(benchmark["synthetic"])
        self.assertFalse(benchmark["external_superiority_evidence"])
        self.assertEqual(benchmark["optional_semantic"], "not_requested")
        self.assertEqual(benchmark["dataset_sha256"], "e6b64d89ad5e3838312f644c3240e43cbf514912a8b08443764ea3449e6e03d7")

        profiles = {item["files"]: item for item in payload["performance"]["profiles"]}
        self.assertEqual(set(profiles), {100, 1000})
        self.assertLess(profiles[100]["search_p95_ms"], 1000)
        self.assertLess(profiles[1000]["context_p95_ms"], 1500)

        pending = set(payload["pending_v1.1b_capabilities"])
        self.assertIn("selective_e2ee_replication", pending)
        self.assertIn("per_memory_permissions", pending)
        self.assertIn("optional_self_hosted_relay", pending)


if __name__ == "__main__":
    unittest.main()
