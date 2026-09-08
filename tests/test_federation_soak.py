import unittest

from scripts.federation_soak import run_soak


class FederationSoakTests(unittest.TestCase):
    def test_short_soak_exercises_recovery_rotation_restart_and_cleanup(self):
        report = run_soak(
            cycles=6,
            cycle_seconds=0,
            outage_every=2,
            restart_every=3,
            rotate_every=2,
            assert_invariants=True,
        )

        self.assertEqual(report["state"], "passed")
        self.assertEqual(report["cycles_completed"], 6)
        self.assertGreaterEqual(report["outages_recovered"], 3)
        self.assertGreaterEqual(report["database_restarts"], 2)
        self.assertGreaterEqual(report["key_rotations"], 3)
        self.assertEqual(report["source_event_count"], report["destination_event_count"])
        self.assertTrue(report["converged"])
        self.assertTrue(report["relay_plaintext_absent"])
        self.assertTrue(report["temporary_state_removed"])


if __name__ == "__main__":
    unittest.main()
