import json
import unittest
from unittest.mock import patch

from scripts import lifecycle_soak as soak
from scripts.lifecycle_soak import (
    _sample_with_convergence,
    _wait_for_continuity_caught_up,
    _wait_for_fresh_repository,
    build_public_report,
)


class LifecycleSoakTests(unittest.TestCase):
    def test_failed_apply_preserves_safe_operation_and_error_class(self):
        plan = {"plan_digest": "plan", "observed_state_digest": "state"}
        receipt = {
            "state": "failed",
            "receipt_path": "/home/private/brain/receipt.json",
            "steps": [{"operation": "stop_continuity", "state": "failed",
                       "error_class": "TimeoutError", "message": "private transcript"}],
        }
        with patch.object(soak, "plan_lifecycle", return_value=plan), patch.object(
            soak, "apply_lifecycle", return_value=receipt
        ), self.assertRaises(RuntimeError) as raised:
            soak._apply({}, {})
        self.assertEqual(getattr(raised.exception, "diagnostic", None), {
            "code": "apply_incomplete", "operation": "stop_continuity",
            "error_class": "TimeoutError",
        })

    def test_blocked_plan_does_not_publish_arbitrary_blocker_text(self):
        with patch.object(soak, "plan_lifecycle", return_value={
            "blocked": True, "blockers": ["/home/private/transcript"],
        }), patch.object(soak, "apply_lifecycle") as apply, self.assertRaises(
            RuntimeError
        ) as raised:
            soak._apply({}, {})
        apply.assert_not_called()
        self.assertEqual(getattr(raised.exception, "diagnostic", None), {
            "code": "plan_blocked", "operation": "unknown",
            "error_class": "RuntimeError",
        })

    def test_sample_convergence_recovers_from_one_transient_mismatch(self):
        with patch(
            "scripts.lifecycle_soak._sample",
            side_effect=[RuntimeError("capture lifecycle state mismatch"), "digest"],
        ) as sample:
            result = _sample_with_convergence(
                {"db_path": "brain.sqlite", "project": "atlas"},
                False,
                timeout_seconds=0.2,
                interval_seconds=0.01,
            )

        self.assertEqual(result, "digest")
        self.assertEqual(sample.call_count, 2)

    def test_sample_convergence_rejects_persistent_mismatch(self):
        with patch(
            "scripts.lifecycle_soak._sample",
            side_effect=RuntimeError("capture lifecycle state mismatch"),
        ) as sample, patch(
            "scripts.lifecycle_soak.time.monotonic",
            side_effect=[0.0, 0.0, 0.01, 0.03],
        ), patch("scripts.lifecycle_soak.time.sleep"), self.assertRaisesRegex(
            RuntimeError, "lifecycle sampling did not converge"
        ):
            _sample_with_convergence(
                {"db_path": "brain.sqlite", "project": "atlas"},
                False,
                timeout_seconds=0.03,
                interval_seconds=0.01,
            )

        self.assertGreaterEqual(sample.call_count, 2)

    def test_continuity_catch_up_requires_post_capture_zero_backlog_cycle(self):
        with patch(
            "scripts.lifecycle_soak.continuity_status",
            side_effect=[
                {"events_inserted": 2, "sessions_pending": 1},
                {"events_inserted": 2, "sessions_pending": 0},
            ],
        ) as status:
            result = _wait_for_continuity_caught_up(
                {"db_path": "brain.sqlite", "project": "atlas"},
                minimum_events=2,
                timeout_seconds=0.2,
                interval_seconds=0.01,
            )

        self.assertEqual(result["sessions_pending"], 0)
        self.assertEqual(status.call_count, 2)

    def test_freshness_probe_retries_transient_non_fresh_state(self):
        with patch(
            "scripts.lifecycle_soak._deep_freshness",
            side_effect=[{"state": "stale"}, {"state": "fresh"}],
        ) as probe:
            result = _wait_for_fresh_repository(
                {"project": "atlas"},
                timeout_seconds=0.2,
                interval_seconds=0.01,
            )

        self.assertEqual(result["state"], "fresh")
        self.assertEqual(probe.call_count, 2)

    def test_public_report_is_deterministic_bounded_and_path_free(self):
        facts = {
            "platform": {"system": "TestOS", "machine": "test-arch"},
            "runtime": {"implementation": "cpython", "python": "3.11.9"},
            "configuration": {
                "duration_seconds": 12.0,
                "interval_seconds": 0.25,
                "console_enabled": False,
            },
            "sample_digests": ["b" * 64, "a" * 64],
            "failure_digests": [],
            "mutation_digests": ["c" * 64, "d" * 64],
            "restart_digests": ["e" * 64],
            "cleanup_digests": ["f" * 64],
        }

        first = build_public_report(facts)
        second = build_public_report(dict(reversed(list(facts.items()))))

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "passed")
        self.assertEqual(first["samples"]["count"], 2)
        self.assertEqual(first["failures"]["count"], 0)
        self.assertEqual(first["mutations"]["count"], 2)
        self.assertEqual(first["restarts"]["count"], 1)
        self.assertEqual(first["cleanup"]["state"], "complete")
        self.assertRegex(first["report_digest"], r"^[0-9a-f]{64}$")
        rendered = json.dumps(first, sort_keys=True)
        self.assertNotIn("C:\\\\Users", rendered)
        self.assertNotIn("/home/", rendered)
        self.assertNotIn("transcript", rendered.casefold())
        self.assertNotIn("content", rendered.casefold())
        self.assertLess(len(rendered), 2_000)

        facts["failure_digests"] = ["0" * 64]
        facts["failure_diagnostics"] = [{
            "phase": "restart-stop", "code": "apply_incomplete",
            "operation": "stop_continuity", "error_class": "TimeoutError",
            "private": "/home/private/transcript",
        }, {
            "phase": "/home/private", "code": "private transcript",
            "operation": "/home/private", "error_class": "private transcript",
        }] * 20
        report = build_public_report(facts)
        diagnostics = report["failures"].get("diagnostics", [])
        self.assertEqual(diagnostics[:2], [{
            "phase": "restart-stop", "code": "apply_incomplete",
            "operation": "stop_continuity", "error_class": "TimeoutError",
        }, {"phase": "unknown", "code": "caught_exception",
            "operation": "unknown", "error_class": "unknown"}])
        self.assertLessEqual(len(diagnostics), 8)
        self.assertNotIn("private", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
