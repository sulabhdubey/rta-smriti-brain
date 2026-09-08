import json
import subprocess
import sys
from pathlib import Path

from scripts.federation_performance_probe import run_probe

ROOT = Path(__file__).resolve().parents[1]


def test_federation_probe_is_bounded_reproducible_and_private_safe():
    report = run_probe(event_count=100, validation_samples=20, assert_bounds=True)

    assert report["schema_version"] == 1
    assert report["fixture"] == "synthetic-governed-federation"
    assert report["reconciliation"]["ordered_events"] == 100
    assert report["reconciliation"]["order_is_deterministic"] is True
    assert report["envelope_validation"]["samples"] == 20
    assert report["incremental_sync"]["event_count"] == 0
    assert report["incremental_sync"]["p95_ms"] <= 250
    serialized = json.dumps(report, sort_keys=True)
    assert "Users\\" not in serialized
    assert "/home/" not in serialized
    assert "synthetic private payload" not in serialized


def test_federation_probe_runs_directly_from_the_repository_root():
    result = subprocess.run(
        [sys.executable, "scripts/federation_performance_probe.py", "--help"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert "--assert-bounds" in result.stdout
