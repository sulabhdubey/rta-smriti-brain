"""Measure governed-federation budgets with generated identities and synthetic data."""

from __future__ import annotations

import argparse
import json
import math
import platform
import sqlite3
import statistics
import sys
import tempfile
import tracemalloc
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rta_brain.db import init_schema
from rta_brain.federation import deterministic_event_order, store_event
from rta_brain.federation_crypto import (
    create_encrypted_event,
    create_identity,
    decrypt_event,
    generate_scope_key,
)
from rta_brain.federation_governance import create_scope, create_space
from rta_brain.federation_transport import FilesystemFederationRelay, push_to_relay

PASSPHRASE = b"synthetic federation performance fixture"


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def _database() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_schema(conn)
    conn.execute(
        "INSERT INTO projects(id, name, created_at) VALUES "
        "(1, 'synthetic-federation', '2026-09-07T00:00:00+00:00')"
    )
    return conn


def run_probe(
    *,
    event_count: int = 10_000,
    validation_samples: int = 100,
    assert_bounds: bool = False,
) -> dict:
    if not 1 <= int(event_count) <= 10_000:
        raise ValueError("event_count must be between 1 and 10,000")
    if not 5 <= int(validation_samples) <= 10_000:
        raise ValueError("validation_samples must be between 5 and 10,000")

    with tempfile.TemporaryDirectory(prefix="rta-federation-probe-") as temporary:
        base = Path(temporary)
        owner = create_identity(base / "identity", passphrase=PASSPHRASE)
        conn = _database()
        relay = FilesystemFederationRelay(base / "relay")
        try:
            space = create_space(
                conn,
                project_id=1,
                owner=owner,
                owner_key_reference="synthetic-generated-identity",
            )
            scope = create_scope(
                conn,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="team",
                label="Synthetic performance scope",
            )
            scope_key = generate_scope_key()
            validation_event = create_encrypted_event(
                {
                    "event_type": "memory.asserted",
                    "object_id": "validation-probe",
                    "text": "V" * (16 * 1024),
                    "privacy_class": "internal",
                    "epistemic_state": "observed",
                    "valid_from": "2026-09-07T00:00:00+00:00",
                },
                identity=owner,
                scope_key=scope_key,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                epoch=1,
                author_sequence=event_count + 1,
                capability_event_id=space["bootstrap"]["event_id"],
                parents=(),
                received_at="2026-09-07T00:00:00+00:00",
            )
            validation_latencies = []
            for _ in range(validation_samples):
                started = perf_counter()
                payload = decrypt_event(
                    validation_event,
                    author_signing_public_key=owner.signing_public_bytes,
                    scope_key=scope_key,
                )
                validation_latencies.append((perf_counter() - started) * 1_000)
                if payload.get("object_id") != "validation-probe":
                    raise AssertionError("federation validation fixture changed")

            conn.execute("BEGIN IMMEDIATE")
            for sequence in range(1, event_count + 1):
                envelope = create_encrypted_event(
                    {
                        "event_type": "memory.asserted",
                        "object_id": f"memory-{sequence}",
                        "text": f"synthetic private payload {sequence}",
                        "privacy_class": "internal",
                        "epistemic_state": "observed",
                        "valid_from": "2026-09-07T00:00:00+00:00",
                    },
                    identity=owner,
                    scope_key=scope_key,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    epoch=1,
                    author_sequence=sequence,
                    capability_event_id=space["bootstrap"]["event_id"],
                    parents=(),
                    received_at="2026-09-07T00:00:00+00:00",
                )
                store_event(conn, project_id=1, envelope=envelope, commit=False)
            conn.commit()

            tracemalloc.start()
            started = perf_counter()
            first_order = deterministic_event_order(
                conn, project_id=1, space_id=space["space_id"]
            )
            reconcile_seconds = perf_counter() - started
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            second_order = deterministic_event_order(
                conn, project_id=1, space_id=space["space_id"]
            )

            sync_latencies = []
            last_sync = None
            for _ in range(20):
                started = perf_counter()
                last_sync = push_to_relay(
                    conn,
                    project_id=1,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    actor_peer_id=owner.identity_id,
                    relay=relay,
                )
                sync_latencies.append((perf_counter() - started) * 1_000)
        finally:
            conn.close()

    report = {
        "schema_version": 1,
        "fixture": "synthetic-governed-federation",
        "environment": {
            "os": platform.system().lower(),
            "architecture": platform.machine().lower(),
            "python": platform.python_version(),
        },
        "envelope_validation": {
            "payload_bytes": 16 * 1024,
            "samples": len(validation_latencies),
            "p50_ms": round(statistics.median(validation_latencies), 3),
            "p95_ms": round(_percentile(validation_latencies, 0.95), 3),
        },
        "reconciliation": {
            "events": event_count,
            "ordered_events": len(first_order),
            "seconds": round(reconcile_seconds, 3),
            "peak_python_allocation_bytes": peak_bytes,
            "order_is_deterministic": [item["event_id"] for item in first_order]
            == [item["event_id"] for item in second_order],
        },
        "incremental_sync": {
            "samples": len(sync_latencies),
            "event_count": int(last_sync["event_count"] if last_sync else -1),
            "p50_ms": round(statistics.median(sync_latencies), 3),
            "p95_ms": round(_percentile(sync_latencies, 0.95), 3),
        },
    }
    if assert_bounds:
        if report["envelope_validation"]["p95_ms"] > 5:
            raise AssertionError("federation envelope validation exceeded the p95 budget")
        if (
            report["reconciliation"]["ordered_events"] != event_count
            or not report["reconciliation"]["order_is_deterministic"]
        ):
            raise AssertionError("federation reconciliation was incomplete or unstable")
        if report["reconciliation"]["seconds"] > 10:
            raise AssertionError("federation reconciliation exceeded the 10 second budget")
        if report["reconciliation"]["peak_python_allocation_bytes"] > 256 * 1024 * 1024:
            raise AssertionError("federation reconciliation exceeded the 256 MiB budget")
        if report["incremental_sync"]["p95_ms"] > 250:
            raise AssertionError("federation no-change sync exceeded the p95 budget")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=10_000)
    parser.add_argument("--validation-samples", type=int, default=100)
    parser.add_argument("--assert-bounds", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = run_probe(
        event_count=args.events,
        validation_samples=args.validation_samples,
        assert_bounds=args.assert_bounds,
    )
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
