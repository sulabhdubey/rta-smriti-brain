"""Measure bounded Rta-Smriti operations over privacy-safe synthetic repositories."""

from __future__ import annotations

import argparse
import json
import math
import platform
import statistics
import sys
import tempfile
import tracemalloc
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rta_brain.cognition import cognition_snapshot  # noqa: E402
from rta_brain.context import build_context_pack  # noqa: E402
from rta_brain.db import (  # noqa: E402
    connect,
    ingest_repo,
    init_project,
    search,
    stale_check,
    update_project_settings,
)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    return ordered[min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))]


def create_repository(root: Path, file_count: int) -> None:
    for index in range(file_count):
        folder = root / f"module_{index // 250:04d}"
        folder.mkdir(exist_ok=True)
        (folder / f"service_{index:06d}.py").write_text(
            f"def queue_worker_{index}():\n"
            f"    # Synthetic queue latency, bounded backpressure, and retry budget {index % 17}.\n"
            f"    return {index % 17}\n",
            encoding="utf-8",
        )


def measure_profile(file_count: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="rta-scale-") as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        create_repository(root, file_count)
        database = Path(tmp) / "brain.sqlite"
        conn = connect(database)
        try:
            init_project(conn, "scale", str(root))
            update_project_settings(
                conn,
                "scale",
                {"parser_adapter": "regex", "embedding_provider": "hash"},
                root_path=str(root),
            )
            tracemalloc.start()
            started = perf_counter()
            indexed = ingest_repo(conn, root, project="scale")
            index_seconds = perf_counter() - started
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            started = perf_counter()
            deep = stale_check(conn, project="scale", deep=True)
            deep_seconds = perf_counter() - started

            queries = [
                "queue latency backpressure",
                "retry budget worker",
                "bounded queue service",
                "queue worker 7",
                "latency retry",
            ]
            started = perf_counter()
            cold_search = search(conn, queries[0], project="scale", limit=8)
            cold_search_ms = (perf_counter() - started) * 1_000
            if cold_search["retrieval"]["mode"] != "hybrid":
                raise AssertionError("scale probe did not exercise hash-hybrid retrieval")

            search_latencies = []
            for query in queries * 6:
                started = perf_counter()
                result = search(conn, query, project="scale", limit=8)
                search_latencies.append((perf_counter() - started) * 1_000)
                if result["retrieval"]["mode"] != "hybrid":
                    raise AssertionError("scale probe did not exercise hash-hybrid retrieval")

            started = perf_counter()
            cold_pack = build_context_pack(conn, queries[0], project="scale", max_tokens=2_000)
            cold_pack_ms = (perf_counter() - started) * 1_000

            pack_latencies = []
            pack_bytes = []
            for query in queries[:3] * 5:
                started = perf_counter()
                pack = build_context_pack(conn, query, project="scale", max_tokens=2_000)
                pack_latencies.append((perf_counter() - started) * 1_000)
                pack_bytes.append(len(pack.encode("utf-8")))

            cognition_snapshot(
                conn,
                project="scale",
                active_root=root,
                include_change_impact=False,
            )
            cognition_latencies = []
            cognition_bytes = []
            for _ in range(20):
                started = perf_counter()
                snapshot = cognition_snapshot(
                    conn,
                    project="scale",
                    active_root=root,
                    include_change_impact=False,
                )
                cognition_latencies.append((perf_counter() - started) * 1_000)
                cognition_bytes.append(len(json.dumps(snapshot, sort_keys=True).encode("utf-8")))
        finally:
            conn.close()

        if indexed["indexed_files"] != file_count or deep["state"] != "fresh":
            raise AssertionError("scale probe did not index and verify the complete synthetic repository")
        return {
            "files": file_count,
            "index_seconds": round(index_seconds, 3),
            "index_seconds_per_1000_files": round(index_seconds / file_count * 1_000, 3),
            "deep_freshness_seconds": round(deep_seconds, 3),
            "search_latency_ms": {
                "cold": round(cold_search_ms, 3),
                "median": round(statistics.median(search_latencies), 3),
                "p95": round(percentile(search_latencies, 0.95), 3),
                "samples": len(search_latencies),
            },
            "context_pack_latency_ms": {
                "cold": round(cold_pack_ms, 3),
                "median": round(statistics.median(pack_latencies), 3),
                "p95": round(percentile(pack_latencies, 0.95), 3),
                "samples": len(pack_latencies),
            },
            "cognition_snapshot_latency_ms": {
                "median": round(statistics.median(cognition_latencies), 3),
                "p95": round(percentile(cognition_latencies, 0.95), 3),
                "samples": len(cognition_latencies),
            },
            "largest_cognition_snapshot_bytes": max(cognition_bytes),
            "largest_context_pack_bytes": max([len(cold_pack.encode("utf-8")), *pack_bytes]),
            "database_bytes": database.stat().st_size,
            "peak_python_allocation_bytes": peak_bytes,
            "indexed_symbols": indexed["symbols"],
            "indexed_edges": indexed["edges"],
        }


def run_probe(profiles: list[int], assert_bounds: bool = False) -> dict:
    normalized = sorted(set(int(value) for value in profiles))
    if not normalized or normalized[0] < 1 or normalized[-1] > 50_000:
        raise ValueError("performance profiles must contain 1 to 50,000 files")
    results = [measure_profile(file_count) for file_count in normalized]
    if assert_bounds:
        for result in results:
            if result["index_seconds_per_1000_files"] > 60:
                raise AssertionError(f"indexing exceeded the generous regression bound: {result}")
            if result["search_latency_ms"]["p95"] > 1_000:
                raise AssertionError(f"retrieval exceeded the generous regression bound: {result}")
            if result["context_pack_latency_ms"]["p95"] > 1_500:
                raise AssertionError(f"context pack exceeded the generous regression bound: {result}")
            if result["largest_context_pack_bytes"] > 32_000:
                raise AssertionError(f"bounded context pack grew unexpectedly: {result}")
            if result["cognition_snapshot_latency_ms"]["p95"] > 750:
                raise AssertionError(
                    f"cognition snapshot exceeded the v1.0 p95 bound: {result}"
                )
            if result["largest_cognition_snapshot_bytes"] > 512 * 1024:
                raise AssertionError(f"cognition snapshot exceeded its byte bound: {result}")
    return {
        "schema_version": 1,
        "fixture": "synthetic-python-repository",
        "environment": {
            "os": platform.system().lower(),
            "architecture": platform.machine().lower(),
            "python": platform.python_version(),
        },
        "profiles": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", nargs="+", type=int, default=[100, 1_000, 10_000])
    parser.add_argument("--assert-bounds", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = run_probe(args.profiles, assert_bounds=args.assert_bounds)
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
