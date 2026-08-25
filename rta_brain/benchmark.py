"""Reproducible public benchmark runner over a synthetic corpus."""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from statistics import median
from time import perf_counter

from .cognition import cognition_snapshot, record_observation
from .context import build_context_pack, build_continuation_prompt, estimate_tokens
from .context_candidates import adapt_context_candidates
from .db import (
    connect,
    ingest_repo,
    init_project,
    reflect,
    remember,
    save_checkpoint,
    search,
    stale_check,
    update_project_settings,
)
from .governance import create_policy, preflight
from .privacy import redact_sensitive_text
from .repository import run_git_inspection
from .temporal import append_claim, attach_evidence

MAX_PUBLIC_BENCHMARK_BYTES = 2_000_000
MAX_PUBLIC_DOCUMENTS = 5_000
MAX_PUBLIC_QUERIES = 1_000
MAX_BENCHMARK_HISTORY_BYTES = 1_000_000
MAX_BENCHMARK_HISTORY_RUNS = 100

_CONTEXT_COMPILER_FIXTURE = {
    "schema_version": 1,
    "name": "Rta-Smriti Context Compiler Continuation Fixture v1",
    "task": "Resume the verified release candidate within its explicit controls.",
    "controls": [
        "Resume the verified release candidate.",
        "Require the privacy proof receipt.",
        "Stop if canonical identity is not exact.",
        "Do not repeat the retired migration.",
    ],
}


def _safe_public_label(value: object, *, fallback: str) -> str:
    redacted, _ = redact_sensitive_text(str(value or fallback))
    return " ".join(redacted.split()).replace("`", "'")[:200] or fallback


def default_public_benchmark_path() -> Path:
    """Return the benchmark corpus shipped inside installed distributions."""
    return Path(__file__).with_name("data") / "public-v1.json"


def _load_dataset(path: Path) -> tuple[dict, str]:
    dataset = Path(path)
    if not dataset.is_file():
        raise ValueError(f"benchmark dataset does not exist: {dataset}")
    if dataset.stat().st_size > MAX_PUBLIC_BENCHMARK_BYTES:
        raise ValueError(f"benchmark dataset exceeds the {MAX_PUBLIC_BENCHMARK_BYTES:,} byte size limit")
    raw = dataset.read_bytes()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("benchmark dataset is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("benchmark dataset must be an object")
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported benchmark schema version")
    documents = payload.get("documents")
    queries = payload.get("queries")
    if (
        not isinstance(documents, list) or not documents or len(documents) > MAX_PUBLIC_DOCUMENTS
        or not isinstance(queries, list) or not queries or len(queries) > MAX_PUBLIC_QUERIES
    ):
        raise ValueError("benchmark requires non-empty documents and queries")
    known_paths = set()
    for item in documents:
        if not isinstance(item, dict):
            raise ValueError("benchmark documents must be objects")
        relative = str(item.get("path") or "").replace("\\", "/")
        if (
            not relative or len(relative) > 1_000 or PurePosixPath(relative).is_absolute()
            or ".." in PurePosixPath(relative).parts or relative in known_paths
        ):
            raise ValueError("benchmark document paths must be relative")
        if not isinstance(item.get("text"), str) or len(item["text"]) > 1_000_000:
            raise ValueError("benchmark document text must be a bounded string")
        known_paths.add(relative)
    for item in queries:
        if not isinstance(item, dict):
            raise ValueError("benchmark queries must be objects")
        if (
            not isinstance(item.get("query"), str) or not item["query"].strip()
            or len(item["query"]) > 2_000
        ):
            raise ValueError("benchmark query must be a non-empty string")
        relevant = item.get("relevant_paths")
        if (
            not isinstance(relevant, list) or not relevant or len(relevant) > 100
            or any(not isinstance(value, str) for value in relevant) or not set(relevant) <= known_paths
        ):
            raise ValueError("benchmark relevant paths must reference corpus documents")
    return payload, hashlib.sha256(raw).hexdigest()


def _rank_metrics(retrieved: list[str], relevant: set[str], k: int) -> tuple[float, float, float, float]:
    selected = retrieved[:k]
    gains = [1.0 if path in relevant else 0.0 for path in selected]
    dcg = sum(gain / math.log2(index + 2) for index, gain in enumerate(gains))
    ideal = sum(1.0 / math.log2(index + 2) for index in range(min(len(relevant), k)))
    hits = sum(gains)
    first = next((index + 1 for index, path in enumerate(selected) if path in relevant), None)
    return (
        dcg / ideal if ideal else 0.0,
        hits / len(relevant),
        (1.0 / first) if first else 0.0,
        hits / len(selected) if selected else 0.0,
    )


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))]


def _run_mode(payload: dict, provider: str, model: str | None = None) -> dict:
    if provider == "no_memory":
        return {
            "ndcg_at_k": 0.0, "recall_at_k": 0.0, "mrr_at_k": 0.0,
            "precision_at_k": 0.0, "context_efficiency": 0.0,
            "latency_ms": {"p50": 0.0, "p95": 0.0},
        }
    with tempfile.TemporaryDirectory(prefix="rta-public-bench-") as tmp:
        root = Path(tmp) / "corpus"
        root.mkdir()
        for document in payload["documents"]:
            destination = root / PurePosixPath(document["path"])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(document["text"], encoding="utf-8")
        conn = connect(Path(tmp) / "brain.sqlite")
        try:
            init_project(conn, "benchmark", str(root))
            if provider in {"hash_hybrid", "sentence-transformers"}:
                settings = {
                    "embedding_provider": "hash" if provider == "hash_hybrid" else "sentence-transformers",
                }
                if model:
                    settings["embedding_model"] = model
                update_project_settings(conn, "benchmark", settings, root_path=str(root))
            ingest_repo(conn, root, project="benchmark")
            scores = []
            latencies = []
            returned = 0
            relevant_returned = 0
            k = min(5, len(payload["documents"]))
            for query in payload["queries"]:
                started = perf_counter()
                result = search(conn, query["query"], project="benchmark", limit=k)
                latencies.append((perf_counter() - started) * 1000)
                paths = [str(item["path"]) for item in result["chunks"]]
                relevant = set(query["relevant_paths"])
                metric = _rank_metrics(paths, relevant, k)
                scores.append(metric)
                returned += len(paths)
                relevant_returned += sum(path in relevant for path in paths)
        finally:
            conn.close()
    count = len(scores)
    return {
        "ndcg_at_k": round(sum(item[0] for item in scores) / count, 6),
        "recall_at_k": round(sum(item[1] for item in scores) / count, 6),
        "mrr_at_k": round(sum(item[2] for item in scores) / count, 6),
        "precision_at_k": round(sum(item[3] for item in scores) / count, 6),
        "context_efficiency": round(relevant_returned / returned, 6) if returned else 0.0,
        "latency_ms": {"p50": round(median(latencies), 3), "p95": round(_percentile(latencies, 0.95), 3)},
    }


def _quality_gates() -> dict[str, float]:
    with tempfile.TemporaryDirectory(prefix="rta-public-gates-") as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        source = root / "state.md"
        source.write_text("The release gate is enabled.\n", encoding="utf-8")
        conn = connect(Path(tmp) / "brain.sqlite")
        try:
            init_project(conn, "gates", str(root))
            ingest_repo(conn, root, project="gates")
            source.write_text("The release gate is disabled.\n", encoding="utf-8")
            stale = stale_check(conn, project="gates", deep=True)
            stale_rejection = float(stale["state"] == "stale" and stale["changed"] == 1)

            remember(conn, "The guarded feature is enabled", project="gates")
            remember(conn, "The guarded feature is disabled", project="gates")
            reflected = reflect(conn, project="gates")
            contradiction_detection = float(reflected["contradictions_flagged"] == 2)

            save_checkpoint(
                conn, "gates", "Ship the verified build", verified_evidence="Focused checks passed",
                remaining_gaps="Operator review", next_action="Run browser proof",
                prohibited_repetition="Do not repeat unrelated scans",
            )
            continuation = build_continuation_prompt(conn, project="gates")
            continuation_success = float(
                "Ship the verified build" in continuation and "Run browser proof" in continuation
            )

            create_policy(
                conn, project="gates", kind="required_check", statement="Privacy proof is required",
                effect="block", action_contains="publish", required_check="privacy-proof",
                pramana="pratyaksha", confidence=0.95,
                provenance={"source_path": "state.md", "source_hash": "synthetic-proof", "verification_status": "verified"},
            )
            blocked = preflight(conn, project="gates", action="publish release")
            allowed = preflight(
                conn, project="gates", action="publish release", completed_checks=["privacy-proof"],
            )
            governance_accuracy = float(blocked["decision"] == "block" and allowed["decision"] == "allow")

            weak = append_claim(
                conn,
                project="gates",
                active_root=root,
                subject="decision:weak-evidence",
                predicate="status",
                value="enabled",
                claim_id="weak-evidence",
                idempotency_key="benchmark:weak-evidence",
                expected_stream_version=0,
                epistemic_state="accepted",
                authority_class="operator",
                confidence=0.9,
                verification_status="verified",
            )
            attach_evidence(
                conn,
                project="gates",
                active_root=root,
                claim_id=weak["claim"]["claim_id"],
                evidence_id="weak-support",
                source_identifier="state.md",
                source_hash=hashlib.sha256(source.read_bytes()).hexdigest(),
                method="synthetic-inference",
                polarity="supporting",
                authority_class="anumana",
                confidence=0.9,
                provenance={
                    "source_path": "state.md",
                    "source_hash": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "verification_status": "verified",
                },
                idempotency_key="benchmark:weak-support",
                expected_stream_version=0,
                verification_status="verified",
            )
            strong = append_claim(
                conn,
                project="gates",
                active_root=root,
                subject="decision:strong-evidence",
                predicate="status",
                value="enabled",
                claim_id="strong-evidence",
                idempotency_key="benchmark:strong-evidence",
                expected_stream_version=0,
                epistemic_state="accepted",
                authority_class="operator",
                confidence=0.9,
                verification_status="verified",
            )
            attach_evidence(
                conn,
                project="gates",
                active_root=root,
                claim_id=strong["claim"]["claim_id"],
                evidence_id="strong-support",
                source_identifier="state.md",
                source_hash=hashlib.sha256(source.read_bytes()).hexdigest(),
                method="synthetic-validator",
                polarity="supporting",
                authority_class="pratyaksha",
                confidence=1.0,
                provenance={
                    "source_path": "state.md",
                    "source_hash": hashlib.sha256(source.read_bytes()).hexdigest(),
                    "verification_status": "verified",
                },
                idempotency_key="benchmark:strong-support",
                expected_stream_version=0,
                verification_status="verified",
            )
            record_observation(
                conn,
                project="gates",
                active_root=root,
                observation_id="synthetic-delivery-conflict",
                subsystem="delivery",
                entity_key="release-state",
                expected_state="ready",
                observed_state="unknown",
                status="conflicting",
                source_identifier="benchmark://delivery",
                source_hash=hashlib.sha256(b"synthetic-delivery").hexdigest(),
                observed_at="2026-01-01T00:00:00+00:00",
            )
            cognition = cognition_snapshot(
                conn,
                project="gates",
                active_root=root,
                now="2026-01-01T00:00:00+00:00",
                include_change_impact=False,
            )
            debt_ids = {
                item["claim_id"] for item in cognition["decision_debt"]["items"]
            }
            decision_debt_detection = float(
                "weak-evidence" in debt_ids and "strong-evidence" not in debt_ids
            )
            evidence_authority_abstention = float("weak-evidence" in debt_ids)
            adapted = adapt_context_candidates(conn, project="gates")
            cognition_context_inclusion = float(any(
                item["source_type"] == "cognition"
                and "synthetic-delivery-conflict" in json.dumps(item)
                for item in adapted["candidates"]
            ))
        finally:
            conn.close()
    return {
        "stale_rejection": stale_rejection,
        "contradiction_detection": contradiction_detection,
        "continuation_success": continuation_success,
        "governance_accuracy": governance_accuracy,
        "decision_debt_detection": decision_debt_detection,
        "evidence_authority_abstention": evidence_authority_abstention,
        "cognition_context_inclusion": cognition_context_inclusion,
    }


def _stable_benchmark_context(text: str) -> str:
    replacements = {
        "Canonical repository root:": "Canonical repository root: <project-root>",
        "Repository identity:": "Repository identity: <repository-id>",
        "Git snapshot:": "Git snapshot: <git-snapshot>",
    }
    lines = []
    for line in str(text).splitlines():
        replacement = next(
            (value for prefix, value in replacements.items() if line.startswith(prefix)),
            None,
        )
        lines.append(replacement if replacement is not None else line)
    return "\n".join(lines) + ("\n" if str(text).endswith("\n") else "")


def _continuation_metrics(text: str, controls: list[str]) -> dict[str, float | int]:
    text = _stable_benchmark_context(text)
    normalized = " ".join(str(text).casefold().split())
    recovered = sum(
        " ".join(control.casefold().split()).rstrip(".") in normalized
        for control in controls
    )
    used_tokens = max(1, estimate_tokens(text))
    return {
        "required_controls": len(controls),
        "recovered_controls": recovered,
        "used_tokens": used_tokens,
        "continuation_success": round(recovered / len(controls), 6),
        "context_efficiency": round(recovered * 1_000 / used_tokens, 6),
    }


def run_context_compiler_benchmark() -> dict:
    """Compare the published v0.6 pack path with the governed v0.8 compiler."""
    from .context_host import (
        authorize_context_contract,
        build_task_contract,
        compile_context_for_agent,
        ensure_context_agent_profile,
    )

    fixture = json.loads(json.dumps(_CONTEXT_COMPILER_FIXTURE))
    fixture_digest = hashlib.sha256(
        json.dumps(
            fixture, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    effective_budget = 1_024
    with tempfile.TemporaryDirectory(prefix="rta-context-bench-") as tmp:
        root = Path(tmp) / "repo"
        root.mkdir()
        for command in (
            ("init", "--quiet"),
            ("config", "user.email", "fixture@example.invalid"),
            ("config", "user.name", "Fixture"),
        ):
            result = run_git_inspection(root, *command, max_output_bytes=1_048_576)
            if result is None or result.returncode != 0:
                raise RuntimeError("trusted Git could not prepare the context benchmark")
        (root / "state.md").write_text(
            "Synthetic release state for context compilation.\n", encoding="utf-8"
        )
        for command in (
            ("add", "state.md"),
            ("commit", "--quiet", "-m", "fixture"),
        ):
            result = run_git_inspection(root, *command, max_output_bytes=1_048_576)
            if result is None or result.returncode != 0:
                raise RuntimeError("trusted Git could not prepare the context benchmark")

        database = Path(tmp) / "brain.sqlite"
        conn = connect(database)
        try:
            init_project(conn, "context-benchmark", str(root))
            ingest_repo(conn, root, project="context-benchmark")
            save_checkpoint(
                conn,
                "context-benchmark",
                fixture["controls"][0],
                verified_evidence="Synthetic baseline verified.",
                next_action="Inspect the next bounded task.",
                prohibited_repetition="Do not repeat completed work.",
            )
            baseline_text = build_context_pack(
                conn,
                fixture["task"],
                project="context-benchmark",
                max_tokens=effective_budget,
            )

            reserved = 1_024 + 256 + 256 + 128
            profile = ensure_context_agent_profile(
                conn,
                project="context-benchmark",
                profile_id="benchmark-agent",
                actor_id="benchmark-operator",
                max_input_tokens=effective_budget + reserved,
            )
            contract = build_task_contract(
                project="context-benchmark",
                agent_profile_id="benchmark-agent",
                objective=fixture["controls"][0],
                actor_id="benchmark-operator",
                max_input_tokens=effective_budget + reserved,
            )
            contract["acceptance_criteria"] = [fixture["controls"][1]]
            contract["stop_conditions"] = [fixture["controls"][2]]
            contract["prohibited_repetition"] = [fixture["controls"][3]]
            contract.pop("control_index", None)
            authorized = authorize_context_contract(
                conn,
                project="context-benchmark",
                agent_profile_version_id=profile["agent_profile_version_id"],
                contract=contract,
                actor_id="benchmark-operator",
            )
            compiled = compile_context_for_agent(
                conn,
                db_path=database,
                project="context-benchmark",
                active_root=root,
                task_contract_id=authorized["task_contract_id"],
                principal_id="benchmark-agent",
                session_id="benchmark-session",
            )
            if compiled.get("status") != "stable":
                raise RuntimeError("synthetic context compilation was not stable")
            candidate_text = compiled["context_pack"]["context_text"]
        finally:
            conn.close()

    baseline = {
        "implementation": "v0.6-context-pack",
        **_continuation_metrics(baseline_text, fixture["controls"]),
    }
    candidate = {
        "implementation": "v0.8-context-compiler",
        **_continuation_metrics(candidate_text, fixture["controls"]),
    }
    continuation_delta = round(
        candidate["continuation_success"] - baseline["continuation_success"], 6
    )
    efficiency_delta = round(
        candidate["context_efficiency"] - baseline["context_efficiency"], 6
    )
    return {
        "schema_version": 1,
        "fixture": fixture["name"],
        "fixture_digest": fixture_digest,
        "synthetic": True,
        "effective_budget_tokens": effective_budget,
        "baseline": baseline,
        "candidate": candidate,
        "improvement": {
            "continuation_success_delta": continuation_delta,
            "context_efficiency_delta": efficiency_delta,
        },
        "gates": {
            "continuation_improved": float(continuation_delta > 0),
            "context_efficiency_improved": float(efficiency_delta > 0),
        },
        "limitations": {
            "external_superiority_evidence": False,
            "statement": (
                "Synthetic regression evidence for explicit continuation controls; "
                "not an external agent-success or market-superiority benchmark."
            ),
        },
    }


def run_public_benchmark(
    dataset: Path,
    *,
    include_semantic: bool = False,
    semantic_model: str = "all-MiniLM-L6-v2",
) -> dict:
    payload, digest = _load_dataset(Path(dataset))
    modes = {
        "no_memory": _run_mode(payload, "no_memory"),
        "lexical": _run_mode(payload, "lexical"),
        "hash_hybrid": _run_mode(payload, "hash_hybrid"),
        "optional_semantic": {
            "status": "not_requested",
            "provider": "sentence-transformers",
            "model": semantic_model,
        },
    }
    if include_semantic:
        try:
            metrics = _run_mode(payload, "sentence-transformers", semantic_model)
        except (ImportError, RuntimeError):
            modes["optional_semantic"] = {
                "status": "unavailable",
                "provider": "sentence-transformers",
                "model": semantic_model,
                "reason": "Optional local Sentence Transformers provider or model is unavailable.",
            }
        else:
            modes["optional_semantic"] = {
                "status": "ok", "provider": "sentence-transformers", "model": semantic_model, **metrics,
            }
    dataset_label = _safe_public_label(payload.get("name"), fallback="public corpus")
    return {
        "schema_version": 1,
        "dataset": dataset_label,
        "dataset_digest": digest,
        "corpus": {"documents": len(payload["documents"]), "queries": len(payload["queries"]), "synthetic": True},
        "modes": modes,
        "quality_gates": _quality_gates(),
        "context_compiler": run_context_compiler_benchmark(),
    }


def _metric(value) -> str:
    if isinstance(value, (int, float)):
        return f"{float(value):.3f}"
    return "NA"


def benchmark_report_markdown(result: dict, *, history: dict | None = None) -> str:
    """Render a bounded, shareable report for the synthetic public benchmark."""
    corpus = result.get("corpus") or {}
    modes = result.get("modes") or {}
    gates = result.get("quality_gates") or {}
    lines = [
        "# Rta-Smriti Public Benchmark",
        "",
        "This report summarizes the packaged synthetic reproducibility and regression harness. "
        "It is not external proof of superiority over other memory systems.",
        "",
        f"- Dataset: `{result.get('dataset', 'public corpus')}`",
        f"- Dataset digest: `{result.get('dataset_digest', 'unknown')}`",
        f"- Corpus: {int(corpus.get('documents') or 0)} documents, {int(corpus.get('queries') or 0)} queries",
        f"- Synthetic: {bool(corpus.get('synthetic'))}",
        "",
        "| Mode | Status | NDCG@K | Recall@K | MRR@K | Precision@K | P50 ms | P95 ms |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name in ("no_memory", "lexical", "hash_hybrid", "optional_semantic"):
        metrics = modes.get(name) or {}
        status = str(metrics.get("status") or "ok")
        latency = metrics.get("latency_ms") if isinstance(metrics.get("latency_ms"), dict) else {}
        lines.append(
            "| "
            + " | ".join((
                name,
                status,
                _metric(metrics.get("ndcg_at_k")),
                _metric(metrics.get("recall_at_k")),
                _metric(metrics.get("mrr_at_k")),
                _metric(metrics.get("precision_at_k")),
                _metric(latency.get("p50")),
                _metric(latency.get("p95")),
            ))
            + " |"
        )
    lines.extend([
        "",
        "## Quality Gates",
        "",
        "| Gate | Score |",
        "| --- | ---: |",
    ])
    for name in sorted(gates):
        lines.append(f"| {name} | {_metric(gates[name])} |")
    compiler = result.get("context_compiler") or {}
    if compiler:
        baseline = compiler.get("baseline") or {}
        candidate = compiler.get("candidate") or {}
        lines.extend([
            "",
            "## Context Compiler Comparison",
            "",
            (
                "The same synthetic project is measured at the same effective input budget. "
                "Control density is recovered required controls per 1,000 estimated tokens."
            ),
            "",
            "| Implementation | Controls recovered | Continuation success | Used tokens | Control density |",
            "| --- | ---: | ---: | ---: | ---: |",
        ])
        for metrics in (baseline, candidate):
            lines.append(
                "| "
                + " | ".join((
                    str(metrics.get("implementation") or "unknown"),
                    f"{int(metrics.get('recovered_controls') or 0)}/{int(metrics.get('required_controls') or 0)}",
                    _metric(metrics.get("continuation_success")),
                    str(int(metrics.get("used_tokens") or 0)),
                    _metric(metrics.get("context_efficiency")),
                ))
                + " |"
            )
        limitation = (compiler.get("limitations") or {}).get("statement")
        if limitation:
            lines.extend(["", str(limitation)])
    lines.extend([
        "",
        "Optional Sentence Transformers comparison is reported only when explicitly requested and available locally.",
        "No private repository content, local home paths, API keys, or credentials are required by this corpus.",
        "",
    ])
    comparison = (history or {}).get("comparison") or {}
    if comparison:
        lines.extend([
            "## Historical Comparison",
            "",
            "Latest run minus the preceding run from the same local history file.",
            "",
            "| Mode | NDCG@K delta | Recall@K delta | MRR@K delta | Precision@K delta |",
            "| --- | ---: | ---: | ---: | ---: |",
        ])
        for name in sorted(comparison):
            metrics = comparison[name]
            lines.append("| " + " | ".join((
                name,
                _metric(metrics.get("ndcg_at_k")),
                _metric(metrics.get("recall_at_k")),
                _metric(metrics.get("mrr_at_k")),
                _metric(metrics.get("precision_at_k")),
            )) + " |")
        lines.append("")
    return "\n".join(lines)


def _history_entry(result: dict, label: str) -> dict:
    safe_modes = {}
    for name, values in (result.get("modes") or {}).items():
        if not isinstance(values, dict):
            continue
        safe_modes[str(name)[:100]] = {
            key: values.get(key) for key in (
                "status", "provider", "model", "ndcg_at_k", "recall_at_k", "mrr_at_k", "precision_at_k", "latency_ms",
            ) if key in values
        }
    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "label": _safe_public_label(label, fallback="run"),
        "dataset": _safe_public_label(result.get("dataset"), fallback="public corpus"),
        "dataset_digest": str(result.get("dataset_digest") or "")[:128],
        "modes": safe_modes,
        "quality_gates": result.get("quality_gates") or {},
    }


def append_benchmark_history(result: dict, output: Path, *, label: str = "run") -> dict:
    requested = Path(output).expanduser()
    if requested.is_symlink():
        raise ValueError("refusing to append to a linked benchmark history")
    destination = requested.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        stat = destination.stat()
        if stat.st_nlink > 1:
            raise ValueError("refusing to append to a linked benchmark history")
        if stat.st_size > MAX_BENCHMARK_HISTORY_BYTES:
            raise ValueError("benchmark history exceeds its size limit")
        existing = benchmark_history(destination)
        if existing["run_count"] >= MAX_BENCHMARK_HISTORY_RUNS:
            raise ValueError("benchmark history exceeds its run limit")
    line = json.dumps(_history_entry(result, label), sort_keys=True, ensure_ascii=True) + "\n"
    if len(line.encode("utf-8")) > 100_000:
        raise ValueError("benchmark history record exceeds its size limit")
    if destination.exists() and destination.stat().st_size + len(line.encode("utf-8")) > MAX_BENCHMARK_HISTORY_BYTES:
        raise ValueError("benchmark history exceeds its size limit")
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(destination, flags, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    return benchmark_history(destination)


def benchmark_history(source: Path) -> dict:
    path = Path(source).expanduser()
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink > 1:
        raise ValueError("benchmark history must be an existing unlinked file")
    if path.stat().st_size > MAX_BENCHMARK_HISTORY_BYTES:
        raise ValueError("benchmark history exceeds its size limit")
    runs = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if line.strip():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"benchmark history record {line_number} is not valid JSON") from exc
                if not isinstance(record, dict) or not isinstance(record.get("modes"), dict):
                    raise ValueError(f"benchmark history record {line_number} has an invalid schema")
                for mode_name, metrics in record["modes"].items():
                    if not isinstance(mode_name, str) or not isinstance(metrics, dict):
                        raise ValueError(f"benchmark history record {line_number} has invalid mode data")
                    for metric_name in ("ndcg_at_k", "recall_at_k", "mrr_at_k", "precision_at_k"):
                        value = metrics.get(metric_name)
                        if value is not None and (
                            isinstance(value, bool)
                            or not isinstance(value, (int, float))
                            or not math.isfinite(float(value))
                        ):
                            raise ValueError(
                                f"benchmark history record {line_number} has invalid metric data"
                            )
                runs.append(record)
            if len(runs) > MAX_BENCHMARK_HISTORY_RUNS:
                raise ValueError("benchmark history exceeds its run limit")
    comparison = {}
    if len(runs) >= 2:
        previous, latest = runs[-2], runs[-1]
        for name in sorted(set((previous.get("modes") or {})) & set((latest.get("modes") or {}))):
            deltas = {}
            for key in ("ndcg_at_k", "recall_at_k", "mrr_at_k", "precision_at_k"):
                before = (previous["modes"].get(name) or {}).get(key)
                after = (latest["modes"].get(name) or {}).get(key)
                if isinstance(before, (int, float)) and isinstance(after, (int, float)):
                    deltas[key] = round(float(after) - float(before), 6)
            if deltas:
                comparison[name] = deltas
    return {"status": "ok", "run_count": len(runs), "runs": runs, "comparison": comparison}


def write_benchmark_report(result: dict, output: Path, *, history: dict | None = None) -> dict:
    requested = Path(output).expanduser()
    if requested.is_symlink():
        raise ValueError("refusing to replace a linked benchmark report")
    destination = requested.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        stat = destination.stat()
        if destination.is_symlink() or stat.st_nlink > 1:
            raise ValueError("refusing to replace a linked benchmark report")
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(benchmark_report_markdown(result, history=history))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {"status": "ok", "path": str(destination), "format": "markdown"}
