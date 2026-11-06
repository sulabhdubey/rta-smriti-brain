"""Reproduce a fictional truth-lifecycle proof with real local engine calls."""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / "rta_brain").is_dir():
    sys.path.insert(0, str(ROOT))

from rta_brain import __version__, db, temporal, context_host, context_receipts, context_selection, context_candidates


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.SetPriorityClass.restype = wintypes.BOOL
        if not kernel.SetPriorityClass(wintypes.HANDLE(-1), 0x4000):
            raise ctypes.WinError(ctypes.get_last_error())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    checks = []
    started = time.perf_counter()

    def check(name, condition):
        checks.append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    modules = {}
    for module in (db, temporal, context_host, context_receipts, context_selection, context_candidates):
        name = module.__name__.rsplit(".", 1)[-1] + ".py"
        installed = Path(module.__file__)
        checkout = args.source / "rta_brain" / name
        check("runtime_source_matches_" + name,
              installed.read_text(encoding="utf-8") == checkout.read_text(encoding="utf-8"))
        modules[name] = digest(installed)
    runtime_kind = "source_checkout" if Path(db.__file__).resolve().is_relative_to(args.source.resolve()) else "installed_release"
    check("runtime_version_declared", bool(__version__))

    with tempfile.TemporaryDirectory(prefix="smriti-proof-", dir=output) as temp:
        root = Path(temp) / "fictional-project"
        root.mkdir()
        source = root / "decision.txt"
        source.write_text("Storage format: YAML\nPayloads: metadata only\n", encoding="utf-8")
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        for git_args in (
            ["init", "-q"],
            ["config", "user.email", "proof@example.invalid"],
            ["config", "user.name", "Fictional Demo"],
            ["add", "decision.txt"],
            ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-qm", "Fictional baseline"],
        ):
            subprocess.run(["git", "-C", str(root), *git_args], check=True,
                           capture_output=True, creationflags=flags)
        database = Path(temp) / "fictional.sqlite"
        conn = db.connect(database)
        try:
            db.init_project(conn, "fictional-demo", str(root))
            common = {"conn": conn, "project": "fictional-demo", "active_root": root}
            original = temporal.append_claim(
                **common, subject="export", predicate="format", value="YAML",
                claim_id="format", idempotency_key="format:1", expected_stream_version=0,
                valid_from="2026-01-01T00:00:00+00:00", privacy_class="public",
            )
            corrected = temporal.revise_claim(
                **common, claim_id="format", value="JSONL", idempotency_key="format:2",
                expected_stream_version=1, valid_from="2026-01-01T00:00:00+00:00",
                reason="Operator correction: use one metadata record per line.",
            )
            old = temporal.truth_as_of(
                conn, project="fictional-demo", claim_id="format",
                valid_at="2026-06-01T00:00:00+00:00", recorded_sequence=1,
            )["claim"]
            current = temporal.truth_current(conn, project="fictional-demo", claim_id="format")["claim"]
            verification = conn.execute(
                "SELECT verification_status FROM truth_claim_versions "
                "WHERE claim_id = 'format' AND recorded_to_sequence IS NULL"
            ).fetchone()[0]
            check("old_decision_preserved", old["object"] == "YAML")
            check("correction_is_current", current["object"] == "JSONL")
            check("correction_not_self_verified", verification == "unverified")

            expected_hash = digest(source)
            temporal.append_claim(
                **common, subject="decision.txt", predicate="matches_baseline", value=True,
                claim_id="file-evidence", idempotency_key="file:1", expected_stream_version=0,
                privacy_class="public",
            )
            temporal.define_validator(
                **common, validator_id="source-hash", validator_type="file_sha256",
                claim_id="file-evidence", config={"path": "decision.txt", "sha256": expected_hash},
                failure_effect="stale", idempotency_key="validator:1", expected_stream_version=0,
                privacy_class="public",
            )
            first = temporal.run_validator(
                **common, validator_id="source-hash", idempotency_key="validator:run:1",
                expected_stream_version=1,
            )
            check("initial_validator_passes", first["evaluation"]["outcome"] == "pass")
            source.write_text("Storage format: JSONL\nPayloads: metadata only\n", encoding="utf-8")
            before_rerun = temporal.truth_current(
                conn, project="fictional-demo", claim_id="file-evidence"
            )["claim"]
            check("read_does_not_claim_automatic_revalidation", before_rerun["effective_state"] != "stale")
            rerun = temporal.run_validator(
                **common, validator_id="source-hash", idempotency_key="validator:run:2",
                expected_stream_version=2,
            )
            after_rerun = temporal.truth_current(
                conn, project="fictional-demo", claim_id="file-evidence"
            )["claim"]
            check("changed_file_fails_original_hash", rerun["evaluation"]["outcome"] == "fail")
            check("failed_revalidation_marks_stale", after_rerun["effective_state"] == "stale")

            for claim_id, value in (("rule-a", "No external network calls"), ("rule-b", "Fetch external data")):
                temporal.append_claim(
                    **common, subject="fictional-policy", predicate="network", value=value,
                    claim_id=claim_id, idempotency_key=claim_id, expected_stream_version=0,
                    privacy_class="public",
                )
            temporal.relate_claims(
                **common, from_claim_id="rule-a", relation_type="contradicts", to_claim_id="rule-b",
                relation_id="policy-conflict", idempotency_key="policy-conflict", expected_stream_version=0,
            )
            conflicts = [temporal.truth_current(conn, project="fictional-demo", claim_id=i)["claim"]
                         for i in ("rule-a", "rule-b")]
            check("both_registered_conflict_branches_disputed", all(c["effective_state"] == "disputed" for c in conflicts))

            event_count = conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0]
            blocked = False
            try:
                temporal.append_claim(
                    **common, subject="agent-result", predicate="status", value="verified",
                    claim_id="forged", idempotency_key="forged", expected_stream_version=0,
                    actor_type="agent", authority_class="agent-proposal", verification_status="verified",
                )
            except PermissionError as exc:
                blocked = "self-verify" in str(exc)
            check("agent_self_verification_rejected_for_expected_reason", blocked)
            check("rejection_created_no_event", conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0] == event_count)

            temporal.append_claim(
                **common, subject="private-placeholder", predicate="value", value="FICTIONAL_PRIVATE_CANARY",
                claim_id="private-placeholder", idempotency_key="private-placeholder", expected_stream_version=0,
                privacy_class="restricted",
            )
            profile = context_host.ensure_context_agent_profile(
                conn, project="fictional-demo", profile_id="proof-reader", actor_id="fictional-owner",
                max_input_tokens=8192, privacy_ceiling="public",
            )
            contract = context_host.build_task_contract(
                project="fictional-demo", agent_profile_id="proof-reader", actor_id="fictional-owner",
                objective="Inspect the corrected export format and unresolved policy conflict.",
                max_input_tokens=8192, privacy_ceiling="public",
            )
            auth = context_host.authorize_context_contract(
                conn, project="fictional-demo", agent_profile_version_id=profile["agent_profile_version_id"],
                contract=contract, actor_id="fictional-owner",
            )
            compiled = context_host.compile_context_for_agent(
                **common, db_path=database, task_contract_id=auth["task_contract_id"],
                principal_id="proof-reader", session_id="fictional-session",
            )
            check("compiler_is_stable", compiled["status"] == "stable")
            receipt_id = compiled["compilation_receipt"]["compilation_id"]
            explanation = context_host.explain_context_for_agent(
                conn, db_path=database, project="fictional-demo", compilation_id=receipt_id,
                principal_id="proof-reader", session_id="fictional-session",
            )
            check("receipt_integrity_verified", explanation["receipt_integrity_verified"] is True)
            serialized = json.dumps({"compiled": compiled, "explanation": explanation}, sort_keys=True)
            check("restricted_content_absent_from_agent_result", "FICTIONAL_PRIVATE_CANARY" not in serialized)
            check("bearer_material_absent_from_agent_result", all(x not in serialized for x in ("capability_token", "authority_secret")))
            selected = {row["source_id"]: row for row in compiled["context_pack"]["selected"]}
            check("agent_sees_stale_evidence_label", "Evidence state: stale" in selected["truth:file-evidence"]["text"])
            check("agent_sees_unverified_correction_label", "assertion verification: unverified" in selected["truth:format"]["text"])
            check("agent_sees_both_disputed_branches", all("Evidence state: disputed" in selected["truth:" + name]["text"] for name in ("rule-a", "rule-b")))
            budget = compiled["context_pack"]["budget"]
            check("rendered_status_fits_authorized_budget", budget["used_tokens"] <= budget["available_tokens"])
            # Keep raw diagnostic output private; only allowlisted fields enter the public proof.
            (output / "private-engine-output.json").write_text(json.dumps({
                "compiled": compiled, "explanation": explanation,
                "before_rerun": before_rerun, "after_rerun": after_rerun,
            }, indent=2), encoding="utf-8")

            ledger = temporal.verify_ledger(conn, project="fictional-demo")
            check("ledger_integrity_ok", ledger["status"] == "ok")
            proof = {
                "schema": "rta-smriti.fictional-proof/v1",
                "runtime": __version__,
                "runtime_kind": runtime_kind,
                "source_baseline_commit": "43f238fd4214a8095e13af3b3291d7a2c6f75de3",
                "data": "Fictional fixture. Actual engine API calls. No model calls. Module hashes bind the implementation.",
                "decision": {"before": old["object"], "current": current["object"],
                             "verification": verification, "history_preserved": True},
                "revalidation": {"first_outcome": first["evaluation"]["outcome"],
                                 "state_before_explicit_rerun": before_rerun["effective_state"],
                                 "outcome_after_source_change": rerun["evaluation"]["outcome"],
                                 "state_after_explicit_rerun": after_rerun["effective_state"],
                                 "automatic": False},
                "conflict": {"registered_by": "operator", "branches": [
                    {"value": c["object"], "state": c["effective_state"]} for c in conflicts],
                    "automatic_instruction_arbitration": False},
                "controls": {"agent_self_verification": "rejected", "restricted_content": "excluded",
                             "agent_output_bearer_material": "absent"},
                "receipt": {"status": compiled["status"], "integrity_verified": True,
                            "compilation_id": receipt_id, "budget": budget,
                            "selection": explanation["selection"],
                            "receipt_digest": explanation["compilation"]["receipt_digest"],
                            "agent_evidence": [
                                {"source_id": row["source_id"], "text": row["text"],
                                 "instruction_policy": row["instruction_policy"]}
                                for row in selected.values()
                            ]},
                "module_sha256": modules,
                "checks": checks,
                "elapsed_seconds": round(time.perf_counter() - started, 3),
                "limits": ["A synthetic maintainer test, not an independent security audit.",
                           "Source checks do not automatically prove a decision correct.",
                           "Conflicts were explicitly registered; no general instruction parser is demonstrated.",
                           "No model/session capture or cross-host handoff is exercised by this script.",
                           "Claude native handoff remains unverified."],
            }
            public = output / "public"
            public.mkdir(exist_ok=True)
            (public / "proof.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"passed": len(checks), "elapsed_seconds": proof["elapsed_seconds"],
                              "runtime": proof["runtime"]}))
        finally:
            conn.close()


if __name__ == "__main__":
    main()
