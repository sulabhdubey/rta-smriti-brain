import json
import hashlib
import os
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from rta_brain import db


class ContextHostTests(unittest.TestCase):
    def _git(self, root, *args):
        subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    def _compiler_fixture(self, directory):
        from rta_brain.context_host import (
            authorize_context_contract,
            build_task_contract,
            ensure_context_agent_profile,
        )

        root = Path(directory) / "repo"
        root.mkdir()
        self._git(root, "init")
        self._git(root, "config", "user.email", "fixture@example.invalid")
        self._git(root, "config", "user.name", "Fixture")
        (root / "state.txt").write_text("ready\n", encoding="utf-8")
        self._git(root, "add", "state.txt")
        self._git(root, "commit", "-m", "fixture")
        database = Path(directory) / "brain.sqlite"
        conn = db.connect(database)
        project_id = db.ensure_project(conn, "demo", str(root))
        timestamp = "2026-08-22T00:00:00+00:00"
        conn.execute(
            """
            INSERT INTO checkpoints(
                project_id, objective, verified_evidence, remaining_gaps,
                next_action, prohibited_repetition, source, trigger,
                version, created_at, updated_at
            ) VALUES (?, 'Resume safely', 'verified baseline', '', 'continue',
                      'do not publish', 'operator', 'manual', 1, ?, ?)
            """,
            (project_id, timestamp, timestamp),
        )
        conn.commit()
        profile = ensure_context_agent_profile(
            conn,
            project="demo",
            profile_id="codex",
            actor_id="owner",
            max_input_tokens=8192,
        )
        contract = build_task_contract(
            project="demo",
            agent_profile_id="codex",
            objective="Resume the verified task without repeating completed work.",
            actor_id="owner",
            comparison_modes=["minimal", "investigative"],
        )
        authorized = authorize_context_contract(
            conn,
            project="demo",
            agent_profile_version_id=profile["agent_profile_version_id"],
            contract=contract,
            actor_id="owner",
        )
        return conn, database, root, authorized

    def test_authority_secret_is_created_once_and_never_exposed_by_status(self):
        from rta_brain.context_host import (
            context_authority_status,
            load_context_authority_secret,
        )

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            db.init_project(conn, "demo", tmp)
            conn.close()

            with ThreadPoolExecutor(max_workers=8) as pool:
                secrets = list(
                    pool.map(
                        lambda _index: load_context_authority_secret(database),
                        range(16),
                    )
                )
            status = context_authority_status(database)

            self.assertEqual(len(set(secrets)), 1)
            self.assertEqual(len(secrets[0]), 32)
            self.assertEqual(status["status"], "ready")
            self.assertEqual(status["storage"], "os_protected" if os.name == "nt" else "owner_file")
            self.assertRegex(status["key_fingerprint"], r"^[0-9a-f]{16}$")
            self.assertNotIn("secret", status)
            self.assertNotIn("path", status)

    def test_host_capability_bucket_preserves_at_least_half_the_ttl(self):
        from rta_brain.context_host import _CAPABILITY_TTL_SECONDS, _host_capability

        with tempfile.TemporaryDirectory() as tmp:
            conn, database, _root, authorized = self._compiler_fixture(tmp)
            try:
                ttl_ms = _CAPABILITY_TTL_SECONDS * 1_000
                now = ttl_ms - 1
                capability, _secret, selected_now = _host_capability(
                    conn,
                    db_path=database,
                    project="demo",
                    task_contract_id=authorized["task_contract_id"],
                    principal_type="agent",
                    principal_id="codex",
                    session_id="bucket-boundary",
                    scopes=["compile:context"],
                    now_epoch_ms=now,
                )
            finally:
                conn.close()

        self.assertEqual(selected_now, now)
        self.assertGreaterEqual(
            int(capability["expires_at_epoch_ms"]) - now,
            ttl_ms // 2,
        )

    def test_linked_authority_secret_is_rejected(self):
        from rta_brain.context_host import (
            context_authority_paths,
            load_context_authority_secret,
        )

        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            db.init_project(conn, "demo", tmp)
            conn.close()
            paths = context_authority_paths(database)
            paths["directory"].mkdir(parents=True, exist_ok=True)
            target = Path(tmp) / "attacker.secret"
            target.write_text("attacker-controlled", encoding="ascii")
            try:
                paths["secret"].symlink_to(target)
            except OSError:
                self.skipTest("symbolic links are unavailable for this user")

            with self.assertRaisesRegex(ValueError, "linked"):
                load_context_authority_secret(database)

    def test_bounded_context_json_rejects_oversized_input(self):
        from rta_brain.context_host import load_bounded_context_json

        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "contract.json"
            payload.write_text(json.dumps({"value": "x" * 128}), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "size limit"):
                load_bounded_context_json(payload, maximum_bytes=64)

    def test_host_compilation_is_idempotent_and_never_returns_bearer_material(self):
        from rta_brain.context_host import (
            audit_context_for_operator,
            compile_context_for_agent,
            explain_context_for_agent,
        )

        with tempfile.TemporaryDirectory() as tmp:
            conn, database, root, authorized = self._compiler_fixture(tmp)
            now_epoch_ms = int(time.time() * 1_000)
            common = {
                "conn": conn,
                "db_path": database,
                "project": "demo",
                "active_root": root,
                "task_contract_id": authorized["task_contract_id"],
                "principal_id": "codex",
                "session_id": "task-123",
                "now_epoch_ms": now_epoch_ms,
            }
            first = compile_context_for_agent(**common)
            second = compile_context_for_agent(**common)
            explanation = explain_context_for_agent(
                conn,
                db_path=database,
                project="demo",
                compilation_id=first["compilation_receipt"]["compilation_id"],
                principal_id="codex",
                session_id="task-123",
                now_epoch_ms=now_epoch_ms + 1,
            )
            audit = audit_context_for_operator(
                conn,
                db_path=database,
                project="demo",
                compilation_id=first["compilation_receipt"]["compilation_id"],
                operator_id="owner",
                session_id="operator-task",
                now_epoch_ms=now_epoch_ms + 1,
            )
            conn.close()

        self.assertEqual(first["status"], "stable")
        self.assertEqual(first["context_pack"]["compiler_mode"], "balanced")
        self.assertEqual(
            first["compilation_receipt"]["compilation_id"],
            second["compilation_receipt"]["compilation_id"],
        )
        self.assertTrue(second["compilation_receipt"]["idempotent_replay"])
        self.assertEqual(
            {item["variant_id"] for item in first["available_variants"]},
            {"primary", "mode:minimal", "mode:investigative"},
        )
        self.assertEqual(len(explanation["pack_variants"]), 3)
        self.assertEqual(len(audit["variant_candidate_receipts"]), 2)
        serialized = json.dumps(
            {"first": first, "second": second, "explanation": explanation, "audit": audit},
            sort_keys=True,
        )
        self.assertNotIn("capability_token", serialized)
        self.assertNotIn("authority_secret", serialized)
        self.assertNotIn("operator_audit", serialized)
        self.assertNotIn("variant_audits", serialized)

    def test_agent_pack_renders_failed_check_and_unverified_claim_state(self):
        from rta_brain.context_host import compile_context_for_agent, explain_context_for_agent
        from rta_brain.temporal import append_claim, define_validator, run_validator

        with tempfile.TemporaryDirectory() as tmp:
            conn, database, root, authorized = self._compiler_fixture(tmp)
            common = {"conn": conn, "project": "demo", "active_root": root}
            try:
                artifact = root / "state.txt"
                append_claim(**common, subject="state.txt", predicate="matches_baseline", value=True,
                             claim_id="state-proof", idempotency_key="state-proof", expected_stream_version=0)
                define_validator(
                    **common, validator_id="state-hash", validator_type="file_sha256", claim_id="state-proof",
                    config={"path": "state.txt", "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()},
                    failure_effect="stale", idempotency_key="state-hash", expected_stream_version=0,
                )
                artifact.write_text("changed\n", encoding="utf-8")
                run_validator(**common, validator_id="state-hash",
                              idempotency_key="state-hash:run", expected_stream_version=1)
                compiled = compile_context_for_agent(
                    **common, db_path=database, task_contract_id=authorized["task_contract_id"],
                    principal_id="codex", session_id="state-proof-session",
                )
                explanation = explain_context_for_agent(
                    conn, db_path=database, project="demo",
                    compilation_id=compiled["compilation_receipt"]["compilation_id"],
                    principal_id="codex", session_id="state-proof-session",
                )
            finally:
                conn.close()
        self.assertEqual(compiled["status"], "stable")
        selected = next(row for row in compiled["context_pack"]["selected"]
                        if row["source_id"] == "truth:state-proof")
        self.assertIn("Evidence state: stale", selected["text"])
        self.assertIn("assertion verification: unverified", selected["text"])
        self.assertIn("recorded checks: fail", compiled["context_pack"]["context_text"])
        self.assertEqual(selected["instruction_policy"], "data_only_never_execute")
        self.assertTrue(explanation["receipt_integrity_verified"])
        self.assertLessEqual(compiled["context_pack"]["budget"]["used_tokens"],
                             compiled["context_pack"]["budget"]["available_tokens"])

    def test_host_returns_only_the_requested_authorized_variant(self):
        from rta_brain.context_host import compile_context_for_agent

        with tempfile.TemporaryDirectory() as tmp:
            conn, database, root, authorized = self._compiler_fixture(tmp)
            now_epoch_ms = int(time.time() * 1_000)
            result = compile_context_for_agent(
                conn,
                db_path=database,
                project="demo",
                active_root=root,
                task_contract_id=authorized["task_contract_id"],
                principal_id="codex",
                session_id="task-variants",
                variant_id="mode:minimal",
                now_epoch_ms=now_epoch_ms,
            )
            conn.close()

        self.assertEqual(result["context_pack"]["compiler_mode"], "minimal")
        self.assertNotIn("context_variants", result)
        self.assertNotIn("result", result)

    def test_host_rejects_an_unauthorized_variant_before_persisting_a_compilation(self):
        from rta_brain.context_host import compile_context_for_agent

        with tempfile.TemporaryDirectory() as tmp:
            conn, database, root, authorized = self._compiler_fixture(tmp)
            with self.assertRaisesRegex(PermissionError, "variant"):
                compile_context_for_agent(
                    conn,
                    db_path=database,
                    project="demo",
                    active_root=root,
                    task_contract_id=authorized["task_contract_id"],
                    principal_id="codex",
                    session_id="task-unauthorized",
                    variant_id="mode:handoff",
                )
            count = conn.execute(
                "SELECT COUNT(*) FROM context_compilations"
            ).fetchone()[0]
            conn.close()

        self.assertEqual(count, 0)

    def test_agent_explanation_is_bound_to_the_original_principal_session(self):
        from rta_brain.context_host import (
            compile_context_for_agent,
            explain_context_for_agent,
        )

        with tempfile.TemporaryDirectory() as tmp:
            conn, database, root, authorized = self._compiler_fixture(tmp)
            compiled = compile_context_for_agent(
                conn,
                db_path=database,
                project="demo",
                active_root=root,
                task_contract_id=authorized["task_contract_id"],
                principal_id="codex",
                session_id="task-original",
            )
            compilation_id = compiled["compilation_receipt"]["compilation_id"]
            with self.assertRaisesRegex(PermissionError, "principal session"):
                explain_context_for_agent(
                    conn,
                    db_path=database,
                    project="demo",
                    compilation_id=compilation_id,
                    principal_id="codex",
                    session_id="task-other",
                )
            conn.close()

    def test_operator_records_an_outcome_and_revokes_the_compilation_grant(self):
        from rta_brain.context_host import (
            compile_context_for_agent,
            explain_context_for_agent,
            record_context_outcome_for_operator,
            revoke_context_compilation_grant,
        )

        with tempfile.TemporaryDirectory() as tmp:
            conn, database, root, authorized = self._compiler_fixture(tmp)
            compiled = compile_context_for_agent(
                conn,
                db_path=database,
                project="demo",
                active_root=root,
                task_contract_id=authorized["task_contract_id"],
                principal_id="codex",
                session_id="task-outcome",
            )
            compilation_id = compiled["compilation_receipt"]["compilation_id"]
            outcome = record_context_outcome_for_operator(
                conn,
                db_path=database,
                project="demo",
                compilation_id=compilation_id,
                operator_id="owner",
                session_id="operator-task",
                outcome={
                    "outcome_id": "outcome-1",
                    "task_status": "success",
                    "evidence": {"tests": "passed"},
                    "acceptance_results": {"context": "accepted"},
                    "attributions": [],
                },
            )
            explanation = explain_context_for_agent(
                conn,
                db_path=database,
                project="demo",
                compilation_id=compilation_id,
                principal_id="codex",
                session_id="task-outcome",
            )
            revocation = revoke_context_compilation_grant(
                conn,
                db_path=database,
                project="demo",
                compilation_id=compilation_id,
                operator_id="owner",
                reason="Session closed by operator.",
            )
            with self.assertRaisesRegex(PermissionError, "revoked"):
                explain_context_for_agent(
                    conn,
                    db_path=database,
                    project="demo",
                    compilation_id=compilation_id,
                    principal_id="codex",
                    session_id="task-outcome",
                )
            conn.close()

        self.assertFalse(outcome["idempotent_replay"])
        self.assertEqual(explanation["outcomes"][0]["outcome_id"], "outcome-1")
        self.assertEqual(revocation["status"], "revoked")
        self.assertNotIn("grant_id", revocation)

    def test_revoked_compilation_stays_revoked_after_capability_bucket_rollover(self):
        from rta_brain.context_host import (
            compile_context_for_agent,
            explain_context_for_agent,
            revoke_context_compilation_grant,
        )

        with tempfile.TemporaryDirectory() as tmp:
            conn, database, root, authorized = self._compiler_fixture(tmp)
            try:
                compiled = compile_context_for_agent(
                    conn,
                    db_path=database,
                    project="demo",
                    active_root=root,
                    task_contract_id=authorized["task_contract_id"],
                    principal_id="codex",
                    session_id="task-revoked",
                )
                compilation_id = compiled["compilation_receipt"]["compilation_id"]
                grant = conn.execute(
                    """
                    SELECT g.issued_at_epoch_ms, g.expires_at_epoch_ms
                    FROM context_compilations c
                    JOIN context_authority_grants g ON g.id = c.authority_grant_id
                    WHERE c.compilation_id = ?
                    """,
                    (compilation_id,),
                ).fetchone()
                revoke_context_compilation_grant(
                    conn,
                    db_path=database,
                    project="demo",
                    compilation_id=compilation_id,
                    operator_id="owner",
                    reason="Session closed by operator.",
                    now_epoch_ms=int(grant["issued_at_epoch_ms"]) + 1_000,
                )

                with self.assertRaisesRegex(PermissionError, "revoked"):
                    explain_context_for_agent(
                        conn,
                        db_path=database,
                        project="demo",
                        compilation_id=compilation_id,
                        principal_id="codex",
                        session_id="task-revoked",
                        now_epoch_ms=int(grant["expires_at_epoch_ms"]) + 1,
                    )
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
