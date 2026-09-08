import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain.db import connect, init_project, remember, save_checkpoint
from rta_brain.governance import create_policy
from rta_brain.hooks import install_git_hooks, uninstall_git_hooks
from rta_brain.lifecycle import apply_memory_feedback, run_conservative_decay
from rta_brain.portability import (
    export_bundle,
    import_bundle,
    inspect_bundle,
    snapshot_create,
    snapshot_keygen,
    snapshot_verify,
)
from rta_brain.runtime_control import runtime_executable
from rta_brain.workspaces import (
    add_project_to_workspace,
    create_workspace,
    get_workspace,
    search_workspace,
)


def rewrite_bundle(path: Path, mutate) -> None:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    mutate(envelope["bundle"])
    canonical = json.dumps(
        envelope["bundle"], sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    envelope["manifest"]["sha256"] = hashlib.sha256(canonical).hexdigest()
    path.write_text(json.dumps(envelope), encoding="utf-8")


class PortabilityAndLifecycleTests(unittest.TestCase):
    def test_workspace_groups_multiple_projects_without_rebinding_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = connect(root / "brain.sqlite")
            try:
                init_project(conn, "api", str(root / "api"))
                init_project(conn, "web", str(root / "web"))
                create_workspace(conn, "product", "Product stack")
                add_project_to_workspace(conn, workspace="product", project="api", role="backend")
                add_project_to_workspace(conn, workspace="product", project="web", role="frontend")
                result = get_workspace(conn, "product")
            finally:
                conn.close()
        self.assertEqual([item["project"] for item in result["projects"]], ["api", "web"])
        self.assertEqual({item["role"] for item in result["projects"]}, {"backend", "frontend"})

    def test_workspace_search_crosses_independent_brain_databases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_path, second_path = root / "first.sqlite", root / "second.sqlite"
            first = connect(first_path)
            second = connect(second_path)
            try:
                init_project(first, "api", str(root / "api"))
                init_project(second, "web", str(root / "web"))
                remember(first, "Shared contract uses envelope version seven", project="api")
                remember(second, "Frontend reads envelope version seven", project="web")
                create_workspace(first, "product")
                add_project_to_workspace(first, workspace="product", project="api", db_path=first_path)
                add_project_to_workspace(first, workspace="product", project="web", db_path=second_path)
                from rta_brain.workspaces import search_workspace
                result = search_workspace(first, workspace="product", query="envelope version seven")
                recall_counts = (
                    first.execute("SELECT COUNT(*) FROM recall_logs").fetchone()[0],
                    second.execute("SELECT COUNT(*) FROM recall_logs").fetchone()[0],
                )
            finally:
                second.close()
                first.close()
        self.assertEqual({item["project"] for item in result["results"]}, {"api", "web"})
        self.assertTrue(all(item["memories"] for item in result["results"]))
        self.assertEqual(recall_counts, (0, 0))

    def test_workspace_members_require_existing_unlinked_brain_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = connect(root / "owner.sqlite")
            member_path = root / "member.sqlite"
            member = connect(member_path)
            try:
                init_project(owner, "api", str(root / "api"))
                init_project(member, "web", str(root / "web"))
                create_workspace(owner, "product")
                missing = root / "missing.sqlite"
                with self.assertRaisesRegex(ValueError, "does not exist"):
                    add_project_to_workspace(
                        owner, workspace="product", project="web", db_path=missing,
                    )
                self.assertFalse(missing.exists())

                linked = root / "linked.sqlite"
                linked.hardlink_to(member_path)
                with self.assertRaisesRegex(ValueError, "linked"):
                    add_project_to_workspace(
                        owner, workspace="product", project="web", db_path=linked,
                    )

                linked.unlink()
                add_project_to_workspace(
                    owner, workspace="product", project="web", db_path=member_path,
                )
                member.close()
                member = None
                member_path.unlink()
                degraded = search_workspace(owner, workspace="product", query="contract")
                self.assertEqual(degraded["status"], "degraded")
                self.assertEqual(degraded["results"], [])
                self.assertEqual(degraded["errors"][0]["project"], "web")
                self.assertFalse(member_path.exists())
            finally:
                if member is not None:
                    member.close()
                owner.close()

    def test_redacted_bundle_round_trip_and_signed_snapshot_detects_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_db = root / "source.sqlite"
            conn = connect(source_db)
            try:
                init_project(conn, "demo", str(root / "private-repo"))
                remember(
                    conn,
                    "Deploy with api_key=synthetic-redaction-fixture and keep the owner path private",
                    project="demo",
                    provenance={"source_path": str(Path.home() / "private" / "proof.md"), "verification_status": "verified"},
                )
                dry_run = export_bundle(
                    conn, root / "not-written.json", projects=["demo"], redact=True, preview=True,
                )
                bundle = export_bundle(conn, root / "bundle.json", projects=["demo"], redact=True)
            finally:
                conn.close()
            self.assertTrue(dry_run["preview"])
            self.assertFalse((root / "not-written.json").exists())
            self.assertEqual(dry_run["counts"]["memories"], 1)
            text = (root / "bundle.json").read_text(encoding="utf-8")
            self.assertNotIn(str(Path.home()), text)
            self.assertNotIn("synthetic-redaction-fixture", text)
            self.assertGreater(bundle["redactions"], 0)
            self.assertFalse(bundle["authenticated"])
            self.assertEqual(bundle["integrity"], "content-sha256")
            envelope = json.loads(text)
            self.assertEqual(envelope["manifest"]["authentication"], "none")

            target = connect(root / "target.sqlite")
            try:
                preview = inspect_bundle(root / "bundle.json", conn=target)
                self.assertEqual(preview["counts"]["projects"], 1)
                imported = import_bundle(target, root / "bundle.json")
                row = target.execute("SELECT text FROM memories").fetchone()
            finally:
                target.close()
            self.assertEqual(imported["projects"], 1)
            self.assertIn("[REDACTED]", row["text"])

            key = root / "snapshot.key"
            snapshot = root / "snapshot.rta.json"
            snapshot_create(source_db, snapshot, key_path=key)
            self.assertTrue(snapshot_verify(snapshot, key_path=key)["valid"])
            header, payload = snapshot.read_bytes().split(b"\n", 1)
            authenticated = json.loads(header)
            authenticated["manifest"]["project_count"] = 999
            snapshot.write_bytes(json.dumps(authenticated).encode("ascii") + b"\n" + payload)
            self.assertFalse(snapshot_verify(snapshot, key_path=key)["valid"])

    def test_snapshot_can_use_optional_public_key_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_db = root / "source.sqlite"
            conn = connect(source_db)
            try:
                init_project(conn, "demo", str(root / "repo"))
                remember(conn, "Public-key snapshot fixture", project="demo")
            finally:
                conn.close()

            private_key = root / "snapshot-ed25519-private.pem"
            public_key = root / "snapshot-ed25519-public.pem"
            try:
                generated = snapshot_keygen(private_key, public_key)
            except ValueError as exc:
                if "cryptography" in str(exc):
                    self.skipTest("cryptography optional dependency is not installed")
                raise
            snapshot = root / "snapshot.rta"

            self.assertEqual(generated["signature_algorithm"], "Ed25519")
            self.assertTrue(private_key.exists())
            self.assertTrue(public_key.exists())
            created = snapshot_create(source_db, snapshot, private_key_path=private_key)
            self.assertEqual(created["signature_algorithm"], "Ed25519")
            verified = snapshot_verify(snapshot, public_key_path=public_key)
            self.assertTrue(verified["valid"], verified)
            self.assertEqual(verified["manifest"]["signature_algorithm"], "Ed25519")

            header, payload = snapshot.read_bytes().split(b"\n", 1)
            authenticated = json.loads(header)
            authenticated["manifest"]["project_count"] = 999
            snapshot.write_bytes(json.dumps(authenticated).encode("ascii") + b"\n" + payload)
            self.assertFalse(snapshot_verify(snapshot, public_key_path=public_key)["valid"])

    def test_snapshot_auth_material_must_be_unambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_db = root / "source.sqlite"
            conn = connect(source_db)
            try:
                init_project(conn, "demo", str(root / "repo"))
            finally:
                conn.close()
            key = root / "snapshot.key"
            private_key = root / "private.pem"
            private_key.write_text("not a real key", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                snapshot_create(source_db, root / "snapshot.rta", key_path=key, private_key_path=private_key)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                snapshot_verify(root / "snapshot.rta", key_path=key, public_key_path=root / "public.pem")

    def test_unsigned_bundle_import_downgrades_memories_and_quarantines_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = connect(root / "source.sqlite")
            try:
                init_project(source, "demo", str(root / "repo"))
                remember(
                    source,
                    "Release only after owner approval",
                    project="demo",
                    pramana="pratyaksha",
                    confidence=1.0,
                    provenance={
                        "source_path": "proof.md",
                        "source_hash": "a" * 64,
                        "verification_status": "verified",
                    },
                )
                save_checkpoint(
                    source,
                    "demo",
                    "Run the imported next action",
                    next_action="Publish without another review",
                )
                create_policy(
                    source,
                    project="demo",
                    kind="constraint",
                    statement="Block every release",
                    effect="block",
                    pramana="pratyaksha",
                    confidence=1.0,
                    provenance={
                        "source_path": "proof.md",
                        "source_hash": "b" * 64,
                        "verification_status": "verified",
                    },
                    overrideable=False,
                )
                export_bundle(source, root / "bundle.json", projects=["demo"], redact=False)
            finally:
                source.close()

            target = connect(root / "target.sqlite")
            try:
                imported = import_bundle(target, root / "bundle.json")
                memory = target.execute(
                    """
                    SELECT m.pramana, mp.source_hash, mp.verification_status, mp.metadata_json
                    FROM memories m JOIN memory_provenance mp ON mp.memory_id = m.id
                    """
                ).fetchone()
                checkpoint_count = target.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0]
                policy_count = target.execute("SELECT COUNT(*) FROM governance_policies").fetchone()[0]
                quarantine = target.execute(
                    "SELECT record_type, status FROM portability_quarantine ORDER BY record_type"
                ).fetchall()
            finally:
                target.close()

        self.assertEqual(memory["pramana"], "smriti")
        self.assertEqual(memory["verification_status"], "unverified")
        self.assertIsNone(memory["source_hash"])
        self.assertEqual(checkpoint_count, 0)
        self.assertEqual(policy_count, 0)
        self.assertEqual([(row["record_type"], row["status"]) for row in quarantine], [
            ("checkpoint", "pending"), ("policy", "pending"),
        ])
        self.assertEqual(imported["quarantined"], {"checkpoints": 1, "policies": 1})
        self.assertFalse(imported["authenticated"])

    def test_redacted_bundle_removes_supported_secret_and_absolute_path_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            aws_key = "AK" + "IA" + "A" * 16
            jwt = ".".join(("eyJ" + "a" * 12, "b" * 12, "c" * 12))
            private_key = "-----BEGIN " + "PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----"
            windows_path = "C:" + "\\Private\\workspace\\secret.txt"
            unc_path = "\\\\server\\share\\private\\secret.txt"
            posix_path = "/opt/private/workspace/secret.txt"
            source = connect(root / "source.sqlite")
            try:
                init_project(source, "demo", str(root / "repo"))
                remember(
                    source,
                    "\n".join((aws_key, jwt, private_key, windows_path, unc_path, posix_path)),
                    project="demo",
                )
                result = export_bundle(source, root / "bundle.json", projects=["demo"], redact=True)
            finally:
                source.close()

            exported = (root / "bundle.json").read_text(encoding="utf-8")
            for sensitive in (aws_key, jwt, "BEGIN PRIVATE KEY", windows_path, unc_path, posix_path):
                self.assertNotIn(sensitive, exported)
            self.assertGreaterEqual(result["redactions"], 6)
            self.assertEqual(inspect_bundle(root / "bundle.json")["warnings"], [])

    def test_bundle_claiming_redaction_fails_closed_on_residual_sensitive_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = connect(root / "source.sqlite")
            try:
                init_project(source, "demo", str(root / "repo"))
                remember(source, "Portable memory", project="demo")
                export_bundle(source, root / "bundle.json", projects=["demo"])
            finally:
                source.close()
            aws_key = "AS" + "IA" + "Z" * 16
            rewrite_bundle(
                root / "bundle.json",
                lambda bundle: bundle["projects"][0]["memories"][0].update({"text": aws_key}),
            )
            with self.assertRaisesRegex(ValueError, "claims redaction"):
                inspect_bundle(root / "bundle.json")

    def test_bundle_reader_does_not_reopen_with_path_read_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = connect(root / "source.sqlite")
            try:
                init_project(source, "demo", str(root / "repo"))
                remember(source, "Portable memory", project="demo")
                export_bundle(source, root / "bundle.json", projects=["demo"])
            finally:
                source.close()

            with patch.object(Path, "read_text", side_effect=AssertionError("pathname reopen")):
                result = inspect_bundle(root / "bundle.json")

        self.assertEqual(result["status"], "ok")

    def test_legacy_snapshot_reader_is_bounded_without_path_read_text(self):
        import base64
        import hmac

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key_bytes = b"k" * 32
            key = root / "snapshot.key"
            key.write_bytes(key_bytes)
            database = b"abc"
            manifest = {
                "schema_version": 1,
                "kind": "rta-smriti-signed-snapshot",
                "created_at": "2026-08-16T00:00:00Z",
                "database_sha256": hashlib.sha256(database).hexdigest(),
                "database_bytes": len(database),
                "project_count": 0,
                "signature_algorithm": "HMAC-SHA256",
            }
            signature = hmac.new(
                key_bytes,
                json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            snapshot = root / "legacy.rta"
            snapshot.write_text(json.dumps({
                "manifest": manifest,
                "signature": signature,
                "database_base64": base64.b64encode(database).decode("ascii"),
            }), encoding="utf-8")

            with patch.object(Path, "read_text", side_effect=AssertionError("pathname reopen")):
                result = snapshot_verify(snapshot, key_path=key)

        self.assertTrue(result["valid"], result)

    def test_snapshot_rejects_unauthenticated_manifest_before_decoding_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "snapshot.key"
            key.write_bytes(b"k" * 32)
            snapshot = root / "hostile.rta"
            manifest = {
                "schema_version": 2,
                "kind": "rta-smriti-signed-snapshot",
                "created_at": "2026-08-16T00:00:00Z",
                "database_sha256": "0" * 64,
                "database_bytes": 3,
                "project_count": 0,
                "signature_algorithm": "HMAC-SHA256",
                "payload_encoding": "base64-lines",
            }
            snapshot.write_bytes(
                json.dumps({"manifest": manifest, "signature": "0" * 64}).encode("ascii")
                + b"\n%%%%"
            )
            result = snapshot_verify(snapshot, key_path=key)
            self.assertFalse(result["valid"])
            self.assertEqual(result["reason"], "snapshot manifest authentication failed")

    def test_snapshot_rejects_oversized_declared_database_before_payload_decode(self):
        from rta_brain.portability import MAX_SNAPSHOT_DATABASE_BYTES

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "snapshot.key"
            key.write_bytes(b"k" * 32)
            snapshot = root / "hostile.rta"
            manifest = {
                "schema_version": 2,
                "kind": "rta-smriti-signed-snapshot",
                "created_at": "2026-08-16T00:00:00Z",
                "database_sha256": "0" * 64,
                "database_bytes": MAX_SNAPSHOT_DATABASE_BYTES + 1,
                "project_count": 0,
                "signature_algorithm": "HMAC-SHA256",
                "payload_encoding": "base64-lines",
            }
            import hmac

            signature = hmac.new(
                b"k" * 32,
                json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            snapshot.write_bytes(
                json.dumps({"manifest": manifest, "signature": signature}).encode("ascii") + b"\n%%%%"
            )
            result = snapshot_verify(snapshot, key_path=key)
            self.assertFalse(result["valid"])
            self.assertEqual(result["reason"], "snapshot database exceeds the safe verification limit")

    def test_snapshot_rejects_oversized_key_files_before_reading_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key = root / "oversized.key"
            key.write_bytes(b"k" * 4097)
            snapshot = root / "snapshot.rta"
            snapshot.write_bytes(b"{}")
            with self.assertRaisesRegex(ValueError, "snapshot key exceeds"):
                snapshot_verify(snapshot, key_path=key)

    def test_bundle_import_stages_all_changes_before_destination_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = connect(root / "source.sqlite")
            try:
                init_project(source, "demo", str(root / "repo"))
                remember(source, "A valid memory before an invalid policy", project="demo")
                export_bundle(source, root / "bundle.json", projects=["demo"])
            finally:
                source.close()
            envelope = json.loads((root / "bundle.json").read_text(encoding="utf-8"))
            envelope["bundle"]["projects"][0]["policies"] = [{
                "kind": "not-a-policy", "statement": "invalid", "effect": "warn",
                "pramana": "smriti", "confidence": 0.5, "provenance_json": "{}",
                "overrideable": 1, "status": "active",
            }]
            canonical = json.dumps(
                envelope["bundle"], sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ).encode("utf-8")
            envelope["manifest"]["sha256"] = hashlib.sha256(canonical).hexdigest()
            (root / "bundle.json").write_text(json.dumps(envelope), encoding="utf-8")

            destination = connect(root / "destination.sqlite")
            try:
                with self.assertRaisesRegex(ValueError, "unknown governance policy kind"):
                    import_bundle(destination, root / "bundle.json")
                self.assertEqual(destination.execute("SELECT COUNT(*) FROM projects").fetchone()[0], 0)
                self.assertEqual(destination.execute("SELECT COUNT(*) FROM memories").fetchone()[0], 0)
            finally:
                destination.close()

    def test_bundle_preview_rejects_records_that_import_would_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = connect(root / "source.sqlite")
            try:
                init_project(source, "demo", str(root / "repo"))
                remember(source, "Valid portable memory", project="demo")
                export_bundle(source, root / "bundle.json", projects=["demo"])
            finally:
                source.close()

            rewrite_bundle(
                root / "bundle.json",
                lambda bundle: bundle["projects"][0]["memories"][0].update({"text": "x" * 20_001}),
            )
            with self.assertRaisesRegex(ValueError, "20,000"):
                inspect_bundle(root / "bundle.json")

            target = connect(root / "target.sqlite")
            try:
                with self.assertRaisesRegex(ValueError, "20,000"):
                    import_bundle(target, root / "bundle.json")
                self.assertEqual(target.execute("SELECT COUNT(*) FROM projects").fetchone()[0], 0)
            finally:
                target.close()

    def test_bundle_preview_validates_checkpoint_and_policy_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = connect(root / "source.sqlite")
            try:
                init_project(source, "demo", str(root / "repo"))
                remember(source, "Portable memory", project="demo")
                export_bundle(source, root / "bundle.json", projects=["demo"])
            finally:
                source.close()

            rewrite_bundle(
                root / "bundle.json",
                lambda bundle: bundle["projects"][0].update({
                    "checkpoints": [{"objective": "", "next_action": "continue"}],
                }),
            )
            with self.assertRaisesRegex(ValueError, "checkpoint objective"):
                inspect_bundle(root / "bundle.json")

            rewrite_bundle(
                root / "bundle.json",
                lambda bundle: bundle["projects"][0].update({
                    "checkpoints": [],
                    "policies": [{
                        "kind": "unknown", "statement": "Do not publish", "effect": "block",
                        "pramana": "smriti", "confidence": 0.5, "provenance_json": "{}",
                        "overrideable": 1, "status": "active",
                    }],
                }),
            )
            with self.assertRaisesRegex(ValueError, "unknown governance policy kind"):
                inspect_bundle(root / "bundle.json")

    def test_bundle_preview_rejects_unknown_and_lossy_provenance_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = connect(root / "source.sqlite")
            try:
                init_project(source, "demo", str(root / "repo"))
                remember(source, "Portable memory", project="demo")
                export_bundle(source, root / "bundle.json", projects=["demo"])
            finally:
                source.close()

            rewrite_bundle(
                root / "bundle.json",
                lambda bundle: bundle["projects"][0]["memories"][0].update({"unexpected": "field"}),
            )
            with self.assertRaisesRegex(ValueError, "unknown memory field"):
                inspect_bundle(root / "bundle.json")

            def replace_unknown_with_long_hash(bundle):
                memory = bundle["projects"][0]["memories"][0]
                memory.pop("unexpected")
                memory["source_hash"] = "a" * 257

            rewrite_bundle(root / "bundle.json", replace_unknown_with_long_hash)
            with self.assertRaisesRegex(ValueError, "source_hash"):
                inspect_bundle(root / "bundle.json")

    def test_bundle_preview_turns_malformed_manifest_types_into_clear_validation_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            malformed = root / "malformed.json"
            malformed.write_text(
                json.dumps({"manifest": [], "bundle": {"kind": "rta-smriti-selective-bundle"}}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "manifest"):
                inspect_bundle(malformed)

    def test_portability_outputs_and_keys_reject_hard_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "brain.sqlite"
            conn = connect(db_path)
            try:
                init_project(conn, "demo", str(root / "repo"))
                victim = root / "victim.txt"
                victim.write_text("keep", encoding="utf-8")
                linked_output = root / "bundle.json"
                linked_output.hardlink_to(victim)
                with self.assertRaisesRegex(ValueError, "linked portability artifact"):
                    export_bundle(conn, linked_output, projects=["demo"])
                self.assertEqual(victim.read_text(encoding="utf-8"), "keep")
            finally:
                conn.close()

            key_victim = root / "key-victim.bin"
            key_victim.write_bytes(b"x" * 32)
            linked_key = root / "snapshot.key"
            linked_key.hardlink_to(key_victim)
            with self.assertRaisesRegex(ValueError, "linked snapshot keys"):
                snapshot_create(db_path, root / "snapshot.rta", key_path=linked_key)
            self.assertEqual(key_victim.read_bytes(), b"x" * 32)

    def test_feedback_reinforces_verified_memory_and_decay_is_conservative(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = connect(Path(tmp) / "brain.sqlite")
            try:
                init_project(conn, "demo", tmp)
                verified = remember(
                    conn, "Verified release rule", project="demo", pramana="pratyaksha", confidence=0.8,
                    provenance={"verification_status": "verified"},
                )["memory"]
                hypothesis = remember(conn, "Maybe use another cache", project="demo", pramana="kalpana", confidence=0.6)["memory"]
                reinforced = apply_memory_feedback(conn, project="demo", memory_id=verified["id"], outcome="helpful", evidence="operator-confirmed")
                decayed = run_conservative_decay(conn, project="demo", minimum_age_days=0)
                rows = {row["id"]: dict(row) for row in conn.execute("SELECT id, confidence, priority, status FROM memories")}
            finally:
                conn.close()
        self.assertGreater(reinforced["memory"]["confidence"], 0.8)
        self.assertEqual(rows[verified["id"]]["status"], "active")
        self.assertLess(rows[hypothesis["id"]]["confidence"], 0.6)
        self.assertEqual(decayed["protected_verified"], 1)

    def test_git_hook_install_is_opt_in_refuses_unmanaged_hook_and_uninstalls_own_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", str(root)], check=True, capture_output=True, text=True)
            hooks = root / ".git" / "hooks"
            existing = hooks / "post-commit"
            existing.write_text("#!/bin/sh\necho existing\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                install_git_hooks(root, db_path=root / "brain.sqlite", project="demo")
            existing.unlink()
            installed = install_git_hooks(root, db_path=root / "brain.sqlite", project="demo")
            self.assertTrue(Path(installed["hook_path"]).exists())
            script = Path(installed["hook_path"]).read_text(encoding="utf-8")
            self.assertIn(str(runtime_executable()).replace("\\", "/"), script)
            self.assertIn(" -I ", script)
            self.assertIn(str(Path(__file__).resolve().parents[1]).replace("\\", "/"), script)
            self.assertIn("run_module", script)
            self.assertNotIn("-m rta_brain.cli", script)
            removed = uninstall_git_hooks(root)
            self.assertTrue(removed["removed"])
            self.assertFalse((hooks / "post-commit").exists())

    def test_git_hook_resolves_linked_worktree_hook_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repository = root / "repository"
            worktree = root / "worktree"
            subprocess.run(["git", "init", str(repository)], check=True, capture_output=True, text=True)
            (repository / "README.md").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "README.md"], check=True)
            subprocess.run(
                [
                    "git", "-C", str(repository), "-c", "user.name=Fixture",
                    "-c", "user.email=fixture@example.invalid", "commit", "-m", "fixture",
                ],
                check=True, capture_output=True, text=True,
            )
            subprocess.run(
                ["git", "-C", str(repository), "worktree", "add", "-b", "fixture-worktree", str(worktree)],
                check=True, capture_output=True, text=True,
            )
            self.assertTrue((worktree / ".git").is_file())
            installed = install_git_hooks(worktree, db_path=root / "brain.sqlite", project="demo")
            hook_path = Path(installed["hook_path"])
            self.assertTrue(hook_path.is_file())
            self.assertNotEqual(hook_path, worktree / ".git" / "hooks" / "post-commit")
            self.assertTrue(uninstall_git_hooks(worktree)["removed"])

    def test_frozen_git_hook_invokes_binary_without_python_module_switch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", str(root)], check=True, capture_output=True, text=True)
            executable = root / "rta-brain.exe"
            with patch.object(sys, "frozen", True, create=True), patch.object(sys, "executable", str(executable)):
                installed = install_git_hooks(root, db_path=root / "brain.sqlite", project="demo")
            script = Path(installed["hook_path"]).read_text(encoding="utf-8")
            self.assertIn(str(executable.resolve()).replace("\\", "/"), script)
            self.assertNotIn("-m rta_brain.cli", script)

    def test_git_hook_rejects_external_core_hooks_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repository"
            outside = Path(tmp) / "outside-hooks"
            root.mkdir()
            outside.mkdir()
            subprocess.run(["git", "init", str(root)], check=True, capture_output=True, text=True)
            subprocess.run(
                ["git", "-C", str(root), "config", "core.hooksPath", str(outside)],
                check=True,
            )

            with self.assertRaisesRegex(ValueError, "outside the verified Git common directory"):
                install_git_hooks(root, db_path=root / "brain.sqlite", project="demo")
            self.assertFalse((outside / "post-commit").exists())

    def test_git_hook_refuses_linked_hook_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", str(root)], check=True, capture_output=True, text=True)
            victim = root / "victim.sh"
            victim.write_text(f"#!/bin/sh\n{__import__('rta_brain.hooks', fromlist=['MARKER']).MARKER}\n", encoding="utf-8")
            hook = root / ".git" / "hooks" / "post-commit"
            hook.hardlink_to(victim)
            with self.assertRaisesRegex(ValueError, "linked"):
                install_git_hooks(root, db_path=root / "brain.sqlite", project="demo")
            self.assertEqual(hook.read_text(encoding="utf-8"), victim.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
