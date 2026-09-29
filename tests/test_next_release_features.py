import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from rta_brain import db


ROOT = Path(__file__).resolve().parents[1]


class RtaBrainNextReleaseTests(unittest.TestCase):
    def test_schema_indexes_source_scoped_chunk_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_schema(conn)
                indexes = {
                    str(row[1])
                    for row in conn.execute("PRAGMA index_list('chunks')")
                }
                self.assertIn("idx_chunks_source_id", indexes)

                plan = " ".join(
                    str(row[3])
                    for row in conn.execute(
                        "EXPLAIN QUERY PLAN SELECT 1 FROM chunks WHERE source_id = ? LIMIT 1",
                        (1,),
                    )
                ).upper()
                self.assertIn("IDX_CHUNKS_SOURCE_ID", plan)
            finally:
                conn.close()

    def test_project_settings_allow_a_larger_fail_closed_file_limit(self):
        self.assertTrue(hasattr(db, "update_project_settings"), "project settings API is missing")
        self.assertTrue(hasattr(db, "get_project_settings"), "project settings reader is missing")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            large = root / "large.py"
            large.write_text("x = '" + ("a" * 600_000) + "'\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.update_project_settings(conn, "demo", {"large_file_policy": "block"})
                blocked = db.ingest_repo(conn, root, project="demo")
                self.assertEqual(blocked["indexed_files"], 0)
                self.assertEqual(blocked["blocked_files"], 1)

                settings = db.update_project_settings(conn, "demo", {"max_file_bytes": 700_000})
                self.assertEqual(settings["max_file_bytes"], 700_000)
                indexed = db.ingest_repo(conn, root, project="demo")
                self.assertEqual(indexed["indexed_files"], 1)
                self.assertEqual(indexed["blocked_files"], 0)
                self.assertEqual(db.get_project_settings(conn, "demo")["max_file_bytes"], 700_000)
            finally:
                conn.close()

    def test_deep_freshness_reuses_the_completed_hash_cache(self):
        self.assertTrue(hasattr(db, "get_hash_cache_stats"), "hash cache diagnostics are missing")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "core.py").write_text("READY = True\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                first = db.stale_check(conn, project="demo", deep=True)
                second = db.stale_check(conn, project="demo", deep=True)
                stats = db.get_hash_cache_stats(conn, "demo")
                self.assertEqual(first["state"], "fresh")
                self.assertEqual(second["state"], "fresh")
                self.assertGreaterEqual(second["hash_cache_hits"], 1)
                self.assertGreaterEqual(stats["entries"], 1)
            finally:
                conn.close()

    def test_incremental_watcher_reindexes_a_changed_file(self):
        watcher = importlib.import_module("rta_brain.watch")
        self.assertTrue(hasattr(watcher, "watch_repository"), "repository watcher is missing")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            target = root / "service.py"
            target.write_text("STATE = 'one'\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                changed = False

                def change_after_first_cycle(_seconds):
                    nonlocal changed
                    if not changed:
                        target.write_text("STATE = 'two'\n", encoding="utf-8")
                        changed = True

                result = watcher.watch_repository(
                    conn,
                    root,
                    project="demo",
                    interval_seconds=0,
                    max_cycles=2,
                    sleep_fn=change_after_first_cycle,
                )
                self.assertEqual(result["cycles"], 2)
                self.assertEqual(result["updated_files"], 1)
                self.assertTrue(any(event["updated_files"] == 1 for event in result["events"]))
            finally:
                conn.close()

    def test_hash_embeddings_add_hybrid_scores_without_a_cloud_dependency(self):
        embeddings = importlib.import_module("rta_brain.embeddings")
        self.assertTrue(hasattr(embeddings, "HashEmbeddingProvider"), "local embedding provider is missing")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "queue.md").write_text("Latency budget and backpressure queue policy.\n", encoding="utf-8")
            (root / "colors.md").write_text("Cerulean palette and typography notes.\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.update_project_settings(conn, "demo", {"embedding_provider": "hash"}, root_path=str(root))
                indexed = db.ingest_repo(conn, root, project="demo")
                found = db.search(conn, "latency backpressure", project="demo", limit=4, hybrid=True)
                self.assertGreater(indexed["embedded_chunks"], 0)
                self.assertEqual(found["retrieval"]["mode"], "hybrid")
                self.assertEqual(found["retrieval"]["provider"], "hash")
                self.assertTrue(any("hybrid_score" in item for item in found["chunks"]))
                self.assertEqual(found["chunks"][0]["path"], "queue.md")
            finally:
                conn.close()

    def test_incremental_ingestion_repairs_a_partial_embedding_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "service.md").write_text(("queue latency policy " * 120) + "\n\n" + ("retry budget " * 120), encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.update_project_settings(conn, "demo", {"embedding_provider": "hash"}, root_path=str(root))
                first = db.ingest_repo(conn, root, project="demo")
                self.assertGreaterEqual(first["embedded_chunks"], 2)
                conn.execute("DELETE FROM chunk_embeddings WHERE chunk_id = (SELECT MIN(chunk_id) FROM chunk_embeddings)")
                conn.commit()

                repaired = db.ingest_repo(conn, root, project="demo")
                self.assertEqual(repaired["updated_files"], 1)
                self.assertGreaterEqual(repaired["embedded_chunks"], 2)
            finally:
                conn.close()

    def test_force_ingestion_reprocesses_unchanged_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            (root / "core.py").write_text("READY = True\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                normal = db.ingest_repo(conn, root, project="demo")
                forced = db.ingest_repo(conn, root, project="demo", force=True)
                self.assertTrue(normal["manifest_unchanged"])
                self.assertFalse(forced["manifest_unchanged"])
                self.assertEqual(forced["updated_files"], 1)
            finally:
                conn.close()

    def test_event_scoped_ingestion_hashes_content_even_when_stats_are_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            source = root / "core.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                original = source.stat()
                source.write_text("VALUE = 2\n", encoding="utf-8")
                os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))

                refreshed = db.ingest_repo(
                    conn, root, project="demo", changed_paths=[source],
                )
                indexed = conn.execute(
                    "SELECT hash FROM sources WHERE path = ?", (str(source.resolve()),),
                ).fetchone()

                self.assertEqual(refreshed["updated_files"], 1)
                self.assertEqual(refreshed["verified_changed_paths"], 1)
                self.assertEqual(indexed["hash"], db.sha256_text("VALUE = 2\n"))
            finally:
                conn.close()

    def test_event_scoped_ingestion_rejects_an_external_link_into_the_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            source = root / "core.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            linked_root = outside / "repo-link"
            try:
                linked_root.symlink_to(root, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlink creation unavailable: {exc}")

            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                with self.assertRaisesRegex(ValueError, "outside the repository root"):
                    db.ingest_repo(
                        conn,
                        root,
                        project="demo",
                        changed_paths=[linked_root / source.name],
                    )
            finally:
                conn.close()

    def test_deep_stale_repair_reindexes_only_same_stat_content_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            source = root / "core.py"
            source.write_text("READY = True\n", encoding="utf-8")
            original_stat = source.stat()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.ingest_repo(conn, root, project="demo")
                source.write_text("READY = None\n", encoding="utf-8")
                os.utime(
                    source,
                    ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                )

                fast = db.ingest_repo(conn, root, project="demo")
                self.assertTrue(fast["manifest_unchanged"])
                self.assertEqual(
                    db.stale_check(
                        conn,
                        project="demo",
                        deep=True,
                        refresh_hashes=True,
                    )["changed"],
                    1,
                )

                repaired = db.ingest_repo(
                    conn,
                    root,
                    project="demo",
                    repair_deep_stale=True,
                )
                self.assertEqual(repaired["updated_files"], 1)
                self.assertEqual(repaired["unchanged_files"], 0)
                self.assertEqual(db.stale_check(conn, project="demo", deep=True)["changed"], 0)
            finally:
                conn.close()

    def test_parser_registry_and_lsp_adapter_are_pluggable(self):
        parsers = importlib.import_module("rta_brain.parsers")
        self.assertTrue(hasattr(parsers, "ParserRegistry"), "parser registry is missing")

        class CustomParser:
            name = "custom"

            def parse(self, _path, _text):
                return parsers.ParseResult(symbols=["CustomSymbol"], imports=["custom.import"])

        registry = parsers.ParserRegistry(load_entry_points=False)
        registry.register(CustomParser())
        parsed = registry.parse(Path("demo.py"), "ignored", parser_name="custom")
        self.assertEqual(parsed.symbols, ["CustomSymbol"])
        self.assertIn("regex", registry.capabilities())
        self.assertIn("tree-sitter", registry.capabilities())
        self.assertIn("lsp", registry.capabilities())

    def test_dashboard_exposes_indexing_controls_and_blocked_warning(self):
        source = (ROOT / "dashboard-src" / "src" / "main.jsx").read_text(encoding="utf-8")
        styles = (ROOT / "dashboard-src" / "src" / "styles.css").read_text(encoding="utf-8")
        console = (ROOT / "rta_brain" / "console.py").read_text(encoding="utf-8")
        self.assertIn("Maximum source file size", source)
        self.assertIn("Hybrid retrieval", source)
        self.assertIn("Parser adapter", source)
        self.assertIn("Metadata-only files remain visible as warnings", source)
        self.assertIn("Strict block mode remains available", source)
        self.assertIn("Auto-detect supported language servers", source)
        self.assertIn("Thread compaction", source)
        self.assertIn("Canonical-root conflict", source)
        self.assertIn("Copy New Task Prompt", source)
        self.assertIn("Prompt Copied", source)
        self.assertIn("Command Copied", source)
        self.assertIn("Reference navigation", source)
        self.assertIn("goBackReference", source)
        self.assertIn("goToReferenceStart", source)
        self.assertIn("canvasCurvePath", source)
        self.assertIn("canvasLinkHalo", source)
        self.assertIn("direct links", source)
        self.assertIn(".canvasCard.traced", styles)
        self.assertIn(".canvasPort", styles)
        self.assertIn("Rta-Smriti Release", source)
        self.assertIn("The selected project brain is not assessed here", source)
        self.assertIn("refreshPublishReadiness", source)
        self.assertIn("Already Added", source)
        self.assertIn("Path copied", source)
        self.assertIn("addFileToTask", source)
        self.assertIn('document.execCommand("copy")', source)
        self.assertIn("color-scheme: dark", styles)
        self.assertIn("select option", styles)
        self.assertIn("Save Checkpoint", source)
        onboarding = (ROOT / "dashboard-src" / "src" / "first-project.jsx").read_text(encoding="utf-8")
        self.assertIn('<option value="hash">Local hybrid</option>', onboarding)
        self.assertIn('import FirstProject from "./first-project.jsx"', source)
        self.assertIn("Action Gate", source)
        self.assertIn("Evaluate action", source)
        self.assertIn("include_operational_context", source)
        self.assertIn("selection_reasons", source)
        self.assertIn(".selectionReasons", styles)
        self.assertIn('"/api/preflight"', source)
        self.assertIn('"/api/governance-policy"', source)
        self.assertIn('"/api/governance"', console)
        self.assertIn('"/api/preflight"', console)
        self.assertIn('"/api/governance-policy"', console)
        self.assertNotIn('<option value="upamana">', source)
        self.assertNotIn('<option value="arthapatti">', source)
        self.assertNotIn('<option value="anupalabdhi">', source)
        self.assertIn("Override receipts", source)
        self.assertIn("governanceRequestRef", source)
        self.assertIn('"/api/settings"', console)
        self.assertIn('"/api/checkpoint"', console)
        self.assertIn('"/api/continuation-prompt"', console)


if __name__ == "__main__":
    unittest.main()
