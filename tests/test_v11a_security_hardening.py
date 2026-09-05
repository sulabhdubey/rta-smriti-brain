import json

from rta_brain import context as context_module
from rta_brain import db as brain_db
from rta_brain import mcp_server as mcp_module
from rta_brain import progressive_retrieval as progressive_module
from rta_brain.cognition import cognition_snapshot, record_observation
from rta_brain.mcp_server import RtaBrainMcpServer
from rta_brain.portability import export_bundle
from rta_brain.privacy import redact_sensitive_data, redact_sensitive_text
from rta_brain.progressive_retrieval import ProgressiveRetriever
from rta_brain.temporal import (
    append_claim,
    attach_evidence,
    migrate_legacy_memories,
    rebuild_projections,
    relate_claims,
)


def _prepared_brain(tmp_path):
    database = tmp_path / "brain.sqlite"
    root = tmp_path / "private-repo"
    root.mkdir()
    conn = brain_db.connect(database)
    brain_db.init_project(conn, "demo", str(root))
    return conn, database, root


def test_recursive_redaction_treats_environment_and_headers_as_secret_containers():
    payload = {
        "environment": {"CUSTOM_VALUE": "opaque-private-value"},
        "headers": {"X-Custom": "opaque-private-header"},
    }

    redacted, count = redact_sensitive_data(payload)

    assert count == 2
    assert redacted["environment"] == "[REDACTED]"
    assert redacted["headers"] == "[REDACTED]"


def test_legacy_migration_preserves_valid_privacy_and_fails_closed_on_unknown(tmp_path):
    conn, _database, _root = _prepared_brain(tmp_path)
    try:
        expected = {}
        for privacy_class in ("public", "internal", "sensitive", "restricted"):
            memory_id = brain_db.remember(
                conn,
                f"{privacy_class} legacy memory",
                project="demo",
                metadata={"privacy_class": privacy_class},
            )["memory"]["id"]
            expected[memory_id] = privacy_class
        for label, metadata in (
            ("absent", {}),
            ("unknown", {"privacy_class": "future-private"}),
            ("null", {"privacy_class": None}),
        ):
            memory_id = brain_db.remember(
                conn,
                f"{label} legacy memory",
                project="demo",
                metadata=metadata,
            )["memory"]["id"]
            expected[memory_id] = "restricted"

        migrate_legacy_memories(conn)

        rows = {
            int(row["legacy_memory_id"]): row["privacy_class"]
            for row in conn.execute(
                "SELECT legacy_memory_id, privacy_class FROM truth_claim_versions"
            )
        }
        events = {
            int(json.loads(row["payload_json"])["legacy_memory_id"]): row["privacy_class"]
            for row in conn.execute(
                "SELECT payload_json, privacy_class FROM truth_events "
                "WHERE event_type = 'legacy_memory_registered.v1'"
            )
        }
    finally:
        conn.close()

    assert rows == expected
    assert events == expected


def test_legacy_migration_repairs_existing_projection_and_rebuild_keeps_repair(tmp_path):
    conn, _database, root = _prepared_brain(tmp_path)
    try:
        memory_id = brain_db.remember(
            conn,
            "legacy memory reclassified after migration",
            project="demo",
            metadata={"privacy_class": "internal"},
        )["memory"]["id"]
        migrate_legacy_memories(conn)
        conn.execute(
            "UPDATE memories SET metadata_json = ? WHERE id = ?",
            (json.dumps({}), memory_id),
        )
        conn.commit()

        repaired = migrate_legacy_memories(conn)
        repaired_class = conn.execute(
            "SELECT privacy_class FROM truth_claim_versions WHERE legacy_memory_id = ?",
            (memory_id,),
        ).fetchone()["privacy_class"]
        conn.commit()
        rebuild_projections(conn, project="demo", active_root=root)
        rebuilt_class = conn.execute(
            "SELECT privacy_class FROM truth_claim_versions WHERE legacy_memory_id = ?",
            (memory_id,),
        ).fetchone()["privacy_class"]
    finally:
        conn.close()

    assert repaired["legacy_memories_reclassified"] == 1
    assert repaired_class == "restricted"
    assert rebuilt_class == "restricted"


def test_redacted_selective_bundle_recursively_redacts_secret_metadata(tmp_path):
    conn, _database, _root = _prepared_brain(tmp_path)
    try:
        brain_db.remember(
            conn,
            "portable memory",
            project="demo",
            metadata={
                "nested": {
                    "items": [
                        {"private_key": "bundle-metadata-secret-7F3"},
                        {"safe": "retained"},
                    ],
                }
            },
            provenance={
                "metadata": {
                    "chain": [
                        {"access_token": "bundle-provenance-secret-8G4"},
                        {"safe": "also-retained"},
                    ]
                }
            },
        )
        output = tmp_path / "bundle.json"
        export_bundle(conn, output, projects=["demo"], redact=True)
    finally:
        conn.close()

    raw = output.read_text(encoding="utf-8")
    envelope = json.loads(raw)
    memory = envelope["bundle"]["projects"][0]["memories"][0]
    metadata = json.loads(memory["metadata_json"])
    provenance_metadata = json.loads(memory["provenance_metadata_json"])
    assert "bundle-metadata-secret-7F3" not in raw
    assert "bundle-provenance-secret-8G4" not in raw
    assert metadata["nested"]["items"][0]["private_key"] == "[REDACTED]"
    assert metadata["nested"]["items"][1]["safe"] == "retained"
    assert provenance_metadata["chain"][0]["access_token"] == "[REDACTED]"
    assert provenance_metadata["chain"][1]["safe"] == "also-retained"


def test_cognition_and_graph_projections_preserve_privacy_for_mcp_filtering(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    try:
        record_observation(
            conn,
            project="demo",
            active_root=root,
            observation_id="sensitive-observation",
            subsystem="release",
            entity_key="private-result",
            observed_state="HIDDEN-COGNITION-RESULT-91B",
            status="observed",
            source_identifier="operator",
            privacy_class="sensitive",
        )
        brain_db.remember(
            conn,
            "HIDDEN-GRAPH-CONTENT-82A release",
            project="demo",
            metadata={"privacy_class": "sensitive"},
        )
        snapshot = cognition_snapshot(
            conn,
            project="demo",
            active_root=root,
            include_change_impact=False,
        )
        graph = brain_db.graph_query(
            conn,
            project="demo",
            query_type="relevance",
            target="release",
        )
    finally:
        conn.close()

    observation = next(
        item
        for item in snapshot["project_twin"]["observations"]
        if item.get("observation_id") == "sensitive-observation"
    )
    assert observation["privacy_class"] == "sensitive"
    assert any(
        edge.get("privacy_class") == "sensitive" and edge.get("memory_id")
        for edge in graph["edges"]
    )

    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    cognition_result = json.dumps(
        server.call_tool(
            "brain_cognition_snapshot", {"include_change_impact": False}
        )
    )
    graph_result = json.dumps(
        server.call_tool(
            "brain_graph_query",
            {"query_type": "relevance", "target": "release"},
        )
    )
    assert "HIDDEN-COGNITION-RESULT-91B" not in cognition_result
    assert "HIDDEN-GRAPH-CONTENT-82A" not in graph_result


def test_mcp_search_and_retrieve_derive_chunk_privacy_from_source(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    marker = "HIDDEN-SOURCE-EVIDENCE-4D2"
    source_path = root / "restricted-source.md"
    source_path.write_text(
        f"sourceprivacytoken {marker}\n", encoding="utf-8"
    )
    try:
        brain_db.ingest_repo(conn, root, project="demo")
        conn.execute(
            "UPDATE sources SET metadata_json = ? WHERE path = ?",
            (json.dumps({"privacy_class": "restricted"}), str(source_path)),
        )
        conn.commit()
    finally:
        conn.close()

    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    search = server.call_tool(
        "brain_search", {"query": "sourceprivacytoken", "limit": 10}
    )["structuredContent"]
    index = server.call_tool(
        "brain_retrieve",
        {"stage": "index", "query": "sourceprivacytoken", "limit": 10},
    )["structuredContent"]
    evidence = server.call_tool(
        "brain_retrieve",
        {"stage": "evidence", "expansion_handle": index["expansion_handle"]},
    )["structuredContent"]

    rendered = json.dumps((search, index, evidence))
    assert marker not in rendered
    assert search["chunks"] == []
    assert index["items"] == []
    assert evidence["items"] == []
    assert search["privacy"]["filtered_counts"]["chunks"] == 1
    assert index["report"]["privacy_filtered_count"] == 1


def test_graph_nodes_use_complete_provenance_at_depth_zero_and_fail_closed_if_isolated(
    tmp_path,
):
    conn, database, root = _prepared_brain(tmp_path)
    try:
        public_memory = brain_db.remember(
            conn,
            "provenancenode public evidence",
            project="demo",
            metadata={"privacy_class": "public"},
        )["memory"]["id"]
        sensitive_memory = brain_db.remember(
            conn,
            "provenancenode sensitive evidence",
            project="demo",
            metadata={"privacy_class": "sensitive"},
        )["memory"]["id"]
        project_id = int(
            conn.execute("SELECT id FROM projects WHERE name = 'demo'").fetchone()["id"]
        )
        mixed_node = brain_db.ensure_entity(
            conn, project_id, "concept", "provenancenode"
        )
        for memory_id in (public_memory, sensitive_memory):
            memory_node = brain_db.ensure_entity(
                conn, project_id, "memory", f"memory:{memory_id}"
            )
            brain_db.add_edge(
                conn,
                project_id,
                memory_node,
                "mentions",
                mixed_node,
                memory_id=memory_id,
            )
        brain_db.ensure_entity(conn, project_id, "concept", "isolatedprivacy")
        conn.commit()

        mixed = brain_db.graph_query(
            conn,
            project="demo",
            query_type="relevance",
            target="provenancenode",
            depth=0,
            limit=1,
        )
        isolated = brain_db.graph_query(
            conn,
            project="demo",
            query_type="relevance",
            target="isolatedprivacy",
            depth=0,
            limit=1,
        )
        truncated_mixed = brain_db.graph_query(
            conn,
            project="demo",
            query_type="relevance",
            target="provenancenode",
            depth=1,
            limit=2,
        )
    finally:
        conn.close()

    assert mixed["edges"] == []
    assert mixed["nodes"][0]["privacy_class"] == "sensitive"
    assert isolated["edges"] == []
    assert isolated["nodes"][0]["privacy_class"] == "restricted"
    assert truncated_mixed["truncated"] is True
    mixed_node_projection = next(
        node for node in truncated_mixed["nodes"] if node["name"] == "provenancenode"
    )
    assert mixed_node_projection["privacy_class"] == "sensitive"
    assert all(
        edge["privacy_class"] == "sensitive"
        for edge in truncated_mixed["edges"]
        if mixed_node_projection["id"] in (edge["from_id"], edge["to_id"])
    )

    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    payload = server.call_tool(
        "brain_graph_query",
        {
            "query_type": "relevance",
            "target": "provenancenode",
            "depth": 1,
            "limit": 10,
        },
    )["structuredContent"]
    rendered = json.dumps((payload["nodes"], payload["edges"]))
    assert "provenancenode" not in rendered


def test_mcp_redacts_checkpoint_fields_from_all_checkpoint_reads(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    checkpoint_values = {
        "objective": "OPAQUE-CHECKPOINT-OBJECTIVE-6C4",
        "verified_evidence": "OPAQUE-CHECKPOINT-EVIDENCE-6C4",
        "remaining_gaps": "OPAQUE-CHECKPOINT-GAPS-6C4",
        "next_action": "OPAQUE-CHECKPOINT-ACTION-6C4",
        "prohibited_repetition": "OPAQUE-CHECKPOINT-PROHIBITION-6C4",
    }
    try:
        brain_db.save_checkpoint(
            conn,
            project="demo",
            **checkpoint_values,
        )
    finally:
        conn.close()

    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    reads = {
        "continuation": server.call_tool("brain_continuation_prompt", {}),
        "context_pack": server.call_tool(
            "brain_context_pack", {"task": "checkpoint continuity"}
        ),
        "operational_readiness": server.call_tool(
            "brain_operational_readiness", {}
        ),
    }
    for read_name, result in reads.items():
        rendered = json.dumps(result)
        for value in checkpoint_values.values():
            assert value not in rendered, read_name
        assert "[REDACTED:MCP_LOCAL_OR_SECRET]" in rendered, read_name


def test_progressive_truth_inherits_restricted_evidence_privacy_for_mcp(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    evidence_id = "restricted-child-evidence-17"
    evidence_method = "restricted-child-method-29"
    evidence_hash = "d" * 64
    try:
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id="internal-parent-claim",
            subject="evidenceprivacyclaim",
            predicate="state",
            value="visible parent",
            privacy_class="internal",
            idempotency_key="internal-parent-claim:1",
            expected_stream_version=0,
        )
        attached = attach_evidence(
            conn,
            project="demo",
            active_root=root,
            claim_id="internal-parent-claim",
            evidence_id=evidence_id,
            source_identifier="restricted-child-source",
            source_hash=evidence_hash,
            method=evidence_method,
            polarity="supporting",
            authority_class="operator",
            confidence=0.9,
            provenance={"review": "restricted"},
            privacy_class="restricted",
            idempotency_key="restricted-child-evidence:1",
            expected_stream_version=0,
        )
        evidence_event_id = attached["event"]["event_id"]
    finally:
        conn.close()

    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    index = server.call_tool(
        "brain_retrieve",
        {"stage": "index", "query": "evidenceprivacyclaim"},
    )["structuredContent"]
    evidence = server.call_tool(
        "brain_retrieve",
        {"stage": "evidence", "expansion_handle": index["expansion_handle"]},
    )["structuredContent"]
    rendered = json.dumps(evidence)

    assert "internal-parent-claim" not in rendered
    assert "truth_evidence" not in rendered
    for forbidden in (evidence_id, evidence_method, evidence_hash, evidence_event_id):
        assert forbidden not in rendered


def test_progressive_truth_missing_or_null_privacy_fails_closed(tmp_path, monkeypatch):
    conn, _database, root = _prepared_brain(tmp_path)
    try:
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id="damaged-truth-privacy",
            subject="damagedtruthprivacy",
            predicate="state",
            value="must remain hidden",
            privacy_class="internal",
            idempotency_key="damaged-truth-privacy:1",
            expected_stream_version=0,
        )
        original_search = progressive_module.search
        projection_mode = {"value": "missing"}

        def damaged_search(*args, **kwargs):
            result = original_search(*args, **kwargs)
            for claim in result.get("truth", []):
                if claim.get("claim_id") == "damaged-truth-privacy":
                    if projection_mode["value"] == "missing":
                        claim.pop("privacy_class", None)
                    else:
                        claim["privacy_class"] = None
            return result

        monkeypatch.setattr(progressive_module, "search", damaged_search)
        outcomes = []
        for mode in ("missing", "null"):
            projection_mode["value"] = mode
            result = ProgressiveRetriever(b"test-secret").retrieve(
                conn,
                project="demo",
                stage="index",
                query="damagedtruthprivacy",
                privacy_ceiling="internal",
            )
            outcomes.append(result)
    finally:
        conn.close()

    assert all(result["items"] == [] for result in outcomes)
    assert all(
        result["report"]["privacy_filtered_count"] == 1 for result in outcomes
    )


def test_structured_mcp_strings_redact_checkpoint_lines_centrally(
    tmp_path, monkeypatch
):
    conn, database, root = _prepared_brain(tmp_path)
    conn.close()
    checkpoint_values = (
        "COMPILED-CONTEXT-OBJECTIVE-71",
        "COMPILED-CONTEXT-EVIDENCE-72",
        "COMPILED-CONTEXT-GAPS-73",
        "COMPILED-CONTEXT-ACTION-74",
        "COMPILED-CONTEXT-PROHIBITION-75",
    )
    compiled_payload = {
        "status": "stable",
        "context_pack": {
            "context_text": "\n".join(
                (
                    f"Objective: {checkpoint_values[0]}",
                    f"- Verified evidence: {checkpoint_values[1]}",
                    f"Remaining gaps: {checkpoint_values[2]}",
                    f"Next action: {checkpoint_values[3]}",
                    f"Do not repeat: {checkpoint_values[4]}",
                )
            ),
            "content": f"Objective: {checkpoint_values[0]}",
        },
    }
    monkeypatch.setattr(
        mcp_module, "compile_context_for_agent", lambda *args, **kwargs: compiled_payload
    )
    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        context_contract_delegations={1: "a" * 64},
        tool_profile="full",
    )
    monkeypatch.setattr(
        server, "_require_context_contract_delegation", lambda conn, contract_id: None
    )

    result = server.call_tool("brain_context_compile", {"task_contract_id": 1})
    rendered = json.dumps(result)

    for value in checkpoint_values:
        assert value not in rendered
    assert rendered.count("[REDACTED:MCP_LOCAL_OR_SECRET]") >= 2


def test_brain_search_structurally_redacts_encoded_json_metadata_in_both_forms(
    tmp_path, monkeypatch
):
    conn, database, root = _prepared_brain(tmp_path)
    conn.close()
    secrets = {
        "metadata": "ENCODED-METADATA-PRIVATE-KEY-81",
        "provenance_metadata": "ENCODED-PROVENANCE-PASSWORD-82",
        "provenance": "ENCODED-PROVENANCE-TOKEN-83",
    }
    payload = {
        "status": "ok",
        "query": "encodedjsonsearch",
        "memories": [
            {
                "id": 1,
                "text": "encodedjsonsearch visible memory",
                "metadata_json": json.dumps(
                    {
                        "privacy_class": "internal",
                        "nested": [{"private_key": secrets["metadata"]}],
                    }
                ),
                "provenance_metadata_json": json.dumps(
                    {"nested": {"password": secrets["provenance_metadata"]}}
                ),
                "provenance_json": json.dumps(
                    {"chain": [{"access_token": secrets["provenance"]}]}
                ),
            }
        ],
        "chunks": [],
        "truth": [],
        "retrieval": {"mode": "fts", "provider": "none"},
    }
    monkeypatch.setattr(mcp_module, "search", lambda *args, **kwargs: payload)
    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )

    result = server.call_tool("brain_search", {"query": "encodedjsonsearch"})
    forms = (
        json.dumps(result["structuredContent"]),
        result["content"][0]["text"],
    )

    for response_form in forms:
        for secret in secrets.values():
            assert secret not in response_form
        assert "[REDACTED:MCP_LOCAL_OR_SECRET]" in response_form
    memory = result["structuredContent"]["memories"][0]
    assert json.loads(memory["metadata_json"])["nested"][0]["private_key"] == (
        "[REDACTED:MCP_LOCAL_OR_SECRET]"
    )
    assert json.loads(memory["provenance_metadata_json"])["nested"]["password"] == (
        "[REDACTED:MCP_LOCAL_OR_SECRET]"
    )
    assert json.loads(memory["provenance_json"])["chain"][0]["access_token"] == (
        "[REDACTED:MCP_LOCAL_OR_SECRET]"
    )


def test_brain_search_redacts_complete_home_paths_in_both_forms(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    windows_suffix = "private-windows-suffix\\plans\\release.txt"
    posix_suffix = "private-posix-suffix/plans/release.txt"
    windows_path = "C:\\Users\\reviewer\\" + windows_suffix
    posix_path = "/home/reviewer/" + posix_suffix
    windows_punctuation_suffix = (
        "Program Files (x86)\\Vendor+Agent\\[private]@corp\\release!.json"
    )
    posix_punctuation_suffix = (
        "opt/Vendor+Agent/[private]@corp/release!.json"
    )
    windows_punctuation_path = "D:\\" + windows_punctuation_suffix
    posix_punctuation_path = "/" + posix_punctuation_suffix
    try:
        brain_db.remember(
            conn,
            "\n".join(
                (
                    "pathredactionmarker",
                    windows_path,
                    posix_path,
                    windows_punctuation_path,
                    posix_punctuation_path,
                )
            ),
            project="demo",
            metadata={"privacy_class": "internal"},
        )
    finally:
        conn.close()
    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )

    result = server.call_tool("brain_search", {"query": "pathredactionmarker"})
    forms = (
        json.dumps(result["structuredContent"]),
        result["content"][0]["text"],
    )

    for response_form in forms:
        assert windows_path not in response_form
        assert posix_path not in response_form
        assert windows_punctuation_path not in response_form
        assert posix_punctuation_path not in response_form
        assert "private-windows-suffix" not in response_form
        assert "private-posix-suffix" not in response_form
        assert "[private]@corp" not in response_form
        assert "release!.json" not in response_form
        assert "[REDACTED:MCP_LOCAL_OR_SECRET]" in response_form


def test_context_pack_filters_real_and_missing_privacy_across_all_results(
    tmp_path, monkeypatch
):
    conn, database, root = _prepared_brain(tmp_path)
    hidden = {
        "restricted_memory": "HIDDEN-CONTEXT-RESTRICTED-MEMORY-91",
        "missing_memory": "HIDDEN-CONTEXT-MISSING-MEMORY-92",
        "restricted_chunk": "HIDDEN-CONTEXT-RESTRICTED-CHUNK-93",
        "missing_chunk": "HIDDEN-CONTEXT-MISSING-CHUNK-94",
        "restricted_truth": "HIDDEN-CONTEXT-RESTRICTED-TRUTH-95",
        "missing_truth": "HIDDEN-CONTEXT-MISSING-TRUTH-96",
    }
    restricted_path = root / "restricted-context.md"
    missing_path = root / "missing-context.md"
    restricted_path.write_text(
        f"contextprivacytoken {hidden['restricted_chunk']}", encoding="utf-8"
    )
    missing_path.write_text(
        f"contextprivacytoken {hidden['missing_chunk']}", encoding="utf-8"
    )
    try:
        brain_db.remember(
            conn,
            f"contextprivacytoken {hidden['restricted_memory']}",
            project="demo",
            metadata={"privacy_class": "restricted"},
        )
        brain_db.remember(
            conn,
            f"contextprivacytoken {hidden['missing_memory']}",
            project="demo",
            metadata={},
        )
        brain_db.remember(
            conn,
            "contextprivacytoken VISIBLE-CONTEXT-INTERNAL-90",
            project="demo",
            metadata={"privacy_class": "internal"},
        )
        brain_db.ingest_repo(conn, root, project="demo")
        conn.execute(
            "UPDATE sources SET metadata_json = ? WHERE path = ?",
            (json.dumps({"privacy_class": "restricted"}), str(restricted_path)),
        )
        conn.execute(
            "UPDATE sources SET metadata_json = ? WHERE path = ?",
            (json.dumps({}), str(missing_path)),
        )
        conn.commit()
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id="restricted-context-truth",
            subject="contextprivacytoken",
            predicate="state",
            value=hidden["restricted_truth"],
            privacy_class="restricted",
            idempotency_key="restricted-context-truth:1",
            expected_stream_version=0,
        )
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id="missing-context-truth",
            subject="contextprivacytoken",
            predicate="state",
            value=hidden["missing_truth"],
            privacy_class="internal",
            idempotency_key="missing-context-truth:1",
            expected_stream_version=0,
        )
        conn.commit()
    finally:
        conn.close()

    original_search = context_module.search

    def search_with_missing_truth_class(*args, **kwargs):
        result = original_search(*args, **kwargs)
        for claim in result.get("truth", []):
            if claim.get("claim_id") == "missing-context-truth":
                claim.pop("privacy_class", None)
        return result

    monkeypatch.setattr(context_module, "search", search_with_missing_truth_class)
    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )

    result = server.call_tool(
        "brain_context_pack", {"task": "contextprivacytoken", "limit": 20}
    )
    rendered = result["content"][0]["text"]

    assert "VISIBLE-CONTEXT-INTERNAL-90" in rendered
    for marker in hidden.values():
        assert marker not in rendered


def test_credential_key_variants_redact_in_mcp_and_selective_bundle(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    sensitive_keys = (
        "dbPassword",
        "db_password",
        "db-password",
        "databasePassword",
        "database_password",
        "database-password",
        "credentials",
        "dbCredentials",
        "service_credentials",
        "service-credentials",
    )
    benign = {
        "credentials_enabled": True,
        "credential_rotation_policy": "quarterly",
        "database_password_policy": "rotate quarterly",
        "passwordless_mode": True,
    }
    metadata = {
        "privacy_class": "internal",
        "credential_matrix": {
            **{key: f"HIDDEN-{index}-CREDENTIAL-VALUE" for index, key in enumerate(sensitive_keys)},
            **benign,
        },
    }
    try:
        brain_db.remember(
            conn,
            "credentialkeytoken visible memory",
            project="demo",
            metadata=metadata,
        )
        output = tmp_path / "credential-bundle.json"
        export_bundle(conn, output, projects=["demo"], redact=True)
    finally:
        conn.close()

    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    search_result = server.call_tool(
        "brain_search", {"query": "credentialkeytoken"}
    )["structuredContent"]
    mcp_metadata = json.loads(search_result["memories"][0]["metadata_json"])
    envelope = json.loads(output.read_text(encoding="utf-8"))
    bundle_metadata = json.loads(
        envelope["bundle"]["projects"][0]["memories"][0]["metadata_json"]
    )

    for key in sensitive_keys:
        assert mcp_metadata["credential_matrix"][key] == (
            "[REDACTED:MCP_LOCAL_OR_SECRET]"
        )
        assert bundle_metadata["credential_matrix"][key] == "[REDACTED]"
    for key, value in benign.items():
        assert mcp_metadata["credential_matrix"][key] == value
        assert bundle_metadata["credential_matrix"][key] == value


def test_repo_and_thread_reingestion_preserve_strongest_source_privacy(tmp_path):
    conn, _database, root = _prepared_brain(tmp_path)
    repo_path = root / "privacy_source.py"
    thread_path = root / "privacy_thread.txt"
    repo_path.write_text("SOURCE_PRIVACY = 'first'\n", encoding="utf-8")
    thread_path.write_text(
        "Decision: preserve the original thread source classification.",
        encoding="utf-8",
    )
    try:
        brain_db.ingest_repo(conn, root, project="demo", force=True)
        brain_db.ingest_thread(conn, thread_path, project="demo", root=root)
        conn.execute(
            "UPDATE sources SET metadata_json = ? "
            "WHERE project_id = (SELECT id FROM projects WHERE name = 'demo') "
            "AND kind = 'file' AND path = ?",
            (json.dumps({"privacy_class": "restricted"}), str(repo_path)),
        )
        conn.execute(
            "UPDATE sources SET metadata_json = ? "
            "WHERE project_id = (SELECT id FROM projects WHERE name = 'demo') "
            "AND kind = 'thread' AND path = ?",
            (json.dumps({"privacy_class": "sensitive"}), str(thread_path)),
        )
        conn.commit()

        repo_path.write_text("SOURCE_PRIVACY = 'second'\n", encoding="utf-8")
        thread_path.write_text(
            "Decision: preserve the stronger thread source classification after change.",
            encoding="utf-8",
        )
        brain_db.ingest_repo(conn, root, project="demo", force=True)
        brain_db.ingest_thread(conn, thread_path, project="demo", root=root)

        stored = {
            (row["kind"], row["path"]): json.loads(row["metadata_json"])[
                "privacy_class"
            ]
            for row in conn.execute(
                "SELECT kind, path, metadata_json FROM sources "
                "WHERE project_id = (SELECT id FROM projects WHERE name = 'demo') "
                "AND ((kind = 'file' AND path = ?) OR (kind = 'thread' AND path = ?))",
                (str(repo_path), str(thread_path)),
            )
        }
    finally:
        conn.close()

    assert stored == {
        ("file", str(repo_path)): "restricted",
        ("thread", str(thread_path)): "sensitive",
    }


def test_reingested_sensitive_thread_promotions_do_not_leak_through_internal_mcp(
    tmp_path,
):
    conn, database, root = _prepared_brain(tmp_path)
    thread_path = root / "sensitive-thread.txt"
    secret = "PROMOTED-THREAD-SECRET-TOKEN-771"
    thread_path.write_text(
        "Decision: establish the initial thread ingestion record.",
        encoding="utf-8",
    )
    try:
        brain_db.ingest_thread(conn, thread_path, project="demo", root=root)
        conn.execute(
            "UPDATE sources SET metadata_json = ? "
            "WHERE project_id = (SELECT id FROM projects WHERE name = 'demo') "
            "AND kind = 'thread' AND path = ?",
            (json.dumps({"privacy_class": "sensitive"}), str(thread_path)),
        )
        conn.commit()
        thread_path.write_text(
            f"Decision: retain sensitive promoted content {secret} after re-ingestion.",
            encoding="utf-8",
        )

        brain_db.ingest_thread(conn, thread_path, project="demo", root=root)
        promoted = conn.execute(
            "SELECT metadata_json FROM memories "
            "WHERE project_id = (SELECT id FROM projects WHERE name = 'demo') "
            "AND status IN ('active', 'pinned') AND text LIKE ?",
            (f"%{secret}%",),
        ).fetchone()
    finally:
        conn.close()

    assert promoted is not None
    assert json.loads(promoted["metadata_json"])["privacy_class"] == "sensitive"

    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    result = server.call_tool(
        "brain_search", {"query": "PROMOTED THREAD SECRET TOKEN 771"}
    )

    assert result["structuredContent"]["memories"] == []
    assert result["structuredContent"]["chunks"] == []
    assert secret not in json.dumps(result["structuredContent"])
    assert secret not in result["content"][0]["text"]


def test_restricted_relation_hides_both_claims_from_lower_privacy_ceiling(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    visible_claim_id = "visible-related-claim"
    restricted_claim_id = "restricted-counterpart-claim"
    relation_id = "restricted-counterpart-relation"
    try:
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id=visible_claim_id,
            subject="visible relation token",
            predicate="state",
            value="visible",
            privacy_class="internal",
            idempotency_key="visible-related-claim:1",
            expected_stream_version=0,
        )
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id=restricted_claim_id,
            subject="private relation counterpart",
            predicate="state",
            value="hidden",
            privacy_class="restricted",
            idempotency_key="restricted-counterpart-claim:1",
            expected_stream_version=0,
        )
        relate_claims(
            conn,
            project="demo",
            active_root=root,
            from_claim_id=visible_claim_id,
            relation_type="contradicts",
            to_claim_id=restricted_claim_id,
            relation_id=relation_id,
            idempotency_key="restricted-counterpart-relation:1",
            expected_stream_version=0,
        )
        conn.commit()
    finally:
        conn.close()

    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    search_result = server.call_tool(
        "brain_search", {"query": "visible relation token", "limit": 10}
    )
    index_result = server.call_tool(
        "brain_retrieve",
        {
            "stage": "index",
            "query": "visible relation token",
            "limit": 10,
            "privacy_ceiling": "internal",
        },
    )["structuredContent"]
    evidence_result = server.call_tool(
        "brain_retrieve",
        {
            "stage": "evidence",
            "expansion_handle": index_result["expansion_handle"],
            "limit": 10,
            "privacy_ceiling": "internal",
        },
    )
    current_result = server.call_tool(
        "brain_truth_current", {"claim_id": visible_claim_id}
    )
    explain_result = server.call_tool(
        "brain_truth_explain", {"claim_id": visible_claim_id}
    )

    for response in (
        search_result,
        evidence_result,
        current_result,
        explain_result,
    ):
        rendered = json.dumps(response)
        assert visible_claim_id not in rendered
        assert restricted_claim_id not in rendered
        assert relation_id not in rendered


def test_checkpoint_redaction_does_not_rewrite_ordinary_memory_or_metadata(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    memory_text = (
        "ordinarycheckpointtoken\n"
        "Objective: document an ordinary project objective.\n"
        "Next action: keep this ordinary memory visible."
    )
    metadata = {
        "privacy_class": "internal",
        "objective": "ordinary metadata objective",
        "remaining_gaps": "ordinary metadata gaps",
    }
    try:
        brain_db.remember(conn, memory_text, project="demo", metadata=metadata)
    finally:
        conn.close()
    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )

    result = server.call_tool("brain_search", {"query": "ordinarycheckpointtoken"})
    memory = result["structuredContent"]["memories"][0]

    assert memory["text"] == memory_text
    assert json.loads(memory["metadata_json"])["objective"] == metadata["objective"]
    assert json.loads(memory["metadata_json"])["remaining_gaps"] == metadata["remaining_gaps"]


def test_absolute_path_redaction_stops_before_trailing_sentence_prose():
    windows = (
        r"Run C:\Program Files (x86)\Vendor+Agent\[private]@corp\release!.json "
        "before launch."
    )
    posix = "Inspect /opt/Vendor+Agent/[private]@corp/release!.json before launch."

    redacted_windows, windows_count = redact_sensitive_text(windows)
    redacted_posix, posix_count = redact_sensitive_text(posix)

    assert redacted_windows == "Run [REDACTED] before launch."
    assert redacted_posix == "Inspect [REDACTED] before launch."
    assert windows_count >= 1
    assert posix_count >= 1


def test_mcp_redaction_accepts_advertised_large_retrieval_payload(tmp_path, monkeypatch):
    _conn, database, root = _prepared_brain(tmp_path)
    _conn.close()
    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    payload = {
        "status": "ok",
        "stage": "evidence",
        "items": [
            {
                "kind": "memory",
                "id": 1,
                "privacy_class": "internal",
                "excerpt": "x" * 350_000,
                "provenance_refs": [{} for _ in range(10_001)],
            }
        ],
    }
    monkeypatch.setattr(
        server.progressive_retriever,
        "retrieve",
        lambda *args, **kwargs: payload,
    )
    retrieve_tool = next(tool for tool in mcp_module.TOOLS if tool["name"] == "brain_retrieve")

    result = server.call_tool(
        "brain_retrieve",
        {"stage": "index", "query": "large", "max_tokens": 100_000},
    )

    assert retrieve_tool["inputSchema"]["properties"]["max_tokens"]["maximum"] == 100_000
    assert len(result["structuredContent"]["items"][0]["excerpt"]) == 350_000
    assert len(result["structuredContent"]["items"][0]["provenance_refs"]) == 10_001


def test_graph_node_privacy_uses_bounded_aggregate_without_degree_downgrade(
    tmp_path, monkeypatch
):
    conn, _database, root = _prepared_brain(tmp_path)
    try:
        project_id = brain_db.ensure_project(conn, "demo")
        public_source = brain_db.upsert_source(
            conn,
            project_id,
            "file",
            str(root / "public.py"),
            "public.py",
            "public-hash",
            {"privacy_class": "public"},
        )
        restricted_source = brain_db.upsert_source(
            conn,
            project_id,
            "file",
            str(root / "restricted.py"),
            "restricted.py",
            "restricted-hash",
            {"privacy_class": "restricted"},
        )
        hub = brain_db.ensure_entity(conn, project_id, "symbol", "bounded privacy hub")
        for index in range(200):
            leaf = brain_db.ensure_entity(conn, project_id, "symbol", f"public leaf {index}")
            brain_db.add_edge(
                conn,
                project_id,
                hub,
                "calls",
                leaf,
                source_id=public_source,
            )
        restricted_leaf = brain_db.ensure_entity(
            conn, project_id, "symbol", "restricted final leaf"
        )
        brain_db.add_edge(
            conn,
            project_id,
            hub,
            "calls",
            restricted_leaf,
            source_id=restricted_source,
        )
        conn.commit()

        def reject_edge_materialization(_rows):
            raise AssertionError("node privacy materialized incident graph edges")

        monkeypatch.setattr(
            brain_db, "_classified_graph_edges", reject_edge_materialization
        )
        result = brain_db.graph_query(
            conn,
            project="demo",
            query_type="impact",
            target="bounded privacy hub",
            depth=0,
            limit=1,
        )
    finally:
        conn.close()

    assert result["nodes"] == [
        {
            "id": hub,
            "type": "symbol",
            "name": "bounded privacy hub",
            "canonical_key": "bounded-privacy-hub",
            "privacy_class": "restricted",
        }
    ]
