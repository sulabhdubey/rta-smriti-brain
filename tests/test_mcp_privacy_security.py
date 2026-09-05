import json

import pytest

from rta_brain import db as brain_db
from rta_brain import mcp_server
from rta_brain.context import build_context_pack, filter_search_results_by_privacy
from rta_brain.db import connect, init_project
from rta_brain.mcp_server import RtaBrainMcpServer
from rta_brain.privacy import redact_sensitive_data
from rta_brain.workspaces import (
    add_project_to_workspace,
    create_workspace,
    search_workspace,
)


def _prepared_brain(tmp_path):
    database = tmp_path / "brain.sqlite"
    root = tmp_path / "repo"
    root.mkdir()
    conn = connect(database)
    init_project(conn, "demo", str(root))
    return conn, database, root


def _add_privacy_markers(conn):
    for privacy_class, marker in (
        ("public", "VISIBLE-PUBLIC-CONTEXT"),
        ("internal", "VISIBLE-INTERNAL-CONTEXT"),
        ("sensitive", "HIDDEN-SENSITIVE-CONTEXT"),
        ("restricted", "HIDDEN-RESTRICTED-CONTEXT"),
        ("future-class", "HIDDEN-UNKNOWN-CONTEXT"),
    ):
        brain_db.remember(
            conn,
            f"privacy-context-marker {marker}",
            project="demo",
            metadata={"privacy_class": privacy_class},
        )


def test_context_pack_applies_ceiling_and_fails_closed_on_unknown_class(tmp_path):
    conn, _database, _root = _prepared_brain(tmp_path)
    try:
        _add_privacy_markers(conn)
        pack = build_context_pack(
            conn,
            "privacy-context-marker",
            project="demo",
            limit=20,
            privacy_ceiling="internal",
        )
    finally:
        conn.close()

    assert "VISIBLE-PUBLIC-CONTEXT" in pack
    assert "VISIBLE-INTERNAL-CONTEXT" in pack
    assert "HIDDEN-SENSITIVE-CONTEXT" not in pack
    assert "HIDDEN-RESTRICTED-CONTEXT" not in pack
    assert "HIDDEN-UNKNOWN-CONTEXT" not in pack


def test_search_filter_honors_parsed_metadata_and_unknown_classes():
    payload = filter_search_results_by_privacy(
        {
            "memories": [
                {
                    "text": "HIDDEN-PARSED-SENSITIVE",
                    "metadata": {"privacy_class": "sensitive"},
                },
                {
                    "text": "HIDDEN-PARSED-UNKNOWN",
                    "metadata": {"privacy_class": "future-class"},
                },
            ],
            "chunks": [],
            "truth": [],
        },
        "internal",
    )

    assert payload["memories"] == []


def test_workspace_search_applies_ceiling_to_each_member_result(tmp_path):
    conn, _database, _root = _prepared_brain(tmp_path)
    try:
        _add_privacy_markers(conn)
        create_workspace(conn, "release")
        add_project_to_workspace(conn, workspace="release", project="demo")
        payload = search_workspace(
            conn,
            workspace="release",
            query="privacy-context-marker",
            limit_per_project=20,
            privacy_ceiling="internal",
        )
    finally:
        conn.close()

    rendered = json.dumps(payload)
    assert "VISIBLE-PUBLIC-CONTEXT" in rendered
    assert "VISIBLE-INTERNAL-CONTEXT" in rendered
    assert "HIDDEN-SENSITIVE-CONTEXT" not in rendered
    assert "HIDDEN-RESTRICTED-CONTEXT" not in rendered
    assert "HIDDEN-UNKNOWN-CONTEXT" not in rendered


def test_public_server_denies_every_read_without_explicit_privacy_filter(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    conn.close()
    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="public",
        tool_profile="full",
    )

    guarded = {
        name
        for name in server.enabled_tools
        if mcp_server._tool_contract(name)["effect"] == "read"
        and name not in mcp_server.PUBLIC_PRIVACY_AWARE_READ_TOOLS
    }
    assert guarded
    for name in guarded:
        with pytest.raises(PermissionError, match="internal-or-higher"):
            server.call_tool(name, {})


def test_mcp_context_pack_cannot_exceed_immutable_server_ceiling(tmp_path):
    conn, database, root = _prepared_brain(tmp_path)
    try:
        _add_privacy_markers(conn)
    finally:
        conn.close()
    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )

    result = server.call_tool(
        "brain_context_pack",
        {"task": "privacy-context-marker", "limit": 20},
    )
    rendered = result["content"][0]["text"]

    assert "VISIBLE-INTERNAL-CONTEXT" in rendered
    assert "HIDDEN-SENSITIVE-CONTEXT" not in rendered
    assert "HIDDEN-RESTRICTED-CONTEXT" not in rendered
    assert "HIDDEN-UNKNOWN-CONTEXT" not in rendered


def test_mcp_filters_classified_records_from_extended_read_results(tmp_path, monkeypatch):
    conn, database, root = _prepared_brain(tmp_path)
    conn.close()
    server = RtaBrainMcpServer(
        database,
        "demo",
        expected_root=root,
        maximum_privacy_ceiling="internal",
        tool_profile="full",
    )
    monkeypatch.setattr(
        mcp_server,
        "list_multimodal_evidence",
        lambda *_args, **_kwargs: {
            "items": [
                {"privacy_class": "public", "text": "VISIBLE-PUBLIC-RESULT"},
                {"privacy_class": "internal", "text": "VISIBLE-INTERNAL-RESULT"},
                {"privacy_class": "sensitive", "text": "HIDDEN-SENSITIVE-RESULT"},
                {"privacy_class": "future-class", "text": "HIDDEN-UNKNOWN-RESULT"},
            ]
        },
    )

    result = server.call_tool("brain_multimodal_list", {})
    rendered = json.dumps(result)

    assert "VISIBLE-PUBLIC-RESULT" in rendered
    assert "VISIBLE-INTERNAL-RESULT" in rendered
    assert "HIDDEN-SENSITIVE-RESULT" not in rendered
    assert "HIDDEN-UNKNOWN-RESULT" not in rendered


def test_capture_read_ceiling_is_clamped_to_server_maximum():
    assert mcp_server._capture_read_privacy_ceiling(
        {"privacy_ceiling": "internal"}, maximum="public"
    ) == "public"


@pytest.mark.parametrize(
    "field_name",
    (
        "password_value",
        "api_key_material",
        "passwordValue",
        "apiKeyMaterial",
        "access_token_value",
        "secret_access_key_material",
        "refreshTokenData",
    ),
)
def test_compound_sensitive_field_values_are_redacted(field_name):
    redacted, count = redact_sensitive_data(
        {field_name: "opaque-credential-material", "password_policy": "rotate"}
    )

    assert redacted[field_name] == "[REDACTED]"
    assert redacted["password_policy"] == "rotate"
    assert count == 1
