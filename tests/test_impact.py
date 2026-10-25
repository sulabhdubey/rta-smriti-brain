import json
from contextlib import closing

import pytest

from rta_brain import db


@pytest.fixture
def brain(tmp_path):
    path = tmp_path / "brain.sqlite"
    with closing(db.connect(path)) as conn:
        db.init_project(conn, "demo", str(tmp_path))
        pid = conn.execute("SELECT id FROM projects WHERE name='demo'").fetchone()[0]
        nodes = {name: db.ensure_entity(conn, pid, "function", name)
                 for name in ("helper", "caller", "test_caller", "secret", "unrelated")}
        for origin, target, privacy in (("caller", "helper", "public"),
                                        ("test_caller", "caller", "public"),
                                        ("secret", "helper", "restricted")):
            sid = conn.execute("INSERT INTO sources(project_id,kind,path,title,hash,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (pid, "file", origin + ".py", origin + ".py", "hash-" + origin,
                 json.dumps({"privacy_class": privacy}), "2026-10-18", "2026-10-18")).lastrowid
            conn.execute("INSERT INTO chunks(source_id,ordinal,text,hash) VALUES(?,?,?,?)",
                         (sid, 0, origin + " calls " + target, "chunk-" + origin))
            db.add_edge(conn, pid, nodes[origin], "calls", nodes[target], source_id=sid, confidence=0.8)
        conn.commit()
    return path


def report(path, **kwargs):
    from rta_brain.impact import impact_report
    with closing(db.connect_readonly(path)) as conn:
        return impact_report(conn, project="demo", target="helper", **kwargs)


def test_explains_paths_and_bounds_context(brain):
    value = report(brain)
    names = {node["name"]: node for node in value["nodes"]}
    assert set(names) == {"helper", "caller", "test_caller"}
    assert len(names["test_caller"]["path_edge_ids"]) == 2
    assert names["test_caller"]["distance"] == 2
    assert value["evidence"][0]["source_hash"]
    assert value["access"]["writes_performed"] is False
    assert value["coverage"]["working_tree_verified"] is False
    assert "secret" not in json.dumps(value)
    limited = report(brain, max_chars=40)
    assert sum(len(item["excerpt"]) for item in limited["evidence"]) <= 40


def test_no_match_is_not_no_impact(brain):
    from rta_brain.impact import impact_report
    with closing(db.connect_readonly(brain)) as conn:
        value = impact_report(conn, project="demo", target="missing")
        assert value["status"] == "no_match"
        assert value["coverage"]["complete"] is False
        with pytest.raises(ValueError, match="unknown project"):
            impact_report(conn, project="foreign", target="helper")


def test_readers_under_writer_and_frozen_preview(brain):
    from rta_brain.impact import impact_preview
    before = report(brain)
    with closing(db.connect(brain)) as writer:
        writer.execute("BEGIN IMMEDIATE")
        for _ in range(100):
            assert report(brain)["revision"] == before["revision"]
        writer.rollback()
        writer.execute("UPDATE chunks SET text='new evidence',hash='new-hash'")
        writer.commit()
    with closing(db.connect_readonly(brain)) as conn:
        with pytest.raises(ValueError, match="changed"):
            impact_preview(conn, project="demo", target="helper", revision=before["revision"],
                           source_ids=[before["evidence"][0]["source_id"]])


def test_preview_is_selected_and_rejects_foreign_evidence(brain):
    from rta_brain.impact import impact_preview
    value = report(brain)
    sid = value["evidence"][0]["source_id"]
    with closing(db.connect_readonly(brain)) as conn:
        preview = impact_preview(conn, project="demo", target="helper", revision=value["revision"], source_ids=[sid])
        assert len(preview["document"]["evidence"]) == 1
        assert preview["sha256"]
        with pytest.raises(ValueError):
            impact_preview(conn, project="demo", target="helper", revision=value["revision"], source_ids=[999999])


def test_cli_uses_readonly_connector(brain, monkeypatch, capsys):
    from rta_brain import cli
    monkeypatch.setattr(cli, "connect", lambda *a, **k: pytest.fail("write connector"))
    monkeypatch.setattr(cli, "database_writer_lease", lambda *a, **k: pytest.fail("writer turn"))
    assert cli.main(["impact", "helper", "--db", str(brain), "--project", "demo", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["nodes"]


def test_mcp_contract_is_read_only_and_project_bound(brain):
    from rta_brain.mcp_server import RtaBrainMcpServer
    server = RtaBrainMcpServer(brain, "demo", tool_profile="full")
    value = server.call_tool("brain_impact", {"target": "helper"})["structuredContent"]
    assert value["access"]["writes_performed"] is False
    assert value["nodes"]
    public = RtaBrainMcpServer(brain, "demo", tool_profile="full", maximum_privacy_ceiling="public")
    with pytest.raises(PermissionError):
        public.call_tool("brain_impact", {"target": "helper"})


def test_cycles_limits_and_malformed_classification(brain):
    with closing(db.connect(brain)) as conn:
        pid = conn.execute("SELECT id FROM projects WHERE name='demo'").fetchone()[0]
        nodes = {r['name']: r['id'] for r in conn.execute("SELECT * FROM entities")}
        sid = conn.execute("SELECT id FROM sources WHERE title='caller.py'").fetchone()[0]
        db.add_edge(conn, pid, nodes['helper'], 'calls', nodes['test_caller'], source_id=sid)
        conn.execute("UPDATE sources SET metadata_json='[]' WHERE title='secret.py'")
        conn.commit()
    value = report(brain, depth=4)
    assert len(value['nodes']) == 3
    assert 'secret' not in json.dumps(value)
    assert len(report(brain, limit=1)['nodes']) == 1
    assert report(brain, limit=1)['coverage']['bounded']
    for options in ({'limit': True}, {'depth': 5}, {'max_chars': -1}):
        with pytest.raises(ValueError):
            report(brain, **options)


def test_real_parser_provides_evidence(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    (root / 'service.py').write_text('def helper():\n    return 1\n\ndef caller():\n    return helper()\n', encoding='utf-8')
    path = tmp_path / 'parsed.sqlite'
    with closing(db.connect(path)) as conn:
        db.init_project(conn, 'demo', str(root))
        db.ingest_repo(conn, root, project='demo')
    value = report(path)
    assert value['nodes']
    assert any(item['path'] == 'service.py' for item in value['evidence'])


def test_query_connection_budget_interrupts_work(brain, monkeypatch):
    import sqlite3
    from rta_brain import impact
    with closing(db.connect_readonly(brain)) as conn:
        clock = iter([0.0, 6.0])
        monkeypatch.setattr(impact, 'monotonic', lambda: next(clock, 6.0))
        impact.limit_impact_connection(conn)
        with pytest.raises(sqlite3.OperationalError, match='interrupted'):
            conn.execute('WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100000) SELECT sum(x) FROM n').fetchone()


def test_fresh_stdio_mcp_reads_impact(brain):
    import subprocess
    import sys
    messages = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'impact-qa', 'version': '1'}}},
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
        {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'brain_impact', 'arguments': {'target': 'helper'}}},
    ]
    run = subprocess.run([sys.executable, '-m', 'rta_brain.mcp_server', '--db', str(brain), '--project', 'demo', '--tool-profile', 'full'],
        input='\n'.join(map(json.dumps, messages)) + '\n', text=True, encoding='utf-8', capture_output=True, timeout=30)
    assert run.returncode == 0, run.stderr
    replies = {item['id']: item for line in run.stdout.splitlines() if (item := json.loads(line)).get('id')}
    tools = {tool['name'] for tool in replies[2]['result']['tools']}
    assert {'brain_impact', 'brain_source_lens'} <= tools
    assert replies[3]['result']['structuredContent']['access']['writes_performed'] is False
    assert replies[3]['result']['structuredContent']['nodes']
