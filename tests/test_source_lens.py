import json
import io
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from rta_brain import db, parsers
from rta_brain.ingest import sha256_text
from rta_brain.source_lens import source_lens


SAMPLE = '\ufeff# example\nclass Store:\n    @staticmethod\n    def read():\n        return "caf\u00e9"\n\nclass Cache:\n    def read(self):\n        return None\n'


@pytest.fixture
def bank(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    path = tmp_path / 'brain.sqlite'
    conn = db.connect(path)
    db.init_project(conn, 'demo', str(root))
    project_id = conn.execute("SELECT id FROM projects WHERE name='demo'").fetchone()[0]

    def seed(relative='sample.py', text=SAMPLE, metadata=None):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.replace('\n', '\r\n').encode('utf-8'))
        source_id = db.upsert_source(
            conn, project_id, 'file', str(target), relative, sha256_text(text),
            metadata if metadata is not None else {
                'relative_path': relative, 'privacy_class': 'internal', 'content_indexed': True,
            },
        )
        conn.commit()
        return source_id

    seed()
    yield root, path, conn, seed
    conn.close()


def test_outline_and_revision_bound_expansion_use_complete_decorated_lines(bank):
    _, path, _, _ = bank
    with db.connect_readonly(path) as conn:
        result = source_lens(conn, project='demo', action='outline', path='sample.py')
        assert result['status'] == 'ok'
        assert result['normalization'] == 'utf8-lf-bom-preserved'
        assert result['source_hash'] == sha256_text(SAMPLE)
        symbol = next(s for s in result['symbols'] if s['qualified_name'] == 'Store.read')
        assert (symbol['parent'], symbol['start_line'], symbol['end_line']) == ('Store', 3, 5)
        expanded = source_lens(conn, project='demo', action='expand', path='sample.py',
                               symbol=symbol['id'], revision=result['revision'])
        assert expanded['text'] == ''.join(SAMPLE.splitlines(keepends=True)[2:5])
        assert expanded['redacted'] is False
        assert expanded['precision'] == 'syntax-lines'


def test_ambiguous_name_does_not_choose_arbitrarily(bank):
    _, _, conn, _ = bank
    outline = source_lens(conn, project='demo', action='outline', path='sample.py')
    result = source_lens(conn, project='demo', action='expand', path='sample.py',
                         symbol='read', revision=outline['revision'])
    assert result['status'] == 'ambiguous'
    assert {s['qualified_name'] for s in result['symbols']} == {'Store.read', 'Cache.read'}
    assert 'text' not in result


def test_stale_source_and_old_revision_fail_closed(bank):
    root, _, conn, seed = bank
    original = source_lens(conn, project='demo', action='outline', path='sample.py')
    (root / 'sample.py').write_text('def changed(): pass\n', encoding='utf-8')
    result = source_lens(conn, project='demo', action='outline', path='sample.py')
    assert result['reason'] == 'stale_source'
    assert 'symbols' not in result
    seed(text='def changed(): pass\n')
    result = source_lens(conn, project='demo', action='expand', path='sample.py',
                         symbol='changed', revision=original['revision'])
    assert result['reason'] == 'revision_mismatch'


@pytest.mark.parametrize('path', ['../outside.py', '/outside.py', 'C:\\outside.py',
                                   'a/../sample.py', 'a\\sample.py', '.git/hooks.py',
                                   'sample.py:stream', 'sample.py\x00', './sample.py'])
def test_unsafe_paths_refused_without_echo(bank, path):
    _, _, conn, _ = bank
    result = source_lens(conn, project='demo', action='outline', path=path)
    assert result == {'schema': 'rta-smriti.source-lens/v1', 'status': 'refused', 'reason': 'unsafe_path'}


@pytest.mark.parametrize('metadata', [{}, {'privacy_class': 'unknown'},
                                      {'privacy_class': 'restricted'},
                                      {'privacy_class': 'internal', 'content_indexed': False}])
def test_unclassified_restricted_or_metadata_only_source_never_read(bank, metadata):
    _, _, conn, seed = bank
    seed('hidden.py', 'def secret(): pass\n', metadata)
    with mock.patch('rta_brain.source_lens.read_text', side_effect=AssertionError('must not read')):
        result = source_lens(conn, project='demo', action='outline', path='hidden.py')
    assert result['status'] == 'refused'


def test_public_ceiling_cannot_read_internal_source(bank):
    _, _, conn, _ = bank
    result = source_lens(conn, project='demo', action='outline', path='sample.py', privacy_ceiling='public')
    assert result['reason'] == 'privacy_denied'


def test_explicit_private_marker_and_invalid_utf8_refused(bank):
    root, _, conn, seed = bank
    seed('private.py', '# <private>not for agents</private>\ndef hidden(): pass\n')
    assert source_lens(conn, project='demo', action='outline', path='private.py')['reason'] == 'private_marker'
    seed('invalid.py', 'def f(): pass\n')
    (root / 'invalid.py').write_bytes(b'def f(): pass\n#\xff')
    assert source_lens(conn, project='demo', action='outline', path='invalid.py')['reason'] == 'unsafe_or_unreadable_source'


def test_find_candidates_are_current_and_bounded(bank):
    root, _, conn, seed = bank
    seed('sample_more.py', 'def other(): pass\n')
    seed('sample_stale.py', 'def old(): pass\n')
    (root / 'sample_stale.py').write_text('def new(): pass\n', encoding='utf-8')
    result = source_lens(conn, project='demo', action='find', query='sample', limit=1)
    assert result['status'] == 'ok'
    assert len(result['items']) == 1
    assert result['truncated'] is True
    assert 'text' not in json.dumps(result)


def test_readonly_under_writer_one_hundred_reads(bank):
    _, path, writer, _ = bank
    reader = db.connect_readonly(path)
    try:
        writer.execute('BEGIN IMMEDIATE')
        before = reader.total_changes
        for _ in range(100):
            assert source_lens(reader, project='demo', action='outline', path='sample.py')['status'] == 'ok'
        assert reader.total_changes == before
        assert reader.execute('PRAGMA query_only').fetchone()[0] == 1
    finally:
        writer.rollback()
        reader.close()


def test_no_writes_even_on_a_write_capable_connection(bank):
    _, _, conn, _ = bank
    before = conn.total_changes
    source_lens(conn, project='demo', action='outline', path='sample.py')
    assert conn.total_changes == before


def test_parser_is_offline_and_reports_syntax_limits():
    with mock.patch('rta_brain.parsers.TreeSitterParser.parse', side_effect=AssertionError('network-capable')):
        result = parsers.parse_source_structure(Path('source.py'), SAMPLE)
    assert result['status'] == 'ok'
    assert result['parser'] == 'python-ast'
    assert parsers.parse_source_structure(Path('source.py'), 'def broken(')['reason'] == 'syntax_error'
    assert parsers.parse_source_structure(Path('source.js'), 'function f() {}')['reason'] == 'unsupported_language'


def test_duplicate_qualified_names_have_distinct_range_ids():
    result = parsers.parse_source_structure(Path('source.py'), 'def f(): pass\ndef f(): pass\n')
    assert [s['qualified_name'] for s in result['symbols']] == ['f', 'f']
    assert len({s['id'] for s in result['symbols']}) == 2


def test_parser_symbol_limit_refuses_partial_precision():
    text = ''.join(f'def f{i}(): pass\n' for i in range(513))
    result = parsers.parse_source_structure(Path('source.py'), text)
    assert result['reason'] == 'structure_limit'
    assert 'symbols' not in result


def test_missing_revision_and_invalid_budget_are_rejected(bank):
    _, _, conn, _ = bank
    with pytest.raises(ValueError, match='revision'):
        source_lens(conn, project='demo', action='expand', path='sample.py', symbol='Store')
    with pytest.raises(ValueError, match='limit'):
        source_lens(conn, project='demo', action='find', query='sample', limit=True)


def test_unknown_project_does_not_initialize_it(bank):
    _, _, conn, _ = bank
    result = source_lens(conn, project='missing', action='outline', path='sample.py')
    assert result['reason'] == 'project_binding_not_ready'
    assert conn.execute("SELECT 1 FROM projects WHERE name='missing'").fetchone() is None


def test_progressive_mcp_reads_use_query_only_connections(bank):
    from rta_brain import mcp_server
    _, path, writer, _ = bank
    db.remember(writer, 'Store policy evidence', project='demo',
                metadata={'privacy_class': 'internal'})
    server = mcp_server.RtaBrainMcpServer(path, default_project='demo')
    original = mcp_server.connect_readonly
    observed = []

    def readonly(db_path):
        conn = original(db_path)
        observed.append(conn.execute('PRAGMA query_only').fetchone()[0])
        return conn

    writer.execute('BEGIN IMMEDIATE')
    try:
        with mock.patch.object(mcp_server, 'connect', side_effect=AssertionError('writer connector')), \
             mock.patch.object(mcp_server, 'connect_readonly', side_effect=readonly):
            index = server.call_tool('brain_retrieve', {'stage': 'index', 'query': 'Store'})['structuredContent']
            assert index['items']
            for stage in ('timeline', 'evidence'):
                server.call_tool('brain_retrieve', {'stage': stage, 'expansion_handle': index['expansion_handle']})
        assert observed == [1, 1, 1]
    finally:
        writer.rollback()


def test_cli_uses_readonly_and_never_requests_a_writer_turn(bank, capsys):
    from rta_brain import cli
    _, path, _, _ = bank
    with mock.patch.object(cli, 'connect', side_effect=AssertionError('writer connector')), \
         mock.patch.object(cli, 'database_writer_lease', side_effect=AssertionError('writer turn')):
        code = cli.main(['source-lens', 'outline', '--db', str(path), '--project', 'demo',
                         '--path', 'sample.py', '--json'])
    assert code == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'ok'


def test_mcp_source_lens_is_extended_readonly_and_respects_ceiling(bank):
    from rta_brain import mcp_server
    _, path, _, _ = bank
    assert len(mcp_server.CORE_READ_TOOLS) == 12
    core = mcp_server.RtaBrainMcpServer(path, default_project='demo', tool_profile='core')
    assert 'brain_source_lens' not in core.enabled_tools
    server = mcp_server.RtaBrainMcpServer(path, default_project='demo', tool_profile='full')
    with mock.patch.object(mcp_server, 'connect', side_effect=AssertionError('writer connector')):
        result = server.call_tool('brain_source_lens', {'action': 'outline', 'path': 'sample.py'})
    assert result['structuredContent']['status'] == 'ok'
    public = mcp_server.RtaBrainMcpServer(path, default_project='demo', tool_profile='full',
                                         maximum_privacy_ceiling='public')
    result = public.call_tool('brain_source_lens', {
        'action': 'outline', 'path': 'sample.py', 'privacy_ceiling': 'sensitive',
    })
    assert result['structuredContent']['reason'] == 'privacy_denied'


def test_unicode_line_separators_inside_strings_do_not_shift_source_ranges(bank):
    _, _, conn, seed = bank
    text = 'value = "a\u2028b\x85c"\n\ndef current():\n    return 42\n'
    seed('unicode.py', text)
    outline = source_lens(conn, project='demo', action='outline', path='unicode.py')
    result = source_lens(conn, project='demo', action='expand', path='unicode.py',
                         symbol='current', revision=outline['revision'])
    assert result['text'] == 'def current():\n    return 42\n'


def test_secret_redaction_is_explicit_and_revision_still_names_original_source(bank):
    _, _, conn, seed = bank
    secret = 'ghp_' + 'a' * 36
    text = f'def configured():\n    return "{secret}"\n'
    seed('credentials.py', text)
    outline = source_lens(conn, project='demo', action='outline', path='credentials.py')
    result = source_lens(conn, project='demo', action='expand', path='credentials.py',
                         symbol='configured', revision=outline['revision'])
    assert secret not in json.dumps(result)
    assert result['redacted'] is True
    assert result['source_hash'] == sha256_text(text)


def test_large_expansion_is_refused_not_silently_truncated(bank):
    _, _, conn, seed = bank
    seed('large.py', 'def large():\n    return "' + 'x' * 33000 + '"\n')
    outline = source_lens(conn, project='demo', action='outline', path='large.py')
    result = source_lens(conn, project='demo', action='expand', path='large.py',
                         symbol='large', revision=outline['revision'])
    assert result['reason'] == 'response_limit'
    assert 'text' not in result


def test_parser_node_and_depth_limits_and_empty_file():
    from rta_brain import source_structure
    assert parsers.parse_source_structure(Path('empty.py'), '')['symbols'] == []
    with mock.patch.object(source_structure, 'MAX_AST_NODES', 5):
        assert parsers.parse_source_structure(Path('f.py'), 'def f(): return [1, 2, 3]')['reason'] == 'structure_limit'
    with mock.patch.object(source_structure, 'MAX_AST_DEPTH', 2):
        assert parsers.parse_source_structure(Path('f.py'), 'def f(): return [1, 2, 3]')['reason'] == 'structure_limit'


def test_hardlinked_source_is_not_served(bank):
    root, _, conn, _ = bank
    os.link(root / 'sample.py', root / 'linked.py')
    assert source_lens(conn, project='demo', action='outline', path='sample.py')['reason'] == 'unsafe_or_unreadable_source'


def test_source_from_other_root_or_changed_identity_is_not_served(bank):
    root, _, conn, _ = bank
    conn.execute("UPDATE sources SET path = ? WHERE title = 'sample.py'", (str(root.parent / 'sample.py'),))
    conn.commit()
    assert source_lens(conn, project='demo', action='outline', path='sample.py')['reason'] == 'source_binding_mismatch'
    conn.execute("UPDATE projects SET checkout_identity='wrong'")
    conn.commit()
    assert source_lens(conn, project='demo', action='outline', path='sample.py')['reason'] == 'project_binding_not_ready'


def test_qualified_lookup_uses_existing_symbol_index(bank):
    _, _, conn, seed = bank
    source_id = seed('backend.py', 'class Policy:\n    def allow(self): return False\n')
    project_id = conn.execute("SELECT id FROM projects WHERE name='demo'").fetchone()[0]
    file_id = db.ensure_entity(conn, project_id, 'file', 'backend.py')
    symbol_id = db.ensure_entity(conn, project_id, 'symbol', 'allow')
    db.add_edge(conn, project_id, file_id, 'contains', symbol_id, source_id=source_id)
    conn.commit()
    result = source_lens(conn, project='demo', action='find', query='Policy.allow')
    assert [item['path'] for item in result['items']] == ['backend.py']


def test_fresh_cli_and_stdio_mcp_success_and_refusal(bank):
    _, path, writer, _ = bank
    writer.execute('BEGIN IMMEDIATE')
    root = Path(__file__).resolve().parents[1]
    command = [sys.executable, '-m', 'rta_brain.cli', 'source-lens', 'outline',
               '--db', str(path), '--project', 'demo', '--path', 'sample.py', '--json']
    cli = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', cwd=root, timeout=30)
    assert cli.returncode == 0, cli.stderr
    outline = json.loads(cli.stdout)
    messages = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
            'protocolVersion': '2025-06-18', 'capabilities': {},
            'clientInfo': {'name': 'source-lens-test', 'version': '1'},
        }},
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
        {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {
            'name': 'brain_source_lens', 'arguments': {'action': 'expand', 'path': 'sample.py',
                                                     'symbol': 'Store.read', 'revision': outline['revision']},
        }},
        {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call', 'params': {
            'name': 'brain_source_lens', 'arguments': {'action': 'outline', 'path': '../private.py'},
        }},
    ]
    mcp = subprocess.run([sys.executable, '-m', 'rta_brain.mcp_server', '--db', str(path),
                          '--project', 'demo', '--tool-profile', 'full'],
                         input='\n'.join(map(json.dumps, messages)) + '\n', capture_output=True,
                         text=True, encoding='utf-8', cwd=root, timeout=30)
    assert mcp.returncode == 0, mcp.stderr
    replies = {x['id']: x for line in mcp.stdout.splitlines() if (x := json.loads(line)).get('id')}
    assert 'brain_source_lens' in {t['name'] for t in replies[2]['result']['tools']}
    assert replies[3]['result']['structuredContent']['text'] == ''.join(SAMPLE.splitlines(keepends=True)[2:5])
    assert replies[4]['result']['structuredContent']['reason'] == 'unsafe_path'
    writer.rollback()


def test_gateway_source_lens_is_query_only_and_requires_project(bank):
    from rta_brain import mcp_server
    _, path, _, _ = bank
    server = mcp_server.RtaBrainMcpServer(brain_dir=path.parent, tool_profile='full')
    with mock.patch.object(mcp_server, 'connect', side_effect=AssertionError('gateway writer connector')):
        result = server.call_tool('brain_source_lens', {'action': 'outline', 'path': 'sample.py', 'project': 'demo'})
    assert result['structuredContent']['status'] == 'ok'
    with pytest.raises(ValueError, match='project is required'):
        server.call_tool('brain_source_lens', {'action': 'outline', 'path': 'sample.py'})


def test_mcp_initialization_never_uses_writer_connector(bank):
    from rta_brain import mcp_server
    _, path, _, _ = bank
    with mock.patch.object(mcp_server, 'connect', side_effect=AssertionError('startup writer connector')), \
         mock.patch.object(mcp_server.sys, 'stdin', io.TextIOWrapper(io.BytesIO())):
        assert mcp_server.serve_stdio(path, 'demo', tool_profile='full') == 0


@pytest.mark.skipif(os.name == 'nt', reason='POSIX directory permissions')
def test_mcp_startup_refuses_nonprivate_directory_without_changing_permissions(bank):
    from rta_brain import mcp_server
    _, path, _, _ = bank
    original_mode = path.parent.stat().st_mode & 0o777
    try:
        path.parent.chmod(0o755)
        with mock.patch.object(mcp_server, 'connect', side_effect=AssertionError('startup writer connector')):
            with pytest.raises(PermissionError, match='directory must be private'):
                mcp_server.RtaBrainMcpServer(path, default_project='demo')
        assert path.parent.stat().st_mode & 0o777 == 0o755
        path.parent.chmod(0o700)
        server = mcp_server.RtaBrainMcpServer(path, default_project='demo', tool_profile='core')
        assert len(server.enabled_tools) == 12
    finally:
        path.parent.chmod(original_mode)


def test_pretty_json_response_obeys_character_budget(bank):
    _, _, conn, seed = bank
    seed('many.py', ''.join(f'def function_{i}(): pass\n' for i in range(40)))
    result = source_lens(conn, project='demo', action='outline', path='many.py', max_chars=2000)
    assert result['status'] == 'ok'
    assert len(json.dumps(result, indent=2, sort_keys=True)) <= 2000
    assert result['truncated'] is True


def test_oversized_file_is_refused_before_parsing(bank):
    _, _, conn, seed = bank
    seed('oversized.py', '#' + 'x' * 512000)
    with mock.patch('rta_brain.source_lens.parse_source_structure', side_effect=AssertionError('must not parse')):
        result = source_lens(conn, project='demo', action='outline', path='oversized.py')
    assert result['reason'] == 'unsafe_or_unreadable_source'


def test_index_work_budget_interrupts_and_clears_its_handler(bank):
    from rta_brain.source_lens import _query
    _, _, conn, _ = bank
    with pytest.raises(sqlite3.OperationalError, match='interrupt'):
        _query(conn, '''WITH RECURSIVE sequence(n) AS (
            VALUES(0) UNION ALL SELECT n + 1 FROM sequence WHERE n < 10000000
        ) SELECT sum(n) FROM sequence''', (), 1)
    assert conn.execute('SELECT 1').fetchone()[0] == 1


def test_find_does_not_disclose_excluded_candidate_counts(bank):
    _, _, conn, seed = bank
    seed('hidden.py', 'def hidden(): pass\n')
    hidden = source_lens(conn, project='demo', action='find', query='hidden', privacy_ceiling='public')
    missing = source_lens(conn, project='demo', action='find', query='absent', privacy_ceiling='public')
    assert hidden == missing


def test_query_bound_includes_whitespace(bank):
    _, _, conn, _ = bank
    with pytest.raises(ValueError, match='query'):
        source_lens(conn, project='demo', action='find', query=' ' * 200 + 'sample')
