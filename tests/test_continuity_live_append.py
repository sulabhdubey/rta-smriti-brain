"""Discovery hints must tolerate growth without authorizing foreign content."""
import json
import os
from unittest.mock import patch

import pytest

from rta_brain import continuity_daemon as daemon
from rta_brain import db
from rta_brain.continuity import ingest_codex_session


def record(kind, **payload):
    return (json.dumps({'type': kind, 'payload': payload}) + '\n').encode()


@pytest.mark.parametrize('foreign_append', [False, True])
@pytest.mark.parametrize('rebound', [False, True])
def test_growth_during_discovery_is_uncached_hint_and_ingestion_rechecks(tmp_path, foreign_append, rebound):
    root, foreign = tmp_path / 'repo', tmp_path / 'foreign'
    root.mkdir()
    foreign.mkdir()
    session = tmp_path / 'session.jsonl'
    session.write_bytes(record('session_meta', id='live', cwd=str(foreign if rebound else root)) +
                        record('turn_context', cwd=str(root)) +
                        record('response_item', type='message', role='user', content='local evidence'))
    original = daemon._session_binding

    def grow_after_scan(*args, **kwargs):
        result = original(*args, **kwargs)
        with session.open('ab') as stream:
            if foreign_append:
                stream.write(record('turn_context', cwd=str(foreign)))
            stream.write(record('response_item', type='message', role='user',
                                content='foreign secret' if foreign_append else 'new local evidence'))
        return result

    cache = daemon.SessionBindingCache()
    with patch.object(daemon, '_session_binding', side_effect=grow_after_scan):
        hint = cache.lookup(session, root)
    assert hint is not None
    assert cache.entries == {}, 'a growing file must never enter the stable cache'
    conn = db.connect(tmp_path / 'brain.sqlite')
    try:
        db.init_project(conn, 'demo', str(root))
        result = ingest_codex_session(conn, session, 'demo', session_id=hint['session_id'],
                                      expected_project_root=root, expected_sessions_root=tmp_path,
                                      binding_start_offset=hint['binding_offset'])
        contents = '\n'.join(row[0] for row in conn.execute('SELECT payload_json FROM session_events'))
        assert 'local evidence' in contents
        assert 'foreign secret' not in contents
        assert result['inserted'] == (1 if foreign_append else 2)
    finally:
        conn.close()
    assert (cache.lookup(session, root) is None) == foreign_append


@pytest.mark.parametrize('mutation', ['replace', 'truncate', 'same-size', 'hardlink'])
def test_non_growth_mutation_cannot_reuse_binding(tmp_path, mutation):
    session = tmp_path / 'session.jsonl'
    session.write_bytes(record('session_meta', id='live', cwd=str(tmp_path)) +
                        record('turn_context', cwd=str(tmp_path)))
    original = daemon._session_binding

    def mutate(*args, **kwargs):
        result = original(*args, **kwargs)
        if mutation == 'replace':
            replacement = tmp_path / 'replacement.jsonl'
            replacement.write_bytes(session.read_bytes() + b'{}\n')
            os.replace(replacement, session)
        elif mutation == 'truncate':
            session.write_bytes(b'{}\n')
        elif mutation == 'same-size':
            contents = session.read_bytes()
            session.write_bytes(b' ' * (len(contents) - 1) + b'\n')
            changed = session.stat()
            os.utime(session, ns=(changed.st_atime_ns, changed.st_mtime_ns + 1_000_000))
        else:
            os.link(session, tmp_path / 'linked.jsonl')
        return result

    cache = daemon.SessionBindingCache()
    with patch.object(daemon, '_session_binding', side_effect=mutate):
        assert cache.lookup(session, tmp_path) is None
    assert cache.entries == {}
