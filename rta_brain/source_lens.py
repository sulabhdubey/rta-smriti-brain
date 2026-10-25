"""Bounded, revision-bound access to current indexed source, without writes."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path, PurePosixPath

from .db import project_binding_status
from .ingest import IGNORED_DIRS, IGNORED_PREFIXES, read_text, sha256_text
from .parsers import parse_source_structure
from .privacy import redact_sensitive_data

SCHEMA = 'rta-smriti.source-lens/v1'
MAX_FILE_BYTES = 512_000
MAX_CANDIDATES = 32
MAX_FIND_BYTES = 2_048_000
MAX_RESPONSE_CHARS = 32_000
PRIVACY_RANKS = {'public': 0, 'internal': 1, 'sensitive': 2}
PRIVATE_MARKER = re.compile(r'<\s*/?\s*private\b', re.IGNORECASE)


def _refuse(reason: str) -> dict:
    return {'schema': SCHEMA, 'status': 'refused', 'reason': reason}


def _safe_path(value: object) -> bool:
    if not isinstance(value, str) or not 0 < len(value) <= 1024:
        return False
    if any(ord(c) < 32 or c in '\\:' for c in value) or value.startswith('/'):
        return False
    parts = value.split('/')
    if any(p in {'', '.', '..'} or p.endswith((' ', '.')) for p in parts):
        return False
    return not any(
        p.startswith('.') or p.casefold() in IGNORED_DIRS
        or p.casefold().startswith(IGNORED_PREFIXES)
        for p in parts
    )


def _query(conn, sql: str, args: tuple, limit: int) -> list:
    # Bound index work as well as rows. These routes own their query connection.
    steps = 0

    def stop():
        nonlocal steps
        steps += 1
        return steps > 2_000

    conn.set_progress_handler(stop, 1_000)
    try:
        return conn.execute(sql, args).fetchmany(limit)
    finally:
        conn.set_progress_handler(None, 0)


def _load(row, root: Path, ceiling: str, binding: dict, *, byte_limit: int) -> dict:
    try:
        metadata = json.loads(row['metadata_json'])
    except (ValueError, TypeError):
        return _refuse('privacy_denied')
    if not isinstance(metadata, dict):
        return _refuse('privacy_denied')
    privacy = metadata.get('privacy_class')
    if privacy not in PRIVACY_RANKS or PRIVACY_RANKS[privacy] > PRIVACY_RANKS[ceiling]:
        return _refuse('privacy_denied')
    if metadata.get('content_indexed') is not True:
        return _refuse('metadata_only_source')
    relative = metadata.get('relative_path')
    if not _safe_path(relative):
        return _refuse('unsafe_path')
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    if row['title'] != relative or Path(row['path']) != candidate:
        return _refuse('source_binding_mismatch')
    text = read_text(candidate, root=root, max_bytes=byte_limit, strict_utf8=True)
    if text is None:
        return _refuse('unsafe_or_unreadable_source')
    if PRIVATE_MARKER.search(text):
        return _refuse('private_marker')
    source_hash = sha256_text(text)
    if source_hash != row['hash']:
        return _refuse('stale_source')
    structure = parse_source_structure(candidate, text)
    if structure['status'] != 'ok':
        return _refuse(structure['reason'])
    revision = hashlib.sha256(json.dumps({
        'schema': SCHEMA, 'binding': binding, 'id': row['id'], 'hash': source_hash,
        'metadata': metadata, 'path': relative, 'parser': structure['parser'],
    }, sort_keys=True, ensure_ascii=True).encode('utf-8')).hexdigest()
    return {
        'status': 'ok', 'path': relative, 'revision': revision, 'source_hash': source_hash,
        'normalization': 'utf8-lf-bom-preserved', 'privacy_class': privacy,
        'parser': structure['parser'], 'precision': structure['precision'],
        'symbols': structure['symbols'], '_text': text,
    }


def _finish(payload: dict, max_chars: int) -> dict:
    payload = {'schema': SCHEMA, **payload}
    payload, redactions = redact_sensitive_data(payload, max_chars=1_000_000)
    payload['redacted'] = bool(redactions)
    def fits() -> bool:
        return len(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True)) <= max_chars

    if fits():
        return payload
    key = 'items' if 'items' in payload else 'symbols'
    if 'text' in payload or not payload.get(key):
        return _refuse('response_limit')
    items = payload[key]
    payload[key] = []
    payload['truncated'] = True
    if not fits():
        return _refuse('response_limit')
    # Keep a prefix without repeatedly serializing a nearly-full large outline.
    lower, upper = 0, len(items)
    while lower < upper:
        middle = (lower + upper + 1) // 2
        payload[key] = items[:middle]
        if fits():
            lower = middle
        else:
            upper = middle - 1
    payload[key] = items[:lower]
    return payload


def source_lens(
    conn, *, project: str, action: str, path: str | None = None,
    query: str | None = None, symbol: str | None = None, revision: str | None = None,
    limit: int = 8, max_chars: int = MAX_RESPONSE_CHARS, privacy_ceiling: str = 'internal',
) -> dict:
    """Find candidates, outline a file, or expand one revision-bound syntax range.

    Source hashes describe normalized text observed during this call, not an
    atomic snapshot of the whole live repository or a claim of runtime truth.
    """
    if action not in {'find', 'outline', 'expand'}:
        raise ValueError('source-lens action must be find, outline, or expand')
    if type(limit) is not int or not 1 <= limit <= 20:
        raise ValueError('source-lens limit must be an integer from 1 to 20')
    if type(max_chars) is not int or not 512 <= max_chars <= MAX_RESPONSE_CHARS:
        raise ValueError('source-lens max_chars must be an integer from 512 to 32000')
    if not isinstance(project, str) or not 0 < len(project) <= 256:
        raise ValueError('source-lens requires a bounded project name')
    if privacy_ceiling not in PRIVACY_RANKS:
        raise ValueError('source-lens privacy ceiling must be public, internal, or sensitive')
    if action == 'find':
        if not isinstance(query, str) or not 0 < len(query) <= 160 or not query.strip():
            raise ValueError('source-lens find requires a query of 1 to 160 characters')
        if any(value is not None for value in (path, symbol, revision)):
            raise ValueError('source-lens find does not accept path, symbol, or revision')
    else:
        if query is not None:
            raise ValueError('source-lens outline/expand does not accept query')
        if not _safe_path(path):
            return _refuse('unsafe_path')
        if action == 'expand':
            if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{64}', revision):
                raise ValueError('source-lens expand requires the outline revision')
            if not isinstance(symbol, str) or not 0 < len(symbol) <= 550:
                raise ValueError('source-lens expand requires a bounded symbol selector')
        elif symbol is not None or revision is not None:
            raise ValueError('source-lens outline does not accept symbol or revision')
    try:
        binding = project_binding_status(conn, project, initialize_schema=False)
        if not binding['ready']:
            return _refuse('project_binding_not_ready')
        project_row = conn.execute('SELECT id, root_path FROM projects WHERE name = ?', (project,)).fetchone()
        root = Path(project_row['root_path'])
        base_sql = '''SELECT id, path, title, hash, metadata_json FROM sources
            WHERE project_id = ? AND kind = 'file'
            AND length(metadata_json) <= 8192 AND length(path) <= 4096 AND length(title) <= 1024
            AND typeof(hash) = 'text' AND length(hash) = 64'''
        if action == 'find':
            needle = query.strip().casefold()
            classes = tuple(name for name, rank in PRIVACY_RANKS.items() if rank <= PRIVACY_RANKS[privacy_ceiling])
            privacy_sql = ''' AND CASE WHEN json_valid(metadata_json)
                THEN json_extract(metadata_json, '$.privacy_class') END IN (''' + ','.join('?' for _ in classes) + ')'
            rows = _query(conn, base_sql + privacy_sql + ''' AND (instr(lower(title), ?) > 0 OR id IN (
                SELECT e.source_id FROM edges e JOIN entities n ON n.id = e.to_entity_id
                WHERE e.project_id = ? AND n.project_id = ? AND e.relation = 'contains'
                AND n.type = 'symbol' AND instr(lower(n.name), ?) > 0))
                ORDER BY title, id LIMIT ?''',
                (project_row['id'], *classes, needle, project_row['id'], project_row['id'],
                 needle.rsplit('.', 1)[-1], MAX_CANDIDATES + 1), MAX_CANDIDATES + 1)
            items = []
            budget = MAX_FIND_BYTES
            for row in rows[:MAX_CANDIDATES]:
                if budget <= 0:
                    break
                read_limit = min(MAX_FILE_BYTES, budget)
                loaded = _load(row, root, privacy_ceiling, binding, byte_limit=read_limit)
                if loaded['status'] != 'ok':
                    budget -= read_limit
                    continue
                # LF normalization can remove one byte per line; reserve that too.
                budget -= len(loaded['_text'].encode('utf-8')) + loaded['_text'].count('\n')
                matches = [s for s in loaded['symbols'] if needle in s['qualified_name'].casefold()]
                if needle not in loaded['path'].casefold() and not matches:
                    continue
                items.append({k: loaded[k] for k in ('path', 'revision', 'source_hash', 'privacy_class', 'parser')})
                if len(items) > limit:
                    break
            return _finish({'status': 'ok', 'items': items[:limit],
                            'truncated': len(items) > limit or len(rows) > MAX_CANDIDATES or budget <= 0,
                            'candidate_basis': 'indexed-path-or-symbol'}, max_chars)
        rows = _query(conn, base_sql + ' AND title = ? LIMIT 2', (project_row['id'], path), 2)
        if len(rows) != 1:
            return _refuse('source_not_uniquely_indexed')
        loaded = _load(rows[0], root, privacy_ceiling, binding, byte_limit=MAX_FILE_BYTES)
        if loaded['status'] != 'ok':
            return loaded
        text = loaded.pop('_text')
        if action == 'outline':
            return _finish({**loaded, 'truncated': False}, max_chars)
        if revision != loaded['revision']:
            return _refuse('revision_mismatch')
        matches = [s for s in loaded['symbols'] if symbol in (s['id'], s['qualified_name'], s['name'])]
        if not matches:
            return _refuse('symbol_not_found')
        if len(matches) != 1:
            return _finish({**loaded, 'status': 'ambiguous', 'symbols': matches, 'truncated': False}, max_chars)
        selected = matches[0]
        loaded.pop('symbols')
        # AST lines count LF only; splitlines also splits Unicode inside literals.
        lines = text.split('\n')
        excerpt = '\n'.join(lines[selected['start_line'] - 1:selected['end_line']])
        if selected['end_line'] < len(lines):
            excerpt += '\n'
        return _finish({**loaded, 'symbol': selected,
                        'text': excerpt}, max_chars)
    except sqlite3.OperationalError as exc:
        if 'interrupt' in str(exc).lower():
            return _refuse('index_query_limit')
        raise
    except (OSError, ValueError, TypeError, RecursionError):
        return _refuse('source_verification_failed')
