"""Offline syntax ranges. No imports, evaluation, plugins, or parser downloads."""

from __future__ import annotations

import ast
from pathlib import Path

MAX_STRUCTURE_BYTES = 512_000
MAX_AST_NODES = 20_000
MAX_AST_DEPTH = 100
MAX_SYMBOLS = 512


def parse_source_structure(path: Path, text: str) -> dict:
    if path.suffix.lower() != '.py':
        return {'status': 'unavailable', 'reason': 'unsupported_language'}
    if len(text.encode('utf-8')) > MAX_STRUCTURE_BYTES:
        return {'status': 'unavailable', 'reason': 'structure_limit'}
    try:
        # The indexed hash retains the BOM; removing it here does not move lines.
        tree = ast.parse(text.removeprefix('\ufeff'), filename='<source>')
    except (SyntaxError, ValueError):
        return {'status': 'unavailable', 'reason': 'syntax_error'}
    except (RecursionError, MemoryError):
        return {'status': 'unavailable', 'reason': 'structure_limit'}
    symbols = []
    stack = [(tree, '', 0)]
    visited = 0
    while stack:
        node, parent, depth = stack.pop()
        visited += 1
        if visited > MAX_AST_NODES or depth > MAX_AST_DEPTH:
            return {'status': 'unavailable', 'reason': 'structure_limit'}
        child_parent = parent
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            name = node.name
            qualified = f'{parent}.{name}' if parent else name
            if len(qualified) > 512 or len(symbols) >= MAX_SYMBOLS:
                return {'status': 'unavailable', 'reason': 'structure_limit'}
            start = min([node.lineno, *[d.lineno for d in node.decorator_list]])
            end = node.end_lineno
            if end is None or end < start:
                return {'status': 'unavailable', 'reason': 'range_unavailable'}
            symbols.append({
                'id': f'{qualified}@{start}:{end}', 'name': name,
                'qualified_name': qualified, 'parent': parent or None,
                'kind': 'class' if isinstance(node, ast.ClassDef) else (
                    'async_function' if isinstance(node, ast.AsyncFunctionDef) else 'function'
                ),
                'start_line': start, 'end_line': end,
            })
            child_parent = qualified
        stack.extend((child, child_parent, depth + 1) for child in reversed(list(ast.iter_child_nodes(node))))
    return {'status': 'ok', 'parser': 'python-ast', 'precision': 'syntax-lines', 'symbols': symbols}
