"""Query-only, bounded impact evidence. No source reads or model calls."""

import hashlib
import json
from time import monotonic

from .db import SCHEMA_VERSION, canonical
from .passport import _literal, _relative_title
from .privacy import redact_sensitive_data


def limit_impact_connection(conn):
    """Set a five-second SQL budget on a dedicated, caller-owned connection."""
    deadline = monotonic() + 5.0
    conn.set_progress_handler(lambda: int(monotonic() >= deadline), 1000)


def _encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2)


def _digest(value):
    return hashlib.sha256(_encoded(value).encode("utf-8")).hexdigest()


# Unknown or malformed classifications never become portable evidence.
_VISIBLE = """CASE WHEN json_valid(s.metadata_json) THEN
    json_type(s.metadata_json) = 'object' AND
    lower(json_extract(s.metadata_json, '$.privacy_class')) IN ('public','internal')
    ELSE 0 END"""
_JOINS = """FROM edges e
    JOIN entities f ON f.id=e.from_entity_id AND f.project_id=e.project_id
    JOIN entities t ON t.id=e.to_entity_id AND t.project_id=e.project_id
    JOIN sources s ON s.id=e.source_id AND s.project_id=e.project_id"""
_ELIGIBLE = f"e.memory_id IS NULL AND s.kind='file' AND {_VISIBLE}"
_RELATIONS = "e.relation IN ('calls','imports','contains','tests')"


def impact_report(conn, *, project, target, depth=2, limit=60, max_chars=8000):
    if not isinstance(project, str) or not project or len(project) > 200:
        raise ValueError("invalid project")
    if not isinstance(target, str) or not target.strip() or len(target) > 500:
        raise ValueError("target must contain 1 to 500 characters")
    for name, value, low, high in (("depth", depth, 1, 4), ("limit", limit, 1, 100),
                                   ("max_chars", max_chars, 0, 16000)):
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{name} must be between {low} and {high}")
    if conn.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
        raise ValueError("impact requires the current schema; use backup-first migration")
    conn.execute("SAVEPOINT impact_read")
    try:
        row = conn.execute("SELECT id FROM projects WHERE name=?", (project,)).fetchone()
        if row is None:
            raise ValueError("unknown project")
        pid = row[0]
        # A seed must participate in an eligible relationship. Hidden-only names
        # and unknown names therefore have the same public response shape.
        seeds = conn.execute(f"""SELECT n.id,n.type,n.name FROM entities n
            WHERE n.project_id=? AND n.canonical_key=? AND EXISTS (
                SELECT 1 {_JOINS} WHERE e.project_id=n.project_id
                AND (e.from_entity_id=n.id OR e.to_entity_id=n.id)
                AND {_ELIGIBLE} AND {_RELATIONS}) ORDER BY n.id LIMIT ?""",
            (pid, canonical(target.strip()), limit + 1)).fetchall()
        bounded = len(seeds) > limit
        nodes = {r["id"]: {"id": r["id"], "type": r["type"], "name": r["name"],
                             "distance": 0, "path_edge_ids": []} for r in seeds[:limit]}
        frontier = list(nodes)
        edges = {}
        for _ in range(depth):
            next_frontier = []
            for node_id in frontier:
                # Follow callers/importers and containing files towards dependents.
                rows = conn.execute(f"""SELECT e.id,e.from_entity_id AS from_id,
                    e.to_entity_id AS to_id,e.relation,e.confidence,s.id AS source_id,
                    f.name AS from_name,f.type AS from_type,t.name AS to_name
                    {_JOINS} WHERE e.project_id=? AND e.to_entity_id=?
                    AND {_ELIGIBLE} AND {_RELATIONS}
                    ORDER BY e.confidence DESC,e.id LIMIT ?""", (pid, node_id, limit + 1)).fetchall()
                bounded |= len(rows) > limit
                for r in rows[:limit]:
                    if r["from_id"] not in nodes and len(nodes) >= limit:
                        bounded = True
                        continue
                    if len(edges) >= limit * 2:
                        bounded = True
                        break
                    edges[r["id"]] = {key: r[key] for key in
                        ("id", "from_id", "to_id", "relation", "confidence", "source_id", "from_name", "to_name")}
                    if r["from_id"] not in nodes:
                        nodes[r["from_id"]] = {"id": r["from_id"], "name": r["from_name"],
                            "type": r["from_type"], "distance": nodes[node_id]["distance"] + 1,
                            "path_edge_ids": nodes[node_id]["path_edge_ids"] + [r["id"]]}
                        next_frontier.append(r["from_id"])
            frontier = next_frontier
            if not frontier:
                break
        evidence = []
        remaining = max_chars
        for sid in sorted({edge["source_id"] for edge in edges.values()}):
            source = conn.execute("SELECT title,hash,updated_at FROM sources WHERE id=? AND project_id=?", (sid, pid)).fetchone()
            chunks = conn.execute("SELECT substr(text,1,?) AS text,hash,length(text) AS length FROM chunks WHERE source_id=? ORDER BY ordinal LIMIT 3",
                                  (min(remaining, 2000), sid)).fetchall()
            text = "\n".join(r["text"] for r in chunks)[:min(remaining, 2000)]
            remaining -= len(text)
            evidence.append({"source_id": sid, "path": _relative_title(source["title"]),
                "source_hash": source["hash"], "indexed_at": source["updated_at"],
                "excerpt": text, "excerpt_is_partial": True,
                "chunk_hashes": [r["hash"] for r in chunks],
                "edge_ids": [e["id"] for e in edges.values() if e["source_id"] == sid]})
        result = {"status": "ok" if nodes else "no_match", "project": project,
            "target": target.strip(), "depth": depth, "limit": limit, "max_chars": max_chars,
            "nodes": list(nodes.values()), "edges": list(edges.values()), "evidence": evidence,
            "coverage": {"complete": False, "working_tree_verified": False,
                "bounded": bounded, "direction": "dependents", "scope": "visible_indexed_file_relationships",
                "limitations": ["Indexed relationships are impact hints, not proof of breakage.",
                    "Exact entity names only; no match does not prove no impact.",
                    "Depth, node and excerpt limits apply. Dynamic calls and unindexed changes may be missing.",
                    "Decision memories are not included in this file-relationship trace."]},
            "access": {"mode": "read_only", "writes_performed": False}}
        result, _ = redact_sensitive_data(result)
        result["revision"] = _digest(result)
        return result
    finally:
        conn.execute("RELEASE impact_read")


def impact_preview(conn, *, project, target, revision, source_ids, depth=2, limit=60, max_chars=8000):
    if not isinstance(source_ids, list) or not source_ids or len(source_ids) > 100 or any(type(i) is not int for i in source_ids) or len(set(source_ids)) != len(source_ids):
        raise ValueError("select unique evidence source IDs")
    report = impact_report(conn, project=project, target=target, depth=depth, limit=limit, max_chars=max_chars)
    if revision != report["revision"]:
        raise ValueError("evidence changed; refresh and review again")
    available = {item["source_id"]: item for item in report["evidence"]}
    if any(i not in available for i in source_ids):
        raise ValueError("evidence is unavailable in this trace")
    selected_edges = [e for e in report["edges"] if e["source_id"] in source_ids]
    document = {"format": "rta-impact-handoff/v1", "target": report["target"],
        "boundary": "Reviewed selection of indexed evidence, not permission to act or proof of current correctness.",
        "relationships": selected_edges, "evidence": [available[i] for i in source_ids],
        "coverage": report["coverage"], "revision": report["revision"]}
    text = _encoded(document)
    lines = ["# Change impact handoff", "", document["boundary"], "", _literal(document["target"])]
    for edge in selected_edges:
        lines.extend(["", _literal(f"{edge['from_name']} --{edge['relation']}--> {edge['to_name']}")])
    for item in document["evidence"]:
        lines.extend(["", _literal(item["path"]), _literal(item["source_hash"]), _literal(item["excerpt"])])
    lines.extend(["", *document["coverage"]["limitations"], "", "Review before sharing; pattern-based redaction is not exhaustive."])
    return {"status": "ok", "document": document, "json": text, "markdown": "\n".join(lines),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "revision": report["revision"]}
