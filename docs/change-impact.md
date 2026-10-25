# Explainable change impact

The published `v1.1.0-alpha.10` artifacts do not include this explorer. These
instructions apply to source builds containing this change; a green PR check
does not mean a new release has been published.

In Project Intelligence, choose Impact. Enter an exact indexed symbol or relative file name and select Trace relationships. The same explorer is available under Project Passport > Changes > Explore change impact.

Graph and list views share a selection. Inspect a node to see the indexed relationship path. Source evidence includes a relative path, indexed hash and a bounded excerpt. Select evidence, preview the handoff, review it for sensitive information and download Markdown. The server rechecks the evidence revision when previewing and downloading; changed evidence requires a fresh review.

CLI:

```sh
rta-brain impact helper --project demo --db /path/to/brain.sqlite --json
```

The full MCP profile includes `brain_impact` with `target`, optional `project`, `depth` (1-4), `limit` (1-100), and `max_chars` (0-16000). It requires an internal-or-higher server ceiling and returns only eligible public/internal file relationships. It does not enable itself in an already-running host: refresh tool discovery or restart the host as appropriate. The core and Passport-only profiles are unchanged.

The endpoint is authenticated `POST /api/impact`, using the console's existing project/database authorization. Actions are `inspect` and `preview`; preview requires the returned `revision` and selected `source_ids` with the same query parameters.

## Limits

- This reads the existing index; it neither scans current files nor verifies working-tree freshness.
- Connections are query-only. No graph service, model, telemetry or background worker is added.
- Traversal follows incoming calls, imports, containment and test relationships. These are impact hints, not proof of breakage or exhaustive test coverage.
- Unknown or malformed source classifications and sensitive/restricted sources are excluded before traversal. This is a conservative public/internal view, not a configurable enterprise authorization model.
- Exact names are required. No matching eligible relationship does not prove that the target is absent or safe to change.
- Results are limited by depth, nodes, edges and excerpt size. Excerpts are partial, and the view does not include every decision or historical version.
- The impact handoff is a separate selected-evidence attachment. Existing Passport decision/checkpoint exports remain available; they are not automatically merged into this attachment.
- Pattern-based redaction is not exhaustive. Review visible names, paths, excerpts and relationships before sharing. Nothing is automatically uploaded.
- The UI graph is a bounded relationship diagram, not a compiler-perfect call graph. Use keyboard-selectable nodes or the equivalent list view.
