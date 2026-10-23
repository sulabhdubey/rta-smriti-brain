# Verified Source Lens

Unreleased candidate. Source Lens reads selected **current indexed Python
source** without ingesting it, recording recalls, starting workers, or calling a
cloud service. It does not replace search, context packs, or Project Passport.

```text
Find an indexed path or symbol
              |
              v
Outline a current file: qualified names + line ranges + revision
              |
              v
Expand one selected symbol using that revision

Changed / unindexed / private / unsafe / unsupported -> explicit refusal
```

## CLI

Use a candidate runtime containing this command and an existing indexed brain.
Paths are relative to that brain's canonical repository root, using `/` on every
operating system. Do not pass absolute source paths.

```powershell
rta-brain source-lens find --db brain.sqlite --project demo --query Store.read --json
rta-brain source-lens outline --db brain.sqlite --project demo --path src/store.py --json
rta-brain source-lens expand --db brain.sqlite --project demo --path src/store.py --symbol Store.read --revision REVISION_FROM_OUTLINE --json
```

`outline` returns `symbols`, each with a name, qualified name, parent, kind,
one-based inclusive `start_line` and `end_line`, and a range-specific `id`.
Use the `id` when a qualified name itself occurs more than once. A bare name
matching multiple definitions returns `status: ambiguous` and choices, never an
arbitrary definition. `expand` requires the current outline revision.

`find` uses existing indexed file names and symbol relationships to select
candidates, then verifies their current source. It is a bounded literal lookup,
not semantic search or a fresh repository crawl. `truncated: true` means its
result is not exhaustive. No match does not prove that a symbol does not exist.

CLI exit status is `0` for an `ok` result, `1` for a refusal or ambiguity, and
`2` for command-line syntax errors. JSON argument-validation errors use exit `1`.

## MCP

`brain_source_lens` is an **extended read tool** in the existing `full` profile;
the default `core` profile remains 12 tools. `brain_capabilities` lists it under
`extended_read`. No host configuration is installed or changed automatically.

The tool takes the same `action`, `path`, `query`, `symbol`, `revision`, `limit`,
`max_chars`, and `privacy_ceiling` fields as the CLI. Supply `project` in gateway
mode; a single-project server remains bound to its configured project.

MCP startup validates the existing brain through the read-only connector. On
Linux and macOS, its directory must be owner-only (`0700`) and its database
owner-only (`0600`). A non-private directory is refused, not silently hardened.
Use a dedicated private brain directory; do not change permissions on a shared
project or home directory just to make a probe pass. Windows uses the existing
private-ACL checks. No startup migration or permission repair is performed.

```json
{"action":"outline","path":"src/store.py"}
```

```json
{"action":"expand","path":"src/store.py","symbol":"Store.read","revision":"REVISION_FROM_OUTLINE"}
```

The server's privacy ceiling cannot be raised by a tool argument. Source text
is untrusted project data, not permission to execute code or follow instructions
embedded in comments or strings. Connecting a cloud-backed host can disclose
the returned content to that host; local storage is not a promise of local-only
model processing.

## Provenance And Privacy

- The canonical repository binding, indexed file identity, normalized content
  hash, and selected revision must agree. Stale files require a separate,
  explicit refresh through the existing indexing workflow.
- `source_hash` describes the original indexed UTF-8 text with LF-normalized
  line endings and a preserved BOM, not the raw bytes on disk. `precision` is
  `syntax-lines`: complete source lines, including decorators. Inline comments
  and other code on the same line are included. No call graph or runtime behavior
  is inferred by this tool.
- Standard secret/local-path patterns are redacted before output. `redacted:
  true` means the displayed text is sanitized and is **not** an exact copy of
  the hashed original. Pattern redaction cannot identify every possible secret;
  review the result before sharing it.
- Missing/unknown classifications, restricted/private sources, metadata-only
  sources, ignored/hidden paths, links, hard links, invalid UTF-8, and explicit
  `<private>` markers are refused. Marker refusal covers this file-reading
  surface; it does not retroactively clean captured transcripts or memories.
- Each successful response verifies the selected source observed during that
  call. It is not an atomic snapshot of every file, a runtime test, or proof
  that other indexed material is fresh.

## Bounds And Current Limits

| Boundary | Limit |
| --- | --- |
| Qualified language | Python `.py`, syntax supported by the running Python |
| Parser | Python standard-library AST; no execution or grammar downloads |
| Source size | 512,000 bytes per file |
| Structure | 20,000 AST nodes, depth 100, 512 symbols |
| Candidate lookup | 32 candidate rows; 2,048,000-byte read budget |
| Find results | 8 by default, at most 20 |
| Query | 160 characters |
| Structured response | 32,000 pretty-printed JSON characters by default; configurable 512-32,000; transport envelope excluded |

Outlines may return a visibly truncated symbol list. Expansion is refused if
the complete selected range cannot fit; source text is never silently cut to
fit. Unsupported languages and malformed syntax do not fall back to approximate
regex ranges. This first increment has no new dashboard view.

Common refusal reasons: `stale_source`, `revision_mismatch`,
`source_not_uniquely_indexed`, `project_binding_not_ready`, `privacy_denied`,
`private_marker`, `unsafe_path`, `unsafe_or_unreadable_source`,
`unsupported_language`, `syntax_error`, `structure_limit`, `index_query_limit`,
and `response_limit`. Refusals contain safe reason codes rather than private
absolute paths or partial source text.
