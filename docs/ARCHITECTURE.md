# Architecture

## Project Cognition Layer

v1 adds a deterministic read projection over existing evidence rather than a
second mutable source of truth. It binds every request to the canonical project
and combines the latest indexed source snapshot, bitemporal claims, normalized
observations, structured work state, durable decisions, and governed media
records. The projection emits project readiness, a digital-twin reconciliation,
knowledge coverage, decision debt, change-impact hints, conflicts, and explicit
input/output truncation metadata.

Readiness is intentionally stricter than database health. Missing checkpoints,
stale or uncertain indexed evidence, unresolved high-authority conflicts,
incomplete work state, and omitted bounded inputs can block or degrade
continuation readiness. Routine cognition reads the latest completed index and
does not walk the live filesystem. Consequential work still requires an explicit
live or deep freshness check. The projection is deterministic and bounded; it is
not an LLM judge, planner, executor, or compiler-perfect program analysis.

## Local Multimodal Evidence

Media is stored as local evidence metadata and bounded content-derived
descriptors. Stable descriptor checks reject links, reparse points, hard links,
path substitution, oversized inputs, and changing files. Original sources and
derived descriptions remain separate records. Derivations start unverified and
require explicit operator authority plus provenance before they can contribute
verified evidence. Retention, redaction, deletion, and public export are
separate operations; public export is metadata-only and omits local paths and
payloads.

## Stable Interfaces

The Python SDK, CLI `cognition` and `media` commands, authenticated loopback
console endpoints, and read-only MCP tools call the same domain boundaries.
Interface responses carry schema/version information, exact totals, displayed
counts, truncation flags, freshness semantics, and limitations. MCP remains
project-scoped and capability-bounded. None of these interfaces grants an agent
execution authority over the project.
Rta-Smriti is a local Python application with a React operator surface. It has no hosted control plane.

```text
Repository / thread / memory
          |
          v
Fail-closed ingestion policy
  | parser registry
  | event-scoped content verification
  | incremental stat manifest
  | SHA-256 cache
          |
          v
SQLite project brain
  | sources + chunks
  | FTS5 indexes
  | optional local vectors
  | entities + evidence edges
  | durable memories + pramana
  | structured checkpoints + claim provenance
  | governance policies + decision receipts
  | workspace references + memory feedback
          |
          +--> CLI / stdio MCP
          +--> loopback-only dashboard
          +--> focused context pack
          +--> selective bundle / authenticated snapshot
```

Codex JSONL sessions enter through a separate continuity adapter. It reads sessions whose current bounded working context is inside the selected canonical project root, persists byte cursors, preserves incomplete final records for the next cycle, redacts common credential shapes, and bounds oversized tool output before writing append-only events. A task whose session metadata points elsewhere can rebind at a later verified `turn_context`; ingestion begins at that byte offset and never imports the earlier foreign transcript. Later context changes are enforced while reading. Initial capture is bounded by session age and a recent byte tail; a provenance-bearing `history_truncated` event exposes omitted history, after which every complete appended record is captured.

## Storage

Each brain is one SQLite database. Connections reject symbolic, reparse, and hard-linked database files; apply owner-only POSIX modes where available; disable SQLite trusted schema; and use WAL journaling, normal synchronous durability, foreign keys, and a bounded busy timeout. Concurrent agents can read while crash-safe writes remain transactional. Project settings, portable repository identity, canonical root binding, manifests, file hashes, chunks, FTS records, optional embedding vectors, memories, claim provenance, versioned checkpoints, governance records, workspace references, entities, edges, evidence, and recall receipts remain local.

## Ingestion

The walker rejects links, non-regular files, ignored folders, traversal overages, total-size overages, and sources above the project's configured cap. A stat manifest skips unchanged repositories. Filesystem events bypass metadata shortcuts and bind a content-hash read to the repository root, even when size and modification time were restored. Only changed files are parsed, chunked, indexed, and embedded. `watch-repo` runs this incremental path in the foreground. The `watcher` lifecycle command runs it in a detached per-project worker, using optional filesystem events when `watchdog` is installed and portable polling otherwise. Polling workers force a full content verification at least every five minutes so same-stat changes cannot remain indefinitely invisible.

Deep freshness uses SHA-256 values cached by project, absolute source path, size, and nanosecond modification time. `ingest-repo --force` bypasses the manifest and metadata shortcuts for an uncached re-read.

Freshness output is anomaly-first: changed, missing, added, and blocked files are returned up to a bounded detail limit, while fresh-file rows are summarized unless explicitly requested.

## Project Identity

A named project is bound to a portable repository identity, one per-checkout identity, and one resolved canonical root. The repository identity establishes lineage; the checkout identity distinguishes clones and linked Git worktrees that share that lineage. Git metadata paths are used for marker writes only after a trusted Git executable independently confirms the native layout and a linked checkout's Git metadata points back to that checkout. Unverified or aliased `.git` pointers fall back to an in-project local identity and cannot redirect marker writes outside the project.

Freshness, self-check, operational readiness, generated single-project MCP configuration, and every call handled by a root-pinned MCP process verify the active checkout. Binding verification also runs when a caller omits an active-root argument. A moved or alternate checkout never inherits a prior checkout's freshness, even when the former folder is missing. Intentional migration requires `root-rebind`, a no-clobber SQLite backup published from a private unique temporary file, stopped watcher, continuity, and MCP owners, matching repository lineage, and one atomic forced reindex. Ingestion snapshots the binding before filesystem scanning and rechecks it after acquiring the SQLite write lock; a concurrent migration aborts the stale scan. Parser or write failure rolls back the root, checkout identity, migration receipt, and index together. Diagnostics expose bounded fingerprints, schema state, commit, dirty count, duplicates, and migration status without raw project names, branch names, or filesystem paths.

## Parser Boundary

`ParserRegistry` ships with:

- automatic parsing, using bundled Tree-sitter grammars when supported, then deterministic regex fallback
- deterministic regex parsing, always available
- a standard-install `tree-sitter-language-pack` adapter for Python, JavaScript, TypeScript/TSX, Go, Rust, and Java
- opt-in PATH discovery and bounded JSON-RPC for Pyright, gopls, TypeScript Language Server, and rust-analyzer; project-local executables are rejected and the resolved executable identity is bound into the manifest and rechecked before launch
- a compatible explicit local JSON command adapter for custom symbol/import providers
- Python entry points in the `rta_smriti.parsers` group

Discovered executables inside the project root are rejected, native LSP execution
never uses a shell, and frames, process time, and response sizes are bounded.
Unavailable or failed parsers fall back to regex and emit warnings in the ingestion receipt.

## Retrieval

FTS5 BM25 remains available on every project. The recommended bootstrap path enables hybrid ranking that combines lexical rank with local cosine similarity through the dependency-free feature-hash provider. Operators can select lexical-only retrieval or a Sentence Transformers adapter, which loads only when separately installed and selected.

Context packs enforce a caller-selected token budget. Checkpoints and high-ranked `pratyaksha` evidence are considered first; lower-priority memories and chunks are omitted when needed, and the pack states when pruning occurred. Optional `tiktoken` provides model tokenization while the dependency-free path uses a conservative deterministic estimate.

Retrieval diagnostics report the active mode, provider, embedding coverage, parser fallbacks, freshness, elapsed time, rank components, source hashes, normalized query terms, and per-result selection reasons. The public benchmark ships as package data and compares no-memory, lexical, and dependency-free hash-hybrid modes on a synthetic corpus. An explicit flag can add an available local Sentence Transformers model; otherwise the result records that optional semantic evidence was not requested. Operators can append bounded private-safe JSONL history and render latest-versus-previous metric deltas. Its results are regression evidence, not a claim of market superiority.

## Cognitive Context Compiler

The governed compiler is separate from the legacy copyable context-pack builder. An operator registers a bounded agent-consumption profile and authorizes an immutable task contract containing objective, acceptance criteria, evidence requirements, stop and escalation conditions, prohibited repetition, privacy scope, informational grants, and token economics. A short-lived host capability binds compilation to the exact project, contract, principal, session, scope, expiry window, and revocation state. Agents cannot self-authorize operator scopes or raise their own privacy ceiling.

Compilation captures one read-only project snapshot, verifies repository and database fences, adapts candidate evidence through a strict normalized contract, filters privacy and scope before scoring, and ranks with fixed-point authority, verification, freshness, temporal, lexical, graph, risk, outcome, and continuation signals. Mandatory controls either fit or the compiler abstains. Comparison variants share the same snapshot, while immutable metadata receipts explain inclusion, exclusion, redaction, downgrade, deduplication, section allocation, and truncation without retaining private payloads by default. Operator-confirmed outcomes can later attribute useful or harmful evidence without letting the compiler execute the task.

The authority key is host-owned. Windows uses DPAPI; POSIX uses an owner-only unlinked file. Status returns only a fingerprint. CLI, loopback console, and MCP entry points call the same compiler boundary; MCP fixes the agent principal and session server-side rather than accepting caller-supplied identity. The compiler prepares evidence and constraints only. It does not plan, route models, call project tools, mutate repositories, or cross into RTA-Net execution responsibilities.

## Governance

Typed policies describe constraints, failed approaches, fragile paths, required checks, and prohibited repetition. Preflight evaluation is deterministic and scope-aware. Only high-trust, verified, hash-backed policy evidence can independently block; weaker records are warnings. Optional operational context adds transient warnings for consequential actions when checkpoint readiness, continuity capture, Git dirty state, canonical root, or index freshness is not green. Every evaluation emits a short-lived receipt bound to the action and current policy digest. Owner overrides record actor, reason, and matched policy evidence. Agent MCP tools cannot mutate policy, attest required checks, or override a block.

## Graph Intelligence

Ingestion records files, symbols, imports, calls, tests, configuration, memories, and evidence links. Supported Tree-sitter languages derive calls from syntax-tree call nodes, excluding comments and string literals; deterministic regex remains the explicit fallback. Bounded graph queries traverse dependencies, dependents, impact, evidence, or relevance to depth four and at most 500 nodes. Each query returns its enforced relation filter: dependency views use calls/imports, impact adds containment/tests, evidence follows containment/tests/memory mentions, and relevance follows memory mentions only. Confidence labels make approximate edges distinguishable from direct source relationships.

## Workspaces And Portability

A workspace is metadata owned by one brain database that references explicitly selected projects in independent local brain databases. Health checks report availability without returning member database paths. Search opens available external databases in SQLite query-only mode, writes no recall receipts, returns grouped results, and reports unavailable members as a degraded partial result instead of losing healthy-project recall. Members can be removed and workspace metadata can be deleted without deleting project brains; project identity and storage remain isolated.

Selective bundles contain only chosen memories, checkpoints, and policies. Source code is excluded. Export redacts home paths and common credential patterns by default and attaches a SHA-256 content digest for integrity, not authentication. Preview mode reports contents, warnings, conflicts, and the digest without mutating disk or a destination brain. Import verifies the envelope, validates bounded schemas, and stages every change in an in-memory SQLite copy before one atomic commit under an explicit rename, merge, or fail conflict strategy. Because bundles are unsigned, imported memories are downgraded to unverified `smriti`; imported checkpoints and policies are quarantined for owner review rather than gaining authority. Bundle inputs are limited to 25 MB and read through a stable descriptor. Private bundle and snapshot writes reject linked paths and use restrictive atomic writes. Authenticated snapshots use a consistent SQLite backup plus either compatible HMAC-SHA256 shared-key authentication or standard-install Ed25519 public-key signatures. Encrypted v3 snapshots derive a 256-bit key from a separate passphrase file with scrypt, stream the database through AES-256-GCM, optionally sign the manifest with Ed25519, and restore only through authenticated digest and SQLite integrity checks to a new path. Verification authenticates manifests before accepting content, caps decoded databases at 64 MiB and legacy envelopes at 16 MiB, and uses bounded reads. HMAC and signature-only snapshots detect tampering but remain private unencrypted artifacts; encrypted snapshots protect content at rest but still must not be published with their passphrase.

## Memory Lifecycle

Helpful, neutral, and harmful outcomes are explicit operator feedback. Conservative decay can reduce confidence only for old, unverified `anumana` and `kalpana` records that have not been reinforced. Verified claims and `pratyaksha` or `sabda` evidence are protected.

## Agent Concurrency

The stdio MCP server is bound to one project and exposes only read tools by default. Single-project startup requires an exact canonical binding; a missing `--root` is derived only from that verified database binding, while generated configuration always includes the explicit pin. The process holds a PID-bound local lease and each direct library call holds a short-lived lease under a cross-process binding gate. Root migration takes the same gate and refuses active leases, closing validation-to-dispatch races without serializing independent tool execution. Memory writes, repository ingestion, and thread ingestion require separate startup capabilities; repository ingestion always uses the registered canonical root, short-circuits when the current index is already fresh, and thread ingestion requires explicit allowed roots plus descriptor-bound reads. Agent-authored memory is downgraded to unverified `anumana` and cannot self-assert source authority. Governed context compilation requires an operator to delegate the exact authorized contract ID and SHA-256 digest at process startup; compile and explain tools are absent otherwise, so clients cannot enumerate another MCP session's sequential contract IDs. Blocking SQLite, hashing, parsing, and embedding work moves to worker threads with bounded request count, bytes, JSON nesting, and concurrency. Mutation visibility is ordered, memory batches are atomic, and checkpoints use optimistic versions under a SQLite write transaction so stale agents cannot silently overwrite newer continuation state.

`mcp-doctor` starts the exact command emitted by `mcp-config`, negotiates the MCP protocol, lists tools, and pings the server under a bounded timeout. Passing the probe proves the generated local server works; the operator must still register the returned host configuration and start a fresh agent task because running hosts do not acquire MCP tools dynamically.

## Background Sync

Managed watchers are explicit user processes, not privileged services. A random launch capability binds each worker to an unlinked lock file. State, heartbeat, counters, stop requests, and logs live beside the selected brain under `.rta-smriti-daemons`. Control files reject symbolic and hard links, state writes are atomic, repository events are coalesced, and every indexing cycle uses a fresh SQLite connection and one rollback-safe transaction. The dashboard never accepts a client-supplied watch root; it reads the canonical root already bound to the selected project.

The console has the same explicit start/open/status/restart/stop lifecycle and stores its capability token in a restricted local control file. Optional login startup writes only an owner-requested user-level registration and can be inspected or removed by the same CLI. The foreground `dashboard` command remains available for diagnostics.

The continuity daemon uses the same managed-process safety model but never changes repository files. It captures a bounded number of pending sessions and events per cycle so stop requests remain responsive. Automatic checkpoints are created only after the newest matching transcript is fully consumed and a terminal, inactivity, or service-shutdown trigger occurs. They carry `source=continuity-daemon`, keep `verified_evidence` empty, and explicitly require operator verification. Manual checkpoints remain separately identifiable.

On POSIX systems, brain databases, WAL/SHM sidecars, daemon state, and logs are restricted to the owning user (`0600`), while daemon control directories use `0700`. Rta-Smriti rejects linked database/control artifacts and files owned by another user. These controls do not isolate mutually untrusted processes running under the same operating-system account; use a dedicated OS account or machine boundary for that threat model.

## Multi-Project MCP Gateway

One stdio MCP process can receive a brain directory instead of one database. Each tool call must name a project. The gateway scans only unlinked SQLite files in that directory and opens the call against exactly one matching project database. Missing and duplicate project names fail closed, preventing accidental cross-project recall while avoiding six copies of the same MCP tool set. This gateway is strictly read-only: mutation capabilities are available only from an explicitly configured single-project MCP binding, and gateway freshness checks cannot refresh the hash cache.

## Distribution

`pyproject.toml` console scripts are the primary source installation path. Static dashboard assets and the public benchmark corpus are included as package data and exercised from a clean wheel. A versioned PyInstaller specification and three-operating-system GitHub workflow build standalone Windows, macOS, and Linux artifacts without making PyInstaller a runtime dependency.

## Trust Boundary

The HTTP console binds only to loopback, requires a per-launch capability token, validates local origins, and confines database paths to its configured brain directory. Retrieved repository text is evidence, not executable instruction. Oversized files default to metadata-only records with `fresh_with_warnings`; their content is never represented as indexed. Strict-policy, linked, or otherwise uninspectable sources keep freshness fail-closed.

Optional continuity compaction calls Ollama only through a validated HTTP(S)
loopback base URL. Inputs and outputs are redacted and bounded, failures preserve
the deterministic checkpoint, source events remain append-only, and summaries
are stored as unverified derived evidence rather than verified facts.
