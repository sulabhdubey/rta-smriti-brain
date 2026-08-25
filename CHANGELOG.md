# Changelog

## [1.0.1-alpha] - 2026-08-26

- Closed a dashboard status race so direct operator feedback is not overwritten by delayed background refreshes.
- Closed temporal-truth database state before sending HTTP responses, preventing follow-up requests from overlapping cleanup on slower runners.
- Requalified the v1 operator, packaging, privacy, and cross-platform release surfaces from the corrected source.

This patch preserves the v1 data model, Project Reality features, and local-first
trust boundaries. Existing `v1.0.0-alpha` tags and artifacts remain immutable.


## [1.0.0-alpha] - 2026-08-25

- Added a bounded deterministic Project Cognition projection that reconciles indexed sources, bitemporal claims, observations, structured work state, decisions, and local media evidence.
- Added Project Reality readiness, digital-twin conflicts, knowledge coverage, decision debt, change-impact hints, and explicit truncation/omission accounting.
- Added a governed local multimodal evidence lifecycle with stable descriptor checks, source/derivation separation, operator verification, redaction, retention, deletion, and metadata-only export.
- Added a stable local Python SDK and aligned CLI, loopback-console, and read-only MCP cognition interfaces.
- Added synthetic cognition quality gates and rendered operator coverage while preserving the boundary that Rta-Smriti prepares evidence and continuity but does not execute project work.

The formal prerelease is published from its exact annotated tag after hosted
CI, tagged native builds, checksum and SBOM verification, privacy checks, and
anonymous download acceptance.

## [0.9.1-alpha] - 2026-08-24

- Added progressive authenticated dashboard bootstrap so useful project state renders before deep repository and continuity checks complete.
- Isolated all project-scoped asynchronous responses so delayed graph, file, capture, retrieval, governance, and truth results cannot leak across project switches.
- Added bounded API timeouts and explicit checking, stopped, and not-configured lifecycle states.
- Made multi-project MCP gateway schemas require an explicit project while preserving project-bound single-brain defaults.
- Added rendered adversarial regressions for progressive loading, delayed registry refresh, file-preview isolation, and capture-state isolation.

## [0.9.0-alpha] - 2026-08-23

- Added opt-in universal passive capture with versioned vendor adapters, bounded private spools, deterministic normalization, and one managed daemon per brain.
- Added append-only hash-chained capture events, causal replay, interruption diagnostics, policy-bound retention, deletion receipts, and encrypted forensic payload grants.
- Hardened interactive retention with preview-bound confirmation, made the multi-project MCP gateway strictly read-only, and closed expired-content, transcript-routing, checkpoint-authority, database-sidecar, adapter final-component, replay/deletion race, source-removal authorization, root-path redaction, provider-credential redaction, diagnostic resource-bound, cross-project status-isolation, stale-enrollment, MCP lifecycle-metadata exposure, daemon PID-reuse, privacy-filtered replay-chain, export-integrity, and paginated-anchor gaps.
- Split continuity process control from ordinary MCP memory-write permission, made lifecycle control responses path-free, and fail closed when a live worker's process identity cannot be verified.
- Added preview-first reversible adapter management, capability-separated CLI/MCP surfaces, and a local capture operator console.
- Added fail-closed source binding, queue backpressure, crash recovery, integrity verification, redaction, and explicit untrusted-evidence boundaries for agent-facing context.

## [0.8.0-alpha] - Unreleased

- Added governed context compilation for named agent profiles, immutable task contracts, bounded candidate selection, and privacy-scoped envelopes.
- Added durable authorization, explanation, outcome, comparison, and revocation receipts without exposing capability secrets.
- Added context compiler workflows across CLI, MCP, and the local operator console.
- Reused one fail-closed repository inspection across brain databases bound to the same canonical root, eliminating repeated health-scan Git subprocess amplification.
- Hardened release privacy scanning for non-Git roots, links, nested or renamed ZIP containers, unsafe archive paths, aggregate work limits, and stable in-memory archive inspection.
- Fail-closed governed MCP compilation now requires an exact process-scoped contract ID and digest; stored context chunks, dashboard result bindings, Git-status uncertainty, Windows archive paths, trusted Git resolution, immutable baselines, and extended UNC privacy detection have dedicated regression coverage.

## [0.7.0-alpha] - Unreleased foundation

- Added an append-only event-sourced bitemporal truth kernel with claim history, evidence links, contradictions, validators, abstentions, and as-of/commit-time queries.
- Added canonical project-brain integrity enforcement across root identity, checkout identity, readiness, MCP startup, and dashboard discovery.

## [0.6.0-alpha] - 2026-08-21

- Added bounded Codex `turn_context` rebinding so a task started elsewhere can be captured after it enters the canonical project, without importing the earlier foreign transcript.
- Added an MCP doctor that probes the exact generated stdio command through initialize, tools/list, and ping before host registration.
- Added AES-256-GCM encrypted portable snapshots with scrypt passphrase derivation, optional Ed25519 sender signatures, authenticated verification, and atomic restore to a new brain.
- Added append-only benchmark history, latest-versus-previous metric deltas, and historical Markdown reporting.
- Replaced regex-derived Tree-sitter call edges with language-aware syntax-tree call extraction for Python, JavaScript, TypeScript, TSX, Go, Rust, and Java.
- Added workspace member health, degraded partial search, member removal, workspace deletion, and a read-only MCP health tool.
- Added dashboard operator workflows for MCP probing, workspace health/member management, and encrypted snapshot key generation, create, verify, and restore.
- Moved common Tree-sitter grammars and Ed25519 support into the standard package and native binary contract.
- Added metadata-only oversized-source isolation with explicit `fresh_with_warnings` semantics and a compatible strict-block policy.
- Added opt-in discovery and bounded native JSON-RPC for supported local language servers, with project-local executable rejection and conservative parser fallback.
- Added opt-in loopback-only Ollama continuity compaction with redaction, request/response bounds, append-only provenance, and unverified derived-state labeling.
- Added release regressions proving that completed ingestion warms every eligible SHA-256 cache entry before a deep verification.

All notable changes are documented here. The project follows semantic versioning while APIs remain alpha.

## [0.5.0-alpha] - 2026-08-20

- Added append-only Codex session events, resumable transcript cursors, structured work-state reconciliation, and operational readiness.
- Added a managed continuity daemon with canonical-project session binding, partial-write recovery, payload redaction/bounds, heartbeat validation, and conservative automatic checkpoints.
- Added dashboard and MCP lifecycle controls plus one fail-closed multi-project MCP gateway.
- Added optional Ed25519 public-key snapshot signatures and cross-platform snapshot key generation while keeping HMAC snapshots compatible.
- Added shareable Markdown output for the public benchmark.
- Added continuity binding diagnostics that explain when recent Codex sessions exist outside the canonical project root without exposing foreign paths.

## [0.4.0-alpha] - 2026-08-16

- Added foreground and managed-background incremental repository sync with optional filesystem events, portable polling fallback, lifecycle status, heartbeat, and a persistent stat-keyed SHA-256 cache.
- Made repository refresh transactional so parser or indexing failures cannot leave a partial new snapshot visible.
- Added bounded concurrent MCP request scheduling so control traffic remains responsive while mutations preserve causal order.
- Expanded optional Tree-sitter extraction for Python, TypeScript, Go, Rust, and Java symbols and imports.
- Added optional hybrid FTS and local-vector retrieval with dependency-free hash embeddings and a lazy Sentence Transformers adapter.
- Added a parser registry with deterministic regex, optional Tree-sitter, explicit LSP command, and Python entry-point adapters.
- Added per-project ingestion policies for parser choice, retrieval provider, semantic weight, and source-file size caps up to 16 MB.
- Added authenticated loopback settings APIs and dashboard controls with explicit blocked-file and optional-dependency warnings.
- Added canonical-root protection, Git checkout diagnostics, structured continuation checkpoints, claim provenance, compact freshness output, and generated-artifact exclusions.
- Added a one-click new-task prompt to the dashboard and MCP/CLI continuation tools.
- Made the recommended bootstrap dependency-free hybrid retrieval with deterministic hash embeddings; lexical-only mode remains selectable.
- Fixed bootstrap ordering so generated agent bridge files are included in the initial index and a new brain starts fresh.

## [0.3.0-alpha] - 2026-08-15

- Added multi-project React operator console and radial semantic graph.
- Added file explorer, Canvas, typed Bases, context-pack receipts, memory ledger, freshness, and bootstrap flow.
- Added agent-neutral targets and stdio MCP integration.
- Added launch site, privacy-safe Atlas demo, Product Hunt assets, social preview, and editable Remotion demo video.
- Added per-launch dashboard capability authentication, bounded HTTP workers, strict MCP frame validation, and hard-link rejection.
- Added explicit untrusted-evidence boundaries to every generated context pack.
- Made context-pack receipts session-only and expanded path masking across display and bootstrap surfaces.
- Split GitHub Pages build and deployment privileges, pinned actions by commit, and added deterministic plus Gitleaks privacy gates.
