# Rta-Smriti v1.0 Sovereign Project Cognition Design

Status: local implementation contract; not approved for publication.

## Product Boundary

Rta-Smriti v1.0 is the local memory, evidence, temporal truth, context, and
governance layer for a project. It observes and explains work. It does not plan
or execute project changes, route models, train models, publish releases, or
replace an agent harness such as RTA-Net.

## Architectural Decision

v1.0 extends the existing append-only truth ledger, repository index, capture
bus, work-state records, and governed context compiler. It does not create a
second source of truth.

The new cognition layer is a deterministic read model with four projections:

1. `project_twin`: reconciles repository, indexed files, truth claims,
   validators, checkpoints, work items, capture state, and optional external
   observations into observed, expected, missing, stale, conflicting, blocked,
   or unknown state.
2. `decision_debt`: identifies accepted or consequential claims that have weak,
   missing, expired, failed, contradictory, or inaccessible evidence.
3. `knowledge_coverage`: measures verified, known, stale, disputed, blocked,
   and unknown knowledge by subsystem without pretending that indexed bytes are
   semantically correct.
4. `change_impact`: maps bounded Git changes to indexed entities, graph edges,
   tests, memories, truth claims, validators, and documentation.

All projections are rebuildable and side-effect free. Explicit repairs flow
through existing governed work items, policies, or truth events and create
receipts; a read projection never repairs state by itself.

## Public Contracts

### Cognition snapshot

`cognition_snapshot(conn, project, root=None, include_change_impact=True)`
returns a versioned object containing:

- canonical project identity and repository state;
- task continuation readiness distinct from database health;
- twin observations and conflicts;
- decision-debt items with severity, reason, evidence, blast radius, and repair;
- subsystem coverage totals and ratios;
- bounded change-impact records;
- source counts, generation timestamp, and explicit limitations.

Output is JSON-safe, deterministically ordered, bounded, and privacy-safe. Raw
absolute paths, secrets, transcript payloads, and private database paths are not
returned.

### Multimodal evidence

Multimodal sources are proof-carrying evidence, not free-form attachments.

- A source record stores media kind, content hash, byte size, privacy class,
  sharing policy, source identifier, and bounded metadata.
- A derived observation stores method, tool identity, model identity when used,
  source hash, output hash, confidence, verification state, and bounded text.
- Source media and derived interpretation remain distinct.
- Local files are read through stable bounded descriptors and reject links,
  traversal, non-regular files, oversized payloads, and content drift.
- Deterministic text metadata is available without optional models. OCR,
  transcription, and vision enrichment are adapters and never become verified
  truth automatically.

### SDK and MCP

The stable Python SDK exposes typed request/response wrappers for health,
search, cognition snapshots, context compilation, truth reads, multimodal
evidence reads, and portability diagnostics. It does not expose internal SQLite
connections as a public contract.

MCP adds read-only cognition and multimodal inspection tools. Mutating evidence
ingestion is capability-gated on a single canonical project binding. The
multi-project gateway remains read-only.

### Operator cockpit

The dashboard adds a Cognition surface with:

- an identity/readiness header;
- decision-debt queue;
- knowledge-coverage map;
- digital-twin conflicts and recovery guidance;
- change-impact explorer;
- multimodal evidence inventory;
- clear loading, empty, partial, stale, blocked, error, and recovery states.

Every control invokes an implemented endpoint or is disabled with a reason.
The surface supports keyboard navigation, reduced motion, contrast, zoom, and
responsive layouts without relying on graph animation for comprehension.

## Projection Rules

### Authority

Authority ordering is deterministic:

1. verified executable validator or direct repository observation;
2. explicit accepted human decision with provenance;
3. corroborated truth claim;
4. structured checkpoint and handoff;
5. indexed source or unverified memory;
6. model-derived interpretation or hypothesis.

A lower-authority item cannot silently overrule a higher-authority item. Ties
remain visible as contradictions.

### Decision debt

A claim contributes debt when it is consequential and any of the following is
true:

- accepted/corroborated but has no active supporting evidence;
- evidence or validator is stale, unavailable, failed, or refuting;
- `expires_at` or `revalidate_at` has passed;
- an active contradiction branch exists;
- a promised next action or approval is unresolved;
- the source is missing, blocked, or no longer retrievable.

Severity uses explicit factors only: authority, epistemic state, evidence gap,
validator failure, contradiction, age, expiry, and graph blast radius. The
response includes every factor. Scores are advisory and never authorize work.

### Knowledge coverage

Coverage is not a single vanity percentage. Each subsystem reports counts for
`verified`, `known`, `stale`, `disputed`, `blocked`, and `unknown`, plus the
denominator and evidence used. The summary may report a ratio only when the
denominator is non-zero and its limitations are present.

### Change impact

The analyzer reads bounded Git status/diff metadata through the existing trusted
Git boundary. It does not execute a shell or trust project-local binaries.
Approximate graph edges remain labelled approximate. Missing compiler/LSP data
degrades visibly instead of fabricating precision.

## Storage Changes

Add schema-versioned tables only for data that cannot be reconstructed:

- `multimodal_sources`
- `multimodal_derivations`
- `cognition_observations` for explicitly imported external observations
- `cognition_reconciliation_receipts` for owner-approved repair outcomes

Derived cognition snapshots, coverage, debt, and change impact are not stored as
truth. Optional bounded cache rows may be introduced only with a source digest
and invalidation key.

Migrations are transactional and idempotent. Older runtimes reject newer schema
versions clearly. Upgrade qualification creates a no-clobber backup; downgrade
is restore from that backup.

## Budgets

- cognition snapshot: p95 <= 750 ms for 10,000 indexed files on warmed local DB;
- routine snapshot output: <= 512 KiB, max 250 debt items, max 500 observations;
- change analysis: <= 2,000 changed paths and <= 5,000 graph edges;
- multimodal source default: 32 MiB, configurable only within a hard 256 MiB cap;
- derived text per observation: <= 64 KiB;
- dashboard cognition response: <= 1 MiB and first useful render <= 2 seconds on
  the public operator fixture;
- no unbounded SQL result, recursion, archive expansion, process output, or file
  read.

## Failure Semantics

- Database healthy does not imply continuation ready.
- Fresh repository bytes do not imply accepted or verified project state.
- Missing optional adapters produce `unavailable`, never `pass`.
- Partial external observations produce a partial snapshot with named gaps.
- Canonical-root mismatch, unsafe file, invalid capability, or projection ledger
  failure fails closed.
- One blocked or metadata-only source does not erase healthy evidence; it is
  isolated and lowers only the affected coverage while remaining visible.

## Test Contract

### Kernel

- deterministic ordering and digest across repeated snapshots;
- no mutation from read projections;
- debt for unsupported, expired, failed, contradictory, and missing evidence;
- no debt for current accepted claims with passing validators and evidence;
- coverage does not equate indexed files with verified knowledge;
- correct partial/unknown semantics for unavailable adapters;
- bounded outputs under adversarial row counts and malformed JSON;
- canonical-root and privacy-safe output checks.

### Multimodal

- PDF/image/audio/video metadata ingestion with neutral synthetic fixtures;
- link, traversal, TOCTOU, oversized, malformed, and content-drift rejection;
- derived interpretation cannot self-promote to verified truth;
- retention, deletion, export, and redaction behavior;
- optional adapter unavailable and failure paths.

### Interfaces

- CLI JSON, SDK, MCP, daemon, installed wheel, native executable, and dashboard
  parity for the shared read contracts;
- capability denial and read-only gateway behavior;
- schema migration, replay, backup, restore, rollback, and older-runtime reject.

### Operator

- novice recovery, developer impact review, maintainer debt triage, security
  evidence inspection, and multi-project operator journeys;
- every cognition action, keyboard path, screen-reader label, responsive state,
  empty/partial/error state, and back navigation;
- browser console/network failures, loading duration, clipping, overflow,
  contrast, zoom, and reduced motion.

### Release

- Windows, macOS, and Linux clean install, upgrade, rollback, uninstall, native
  artifact, MCP, daemon, backup/restore, and offline behavior;
- public benchmark history and regression thresholds;
- threat model, attack-path review, Gitleaks, actionlint, dependencies, SBOM,
  package contents, binaries, website, screenshots, and privacy scan.

## Release Gate

No commit or publication is part of this local implementation approval. The
exact frozen v1.0 candidate, changed-file list, test evidence, browser evidence,
cross-platform evidence, security/privacy results, limitations, release notes,
and rollback sequence must be presented to the owner. Any code change after
that evidence requires a new frozen candidate and renewed approval.
