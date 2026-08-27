# Rta-Smriti Brain

## v1.0.3-alpha

`v1.0.3-alpha` is the current maintenance prerelease for the v1 release line.
It replaces misleading empty-brain rendering after an expired console
capability with a direct recovery path, and turns newer-schema launcher failures
into actionable, non-mutating upgrade guidance. See the
[release notes](docs/RELEASE_NOTES_v1.0.3-alpha.md)
and bounded [verification ledger](docs/RELEASE_VERIFICATION.md).

v1 turns the brain from a searchable index into an inspectable project-reality
layer. A deterministic Project Cognition projection reconciles indexed sources,
bitemporal truth, observations, structured work state, decisions, and local
multimodal evidence. It reports readiness, coverage, change impact, conflicts,
and decision debt under explicit output budgets. It does not execute project
work, route models, or replace an agent harness.
![Rta-Smriti Brain - Give every project a memory](launch-assets/social/github-social-preview.png)

[![CI](https://github.com/sulabhdubey/rta-smriti-brain/actions/workflows/ci.yml/badge.svg)](https://github.com/sulabhdubey/rta-smriti-brain/actions/workflows/ci.yml)
[![Cross-platform binaries](https://github.com/sulabhdubey/rta-smriti-brain/actions/workflows/binaries.yml/badge.svg)](https://github.com/sulabhdubey/rta-smriti-brain/actions/workflows/binaries.yml)
[![Release](https://img.shields.io/github/v/release/sulabhdubey/rta-smriti-brain?include_prereleases&label=release)](https://github.com/sulabhdubey/rta-smriti-brain/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE)

**A sovereign local project-memory and evidence layer for AI coding agents. The `v1.0.3-alpha` release preserves deterministic Project Reality while hardening authorization recovery, launcher upgrades, and schema-compatibility diagnostics.**

**Build provenance:** Conceived and researched by [Sulabh Dubey](https://github.com/sulabhdubey). Built with [OpenAI Codex](https://openai.com/codex/) as the primary design, engineering, testing, and documentation agent under Sulabh's product direction and release approval. [Details](CONTRIBUTORS.md).

Rta-Smriti now connects repository intelligence, durable decisions, agent-session continuity, and evidence-aware retrieval through a private local event journal. Capture is opt-in, bounded, redacted before durable queuing, and explicitly treated as untrusted evidence until an operator or verifier promotes a claim.

[Current release: v1.0.3-alpha](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.0.3-alpha) · [Release notes](docs/RELEASE_NOTES_v1.0.3-alpha.md) · [Live website](https://sulabhdubey.github.io/rta-smriti-brain/) · [60-second v1 product demo (captured from v1.0.2)](launch-assets/product-hunt/rta-smriti-v1.0.2-product-demo.mp4) · [Installation](docs/INSTALLATION.md) · [Usage guide](docs/USAGE_GUIDE.md) · [Architecture](docs/ARCHITECTURE.md) · [Public benchmark](docs/PUBLIC_BENCHMARK.md) · [Release verification](docs/RELEASE_VERIFICATION.md) · [Build provenance](CONTRIBUTORS.md) · [Security](SECURITY.md) · [Roadmap](ROADMAP.md)

Rta-Smriti Brain turns a project repository, long agent threads, durable decisions, and evidence into a small local memory graph that Codex, Claude Code, Cursor, or any MCP-capable agent can reuse before doing work.

It is built for the moment every AI-assisted developer knows too well:

> "New chat. Same project. Same explanations. Same lost context."

Rta-Smriti gives each project a memory that stays on your machine.

## Latest Release

[`v1.0.3-alpha`](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.0.3-alpha)
is the current published prerelease. The exact tagged source passes the hosted
Windows, macOS, and Ubuntu matrix across Python 3.11, 3.12, and 3.13. The native
workflow builds and smoke-tests Windows x64, Linux x64, and macOS standalone
binaries, a universal wheel, CycloneDX SBOMs, and a combined
`SHA256SUMS.txt`. The public wheel and Windows binary were then downloaded
without authentication and acceptance-tested from the release page; see the
[release verification record](docs/RELEASE_VERIFICATION.md) for the evidence
boundary and post-publication checks.

v1 adds deterministic Project Cognition and the Project Reality cockpit on top
of canonical project identity, bitemporal truth, governed context compilation,
and Universal Capture. It reconciles indexed sources, structured work state,
decisions, observations, and governed local media into bounded readiness,
coverage, conflict, change-impact, and decision-debt views. The product remains
an evidence and continuity layer: it does not execute project work or silently
promote captured text into trusted truth.

## What It Does

- Indexes your repo into local SQLite: files, chunks, symbols, imports, and graph edges.
- Stores durable memories: decisions, constraints, procedures, facts, and hypotheses.
- Binds every project brain to one canonical root and refuses silent checkout switching.
- Distinguishes clones and Git worktrees with a per-checkout identity, reports privacy-safe root/repository/checkout fingerprints, and revalidates every MCP call.
- Requires explicit, backup-first root rebinding even when an old folder disappeared; repository scans recheck the binding inside their write transaction before committing.
- Records structured checkpoints: objective, verified evidence, remaining gaps, next action, and prohibited repetition.
- Attaches source path, hash, verification command, timestamp, and verification status to remembered claims.
- Ingests long threads or handoff notes as explicitly unverified prior memory so useful context survives compaction without self-assigning trust.
- Incrementally captures matching local Codex sessions with resumable byte cursors, bounded/redacted event payloads, and conservative interruption checkpoints.
- Builds a focused **context pack** for the next agent task.
- Compiles governed agent-specific context from immutable task contracts, explicit acceptance and stop conditions, privacy grants, and explainable selection receipts.
- Enforces a hard context token budget and keeps direct evidence ahead of low-trust historical memory.
- Runs a local operator console with graph, canvas, typed bases, context-pack receipts, memory ledger, freshness checks, and bootstrap flow.
- Loads project surfaces progressively with bounded requests, explicit lifecycle states, and race-safe project switching.
- Exposes a dependency-light stdio MCP server for agent integrations.
- Runs independent MCP tool calls concurrently while preserving ordered mutation visibility.
- Watches active repositories with foreground or managed-background incremental sync and reuses a persistent SHA-256 cache for deep freshness checks.
- Supports optional local hybrid retrieval through a built-in deterministic hash provider or an installed Sentence Transformers model.
- Ships Tree-sitter parsing for seven common source families, deterministic regex fallback, and opt-in discovery of supported local language servers.
- Evaluates intended actions through an evidence-aware **Action Gate** that returns `allow`, `warn`, or `block` with policy, readiness, Git, and freshness signals.
- Explains retrieval provider, embedding coverage, freshness, latency, lexical/semantic rank, and source-hash provenance instead of hiding ranking decisions.
- Traverses bounded dependency, dependent, impact, evidence, and relevance subgraphs with explicit relation filters, including approximate calls and test links.
- Searches existing project brains through query-only local workspaces without merging or mutating their databases.
- Previews and exports selective redacted memory bundles, stages verified imports before one atomic commit, and verifies authenticated private snapshots.
- Records helpful or harmful memory outcomes and conservatively ages only eligible unverified inference or hypothesis records.
- Keeps data local by default: no API keys, no telemetry, no cloud database.

## Why It Is Different

Most second-brain tools store notes. Most code tools index files. Most agent memory systems recall text.

Rta-Smriti combines all three into a small, inspectable project brain:

| Layer | What it adds |
| --- | --- |
| Repo map | Files, chunks, symbols, imports, and evidence edges |
| Memory ledger | Durable decisions, constraints, procedures, and facts |
| Thread memory | Long sessions become searchable project evidence |
| Context pack | A compact, copyable brief for the next agent turn |
| Continuation checkpoint | Structured state that tells the next agent what is done, what remains, and what not to repeat |
| Pramana model | Evidence labels so observed facts, trusted docs, inference, memory, and hypotheses are not treated equally |
| Action Gate | Pre-action checks that surface trusted constraints, required proof, fragile paths, prohibited repetition, checkpoint readiness, dirty worktrees, and stale indexes |
| Explainable intelligence | Retrieval diagnostics with selection reasons plus bounded graph impact queries with evidence hashes and confidence |
| Local workspaces | Search across explicitly selected project brains while preserving database isolation |
| Local operator console | Visual graph, freshness, publish checks, bootstrap, and memory reflection |

The core idea is simple: **memory should not only remember. It should help an agent decide what context deserves trust right now.**

## The Pramana Model

Rta-Smriti uses a Vedic-inspired evidence model to classify context:

- `pratyaksha`: directly observed from code, tests, files, or tools
- `sabda`: trusted instruction, documentation, or human guidance
- `anumana`: inference
- `smriti`: prior memory
- `kalpana`: hypothesis or creative possibility

This keeps a test result, a human instruction, an assumption, and a brainstorm from collapsing into the same kind of "memory."

## Install

Requirements: Python 3.11 or newer and Git. Rta-Smriti supports Windows,
macOS, and Linux. Node.js is only needed to modify the dashboard source.

### Windows (PowerShell)

```powershell
git clone https://github.com/sulabhdubey/rta-smriti-brain.git
cd .\rta-smriti-brain
python --version
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install .
$RtaBrain = Join-Path $PWD ".venv\Scripts\rta-brain.exe"
& $RtaBrain --json doctor
```

Keep `$RtaBrain` in the current PowerShell session and use `& $RtaBrain` in
the commands below. The launcher is generated from `project.scripts` by pip;
it does not depend on the source wrapper files.

### macOS Or Linux (Bash/Zsh)

```bash
git clone https://github.com/sulabhdubey/rta-smriti-brain.git
cd rta-smriti-brain
python3 --version
python3 -m venv .venv
./.venv/bin/python -m pip install .
RtaBrain="$PWD/.venv/bin/rta-brain"
"$RtaBrain" --json doctor
```

Keep `RtaBrain` in the current shell and use `"$RtaBrain"` in Bash or Zsh.
See the [installation guide](docs/INSTALLATION.md) for native binary artifacts,
optional extras, troubleshooting, and uninstall instructions.

Upgrading from an earlier alpha requires upgrading the active launcher, not
changing the brain database. If the console reports a newer schema, follow the
[existing-installation upgrade procedure](docs/INSTALLATION.md#upgrade-an-existing-installation).
After a console restart, reopen it with `console open`; the plain loopback URL
does not carry the new one-session capability.

## Quick Start

Create one central brain directory, then onboard and open a project in one command. This detects the canonical Git root, creates or migrates the brain, indexes it, starts the background watcher, starts Codex task-continuity capture when a local Codex sessions folder exists, opens the managed console, and opens an authorized browser session:

New brains default to built-in hash retrieval. Re-running onboarding preserves an existing brain's configured provider; use `--embedding-provider` only when you intentionally want to rebuild retrieval with a different provider.

```powershell
$BrainDir = "$env:USERPROFILE\Documents\Rta-Smriti\brains"
& $RtaBrain start C:\path\to\my-project --project my-project --brain-dir $BrainDir --write-agents
```

```bash
BrainDir="$HOME/.local/share/rta-smriti/brains"
"$RtaBrain" start /path/to/my-project --project my-project --brain-dir "$BrainDir" --write-agents
```

### Share What Happened

Tried Rta-Smriti on a real project? [Share your experience in Discussions](https://github.com/sulabhdubey/rta-smriti-brain/discussions), [ask for installation help](https://github.com/sulabhdubey/rta-smriti-brain/discussions/categories/q-a), or [pick a first contribution](https://github.com/sulabhdubey/rta-smriti-brain/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22). If it saved you from repeating project context, consider [starring the repository](https://github.com/sulabhdubey/rta-smriti-brain).

Verify that commands are operating on the intended checkout by passing its root:

```powershell
& $RtaBrain --db "$BrainDir\my-project.sqlite" --json self-check --project my-project --check-files --root C:\path\to\my-project
```

```bash
"$RtaBrain" --db "$BrainDir/my-project.sqlite" --json self-check --project my-project --check-files --root /path/to/my-project
```

If a project intentionally moves to another clone or worktree of the same repository, stop its watcher and continuity worker, create a no-clobber backup, rebind, then restart the workers. Rta-Smriti refuses cross-repository rebinding and rolls back the binding and index if reindexing fails:

```powershell
& $RtaBrain --db "$BrainDir\my-project.sqlite" watcher stop --project my-project
& $RtaBrain --db "$BrainDir\my-project.sqlite" continuity stop --project my-project
& $RtaBrain --db "$BrainDir\my-project.sqlite" --json root-rebind C:\new\checkout --project my-project --backup C:\backups\my-project-before-rebind.sqlite
```

Use `integrity-diagnostics --root <checkout>` for a bounded report safe to share: it contains fingerprints and counts, not raw project names or filesystem paths.

## Dashboard

The `start` command opens the managed console automatically. Later, use its lifecycle commands without keeping a terminal open:

```powershell
& $RtaBrain console open --brain-dir $BrainDir
& $RtaBrain console status --brain-dir $BrainDir --json
```

```bash
"$RtaBrain" console open --brain-dir "$BrainDir"
"$RtaBrain" console status --brain-dir "$BrainDir" --json
```

The managed console survives terminal closure. `console open` retrieves the current
session URL; `console restart` repairs stale state or a failed process; `console stop`
ends it explicitly. Login startup is optional and owner-controlled through
`console login-enable` / `console login-disable` on Windows, macOS, and Linux.

Use `--no-continuity` when onboarding a machine that does not use Codex local
sessions, or pass `--sessions-root` when Codex stores sessions somewhere else.

The dashboard runs on `127.0.0.1` and includes:

![Rta-Smriti v1 Project Reality cockpit with readiness, decision debt, coverage, and change impact](launch-assets/screenshots/operator-cognition-v1.0.2.png)

- **Project switcher**: every local brain, readiness, file count, memory count
- **Canonical-root and Git identity**: bound project root, repository root, branch, HEAD, dirty-file count, and duplicate-root warnings
- **File explorer**: browse the real indexed folder tree, preview source without exposing absolute paths, search files, and add a relevant path directly to the current task
- **Semantic brain graph**: the active project sits at the center of stable Files, Symbols, Imports, Memories, and Evidence hubs; compact leaves reveal labels on hover, focus, or selection
- **Graph navigation**: collapse semantic hubs, pan or zoom the workspace, use the overview minimap, and switch between Global, Local, and Task scopes
- **Spatial canvas**: arrange a temporary working set, inspect a card, reset the layout, and export it as JSON
- **Typed bases**: scan memories, symbols, imports, and launch checks as dense, filterable tables
- **Search nodes**: filter graph nodes by file, symbol, memory, or artifact text
- **Types**: show/hide file, memory, docs, config, test, data, and artifact nodes
- **Context-Pack Studio**: choose any supported or custom target agent, select a 2K/4K/8K/16K token budget, type a task, and generate a focused pack; pack text and receipt metadata remain in the current browser session only
- **Evidence inspector**: open the optional detail panel for the selected node, must-know memories, and measured fresh/changed/missing/added/blocked source counts
- **Truth Timeline**: inspect bitemporal claims, evidence links, contradictions, validator health, and recorded-versus-valid time without flattening history into mutable notes
- **Universal Capture**: review explicitly authorized agent-event sources, bounded normalized events, replay order, redaction state, queue health, retention previews, and daemon diagnostics; captured text remains untrusted until promoted with evidence
- **Project Reality**: inspect deterministic readiness, digital-twin reconciliation, knowledge coverage, decision debt, change impact, bounded conflicts, and governed local media evidence
- **Incremental refresh**: update the selected repo index from the freshness control; filesystem events force a bounded content-hash check for touched paths, while unchanged projects use a fast stat manifest
- **Indexing policy**: configure metadata-only or strict oversized-file handling, parser/LSP behavior, local thread compaction, and optional hybrid retrieval per project
- **References and backlinks**: inspect why a node is connected and follow its visible relationships
- **Action Gate**: evaluate a proposed action against trusted policies, required checks, expiry, scope, provenance, continuation readiness, Git state, and freshness; owner overrides create durable receipts
- **Intelligence**: explain retrieval with source hashes and selection reasons, then run bounded dependency, dependent, impact, evidence, or relevance queries
- **Workspaces**: group independent local brains and search them together without copying or rebinding their repositories
- **Memory ledger**: inspect stored memories, record helpful/harmful outcomes, and run conservative reflection
- **Continue Work**: edit the structured checkpoint and copy a ready-to-use prompt for a new agent task
- **Rta-Smriti Release**: source-checkout files and GitHub publication checks; it does not assess the selected private project
- **Task continuity**: start or stop project-bound Codex session capture and inspect its heartbeat, last capture, checkpoint, and error state
- **Bootstrap flow**: create a new project brain from the UI
- **Command palette**: copy common commands into your agent chat

## How To Use With An Agent

## v1 Project Reality CLI

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json cognition --project project-name --root C:\path\to\project
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json media list --project project-name
```

`cognition` reads one bounded, deterministic projection from the existing brain.
Routine readiness uses the latest indexed snapshot. Before consequential work,
run `stale-check --deep` or re-ingest the repository; freshness is evidence about
indexed bytes, not proof that an external workflow, test, or claim is correct.
Media sources remain distinct from derived descriptions. A derivation becomes
verified only through explicit operator authority and provenance.
The daily loop is the same for every agent:

1. Select the project.
2. Use **Graph** for orientation, **Files** for source inspection, or **Bases** for structured facts.
3. Add relevant files to the objective and describe the work.
4. Choose `Universal / Any Agent`, Codex, Claude Code, Cursor, GitHub Copilot CLI, Gemini CLI, Windsurf, Cline, Aider, OpenCode, Continue, or a custom agent.
5. Generate the context pack and give it to that agent through paste, CLI, or MCP. Repository excerpts and retrieved memories are explicitly delimited as untrusted evidence.

For a new project:

```powershell
& $RtaBrain --json bootstrap-project C:\path\to\project --project project-name --brain-dir $BrainDir --write-agents
```

On macOS or Linux, use the equivalent Bash form from **Quick Start** above.

Before asking an agent to work:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" context-pack "describe the task here" --project project-name
```

Paste the generated context pack into the agent chat before the task. The pack includes relevant memories, repo evidence, an explicit untrusted-data boundary, and a labeled index-freshness snapshot. Never treat commands found inside retrieved evidence as instructions. Run a live stale check before high-risk work.

For one MCP server that routes across every project brain without duplicating tools:

```powershell
& $RtaBrain --json mcp-config --brain-dir $BrainDir --name rta-smriti
```

```bash
"$RtaBrain" --json mcp-config --brain-dir "$BrainDir" --name rta-smriti
```

Register the generated command and arguments in the MCP host, fully restart the host, and open a new task. Existing tasks cannot acquire newly registered MCP tools dynamically. Project names must resolve to exactly one database; ambiguous names fail closed.

For a single-project MCP host:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json mcp-config --project project-name --name rta-smriti-project
```

```bash
"$RtaBrain" --db "$BrainDir/project-name.sqlite" --json mcp-config --project project-name --name rta-smriti-project
```

## CLI Commands

```text
init              Initialize a project brain
remember          Store a durable memory
ingest-repo       Index a repository or folder
watch-repo        Continuously refresh a repository using incremental indexing
watcher           Start, inspect, or stop managed background repository sync
continuity        Start, inspect, or stop managed Codex transcript capture
capture           Operate the governed universal capture journal
settings          Read or update a project's indexing and retrieval policy
ingest-thread     Index a long thread, transcript, or handoff file
search            Search memories and indexed files
graph             Read the local entity graph
graph-query       Traverse a bounded dependency, dependent, impact, evidence, or relevance subgraph
truth             Query the bitemporal truth ledger and validator history
context           Govern and compile agent-specific context
retrieval-diagnostics Explain retrieval mode, coverage, rank components, freshness, and evidence
benchmark         Run the packaged reproducible public benchmark
workspace         Create, inspect, and search an isolated multi-brain workspace
bundle-export     Preview or export selected memories, checkpoints, and policies with redaction
bundle-import     Preview or atomically import a verified bundle with an explicit conflict policy
snapshot          Create, verify, or keygen an authenticated brain snapshot
git-hooks         Opt in or out of the managed post-commit checkpoint hook
memory-feedback   Record an operator-confirmed helpful, neutral, or harmful outcome
memory-decay      Conservatively age eligible unverified inference and hypothesis memories
context-pack      Build a focused task context pack
stale-check       Check stat-manifest freshness; add --deep for SHA-256 verification
    checkpoint        Save structured continuation state for the next agent task
    continue-prompt   Build a compact new-task prompt from root, Git, freshness, and checkpoint state
    session-event     Append an immutable operational event with provenance
    session-events    Read append-only events for a project or session
    ingest-codex-session Incrementally capture a local Codex JSONL session
    work-item         Track an asset, job, QA result, retry, approval, fallback, or blocker
    reconcile         Compare structured work state with the bound filesystem
    operational-readiness Separate database health from safe task continuation
reflect           Consolidate duplicate memories and flag simple contradictions
mcp-config        Generate an MCP host config snippet
bootstrap-project Create a brain, index a repo, and optionally write agent instructions
start             Onboard a project and launch watcher plus managed console in one command
self-check        Verify that a project brain is ready
projects-list     List projects registered in a brain database
install-local     Install native Windows or POSIX command wrappers
doctor            Verify local brain health
dashboard         Run the local operator console
console           Start, open, inspect, restart, stop, or configure login startup
publish-readiness Check whether the package is ready to publish
```

Continuity capture uses a 30-day session lookback on first start so a new brain does not silently import an entire Codex history. Oversized new or resumed session backlogs retain a 2 MB recent tail, record an explicit `history_truncated` event, and then capture all new events. Pass `--lookback-days 0` only when you intentionally want every matching historical session; adjust the recovery bound with `--backlog-tail-mb`. Status reports the remaining session backlog, and continuation readiness stays fail-closed while capture is behind or has errors.

## MCP Server

Rta-Smriti ships a stdio MCP server. Run `mcp-config` as shown above to generate
the correct absolute `command` and `args` for the current operating system and
Python environment; do not hand-edit a Windows path into a macOS or Linux host.

The generated server is project-bound and read-only by default. Memory writes,
canonical-repository ingestion, and thread ingestion require explicit startup
capabilities: `--allow-memory-writes`, `--allow-repo-ingestion`, and
`--allow-thread-ingestion`. Starting or stopping the continuity worker is a
separate process-control grant, `--allow-continuity-control`. Thread ingestion also requires one or more
`--allow-thread-root` values; the selected file is consumed through the same
descriptor-bound root check. Agent-authored memories are always stored as
unverified `anumana` with confidence capped at `0.75`. Owner-only governance
mutation, required-check attestation, and overrides are never exposed to MCP.
Single-project configuration is emitted only for an exact, healthy canonical
binding and always pins `--root`. A live stdio server holds a local process
lease, so `root-rebind` refuses to move its project until the MCP host stops.

Tools exposed:

- `brain_search`
- `brain_context_pack`
- `brain_context_compile`
- `brain_context_explain`
- `brain_remember`
- `brain_remember_batch`
- `brain_ingest_repo`
- `brain_ingest_thread`
- `brain_repo_map`
- `brain_graph_query`
- `brain_retrieval_diagnostics`
- `brain_workspace_list`
- `brain_workspace_search`
- `brain_stale_check`
- `brain_checkpoint`
- `brain_continuation_prompt`
- `brain_session_event`
- `brain_session_events`
- `brain_ingest_codex_session`
- `brain_work_item`
- `brain_reconcile`
- `brain_operational_readiness`
- `brain_continuity_status`
- `brain_continuity_control`
- `brain_reflect`
- `brain_policy_add` (owner-only)
- `brain_policy_list`
- `brain_policy_retire` (owner-only)
- `brain_preflight` (agents cannot attest checks or override)
- `brain_governance_receipts`
- `brain_doctor`

`brain_context_compile` and `brain_context_explain` are fail-closed MCP tools.
They are exposed only when the operator starts a single-project MCP server with
`--context-contract ID:DIGEST` for an authorized task contract. A plain
generated MCP configuration keeps search, context packs, repository maps, and
truth reads available without granting governed compilation rights.

## Real-World Use Cases

- **Agent handoff**: move from Codex to Claude Code or Cursor without retelling the architecture, constraints, and current objective.
- **Long-thread recovery**: preserve decisions and evidence before a chat compacts or a session ends.
- **Repository onboarding**: give a developer or agent a focused map of unfamiliar files, symbols, imports, and project rules.
- **Debugging and incidents**: assemble the relevant code, prior fixes, risks, and evidence for one fault instead of scanning the whole repo.
- **Refactors and migrations**: trace dependencies and retain the decisions that explain why boundaries exist.
- **Release and security reviews**: pair live freshness checks with trusted constraints, evidence, and publish readiness.
- **Multi-project operation**: switch between separate local brains without mixing one client, product, or codebase into another.
- **Cross-repository change planning**: search an explicit workspace and inspect bounded impact links before touching a shared contract.
- **Governed agent work**: stop a release, migration, or fragile-path change when required evidence is missing, while keeping overrides visible and attributable.
- **Research and product work**: keep source-backed findings, hypotheses, and decisions distinguishable through pramana labels.

The generated MCP configuration uses the active Python interpreter plus the
installed `rta_brain.mcp_server` module, so paths with spaces and clean wheel
installs are handled without relying on a global command.

## Privacy And Security

Rta-Smriti is local-first by design:

- It does not require API keys.
- It does not send repo content to a hosted service.
- It stores project memory in local SQLite files.
- Brain databases reject linked files, use private POSIX modes where applicable, and disable SQLite trusted schema while retaining FTS5.
- It stores canvas layouts and the selected agent in browser local storage. Context-pack text and receipt metadata are session-only.
- Its dashboard uses a per-launch capability token and rejects non-loopback binding, hostile Host headers, cross-port origins, hard-linked files, and database paths outside the configured brain directory.
- It ignores common noisy folders such as `.git`, `node_modules`, `.venv`, `dist`, `build`, `.next`, and cache directories.
- You should not commit `.rta-smriti/`, `*.sqlite`, logs, private thread exports, or generated local brain files.

See [SECURITY.md](SECURITY.md) and [docs/PUBLISHING_PRIVACY.md](docs/PUBLISHING_PRIVACY.md).

## Current Maturity

Alpha, local-first, working developer tool.

Verified by the current public prerelease and hosted CI matrix:

- Python CLI
- SQLite schema and FTS search
- repo ingestion
- thread ingestion
- context-pack generation
- MCP stdio server
- React dashboard
- local publish-readiness checks
- incremental foreground and managed-background repository sync with SHA-256 cache
- optional local hybrid retrieval
- parser adapter registry with regex, Tree-sitter, LSP, and entry-point extension paths
- metadata-only oversized-source isolation with an explicit strict-block mode
- canonical-root protection and Git checkout awareness
- structured checkpoints, claim provenance, and compact freshness receipts
- managed Codex continuity capture with resumable cursors, redaction, backlog bounds, and conservative interruption checkpoints
- structured work-state reconciliation for assets, jobs, approvals, blockers, QA decisions, fallbacks, and next actions
- operational readiness that separates database health from continuation readiness
- multi-project MCP gateway with fail-closed project selection
- managed console lifecycle, optional login startup, and one-command onboarding
- evidence-aware Action Gate with hash-backed policies and short-lived decision receipts
- retrieval diagnostics, bounded graph queries, and a packaged privacy-safe benchmark harness
- isolated cross-brain workspaces, redacted selective bundles, and authenticated local snapshots
- opt-in Git checkpoint hooks plus operator-confirmed reinforcement and conservative decay

Intentional design constraints:

- Project brains stay in local SQLite files. There is no cloud sync or hosted account system.
- The dashboard is loopback-only. Remote and LAN hosting are deliberately rejected.
- Retrieval and reflection are inspectable and deterministic by default. The main bootstrap flow selects the dependency-free local hash provider by default and operators can choose lexical-only or an installed Sentence Transformers model; reflection remains conservative rather than a full semantic judge.
- Eligible source files above the 512 KB content cap are tracked by path, size, and modification time as `metadata_only` by default. Their content is never represented as indexed or verified. Operators can select strict-block mode or raise the cap to 16 MB.

Advanced modes and safety boundaries:

- Managed sync, continuity, and console processes are user-level local processes. Login startup is opt-in because Rta-Smriti does not install privileged services. Windows startup uses a hidden direct-process launcher and re-enabling it migrates the legacy visible `.cmd` entry.
- Hybrid retrieval works dependency-free through the built-in hash provider. Sentence Transformers remains an explicit local extra for operators who want model-backed comparison.
- Standard installs and standalone binaries include Tree-sitter grammars for Python, JavaScript, TypeScript/TSX, Go, Rust, and Java, with deterministic regex fallback for unsupported syntax.
- LSP mode can discover `pyright-langserver`, `basedpyright-langserver`, `gopls`, `typescript-language-server`, or `rust-analyzer` from the operator PATH. Execution is opt-in, bounded, never uses a shell, and rejects project-local discovered executables; the legacy explicit JSON adapter remains available.
- Repository ingestion warms the persistent SHA-256 cache while content is already being read. A following deep verification reuses unchanged hashes; only a legacy/cold cache or changed file requires another content read.
- Standard installs and standalone binaries include Watchdog filesystem events. The emergency polling fallback hashes on cadence, backs off on repositories with 10,000 or more indexed files, and forces periodic deep verification, so same-stat changes may be detected later when events are unavailable.
- The per-file content cap is configurable up to 16 MB. Metadata-only sources produce `fresh_with_warnings`; strict mode keeps the previous fail-closed behavior.
- Call edges are deterministic impact hints, not compiler-perfect call graphs. Use them to find likely blast radius, then verify consequential changes against source and tests.
- Standard installs include Ed25519 public-key signatures. Compatible HMAC-SHA256 snapshots remain available, while encrypted snapshots use scrypt plus AES-256-GCM and may also carry an Ed25519 signature. Private snapshots and keys are never safe public exports.
- Optional Ollama compaction is restricted to an HTTP(S) loopback endpoint, redacts common secrets and home paths, bounds request/response sizes and time, preserves the append-only event record, and labels every derived summary unverified.
- Snapshot verification accepts at most a 64 MiB SQLite payload; legacy snapshot envelopes are capped at 16 MiB. Selective bundle inputs are capped at 25 MB and consumed through stable bounded reads.
- The public benchmark can emit JSON or a shareable Markdown report. It is a small synthetic reproducibility and regression harness, not external proof of superiority over other memory systems.

See [ROADMAP.md](ROADMAP.md) for planned improvements. Local-first operation and inspectable evidence remain non-negotiable.

### Optional Indexing Policy

```powershell
# Enable dependency-free local hybrid retrieval and raise the source cap to 1 MB.
& $RtaBrain --db .\.rta-smriti\brain.sqlite --json settings --project demo --embedding-provider hash --max-file-mb 1

# Keep an active project incrementally refreshed until Ctrl+C.
& $RtaBrain --db .\.rta-smriti\brain.sqlite watch-repo . --project demo --interval 2

# Or run the same incremental refresh as a managed background process.
& $RtaBrain --db .\.rta-smriti\brain.sqlite watcher start . --project demo --interval 2
& $RtaBrain --db .\.rta-smriti\brain.sqlite --json watcher status --project demo
& $RtaBrain --db .\.rta-smriti\brain.sqlite watcher stop --project demo

# Auto mode uses the Tree-sitter grammars included by the standard install.
& $RtaBrain --db .\.rta-smriti\brain.sqlite --json settings --project demo --parser-adapter auto

# Track oversized sources by metadata without claiming their content is indexed (default),
# or opt back into strict blocking.
& $RtaBrain --db .\.rta-smriti\brain.sqlite --json settings --project demo --large-file-policy metadata

# Discover a supported language server already installed on the operator PATH.
& $RtaBrain --db .\.rta-smriti\brain.sqlite --json settings --project demo --parser-adapter lsp --lsp-auto-discovery

# Optional local-only transcript compaction through Ollama.
& $RtaBrain --db .\.rta-smriti\brain.sqlite --json settings --project demo --compaction-provider ollama --compaction-model qwen3:0.6b

# Or install both optional local backends.
python -m pip install -e ".[all-local]"

# Ed25519 snapshot signing is included in the standard install.
```

## Development

Dashboard source lives in `dashboard-src/`. Runtime users do not need Node because built static files are packaged in `rta_brain/static/`.

Routine context packs use the latest completed index snapshot so even very large brains stay responsive. Before a release or security-critical decision, run:

```powershell
& $RtaBrain --db <project-brain.sqlite> --json stale-check --project <project-name> --deep
```

```powershell
npm install
npm run test:unit
npm run build
python scripts/build_installed_smoke.py
npx playwright install chromium
npm run test:operator
python scripts/performance_probe.py --profiles 100 1000 --assert-bounds
python -m pip install ".[binary]"
python scripts/build_binary.py
python -m unittest discover -s tests -v
python -m compileall -q rta_brain tests scripts
pip install -e . --dry-run --no-deps
python rta-brain.py publish-readiness --json
```

The rendered acceptance suite uses a disposable Git repository and brain, never a developer's
existing projects. GitHub CI runs it on Windows, macOS, and Linux for Python 3.11. See
[Operator QA](docs/OPERATOR_QA.md), [Performance Evidence](docs/PERFORMANCE.md), and the
[Release Completion Audit](docs/RELEASE_COMPLETION_AUDIT.md).

## Positioning

**One-liner:** Local project memory and context packs for AI coding agents.

**Short description:** Rta-Smriti Brain gives each software project a private local memory graph so coding agents can start with the right repo context, decisions, constraints, and evidence instead of asking you to explain everything again.

**Tagline:** Stop re-explaining your project to every new AI chat.

## License

MIT. See [LICENSE](LICENSE).
