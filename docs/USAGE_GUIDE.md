# Rta-Smriti Brain Usage Guide

## Project Reality In v1

Project Reality answers a narrower and more useful question than “is the
database healthy?”: does the brain contain enough current, reconciled, and
appropriately trusted evidence for another operator or agent to continue?

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json cognition --project project-name --root C:\path\to\project
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json media list --project project-name
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json media add C:\path\to\evidence.png --project project-name
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json media verify MEDIA_ID --project project-name --authority operator --evidence "reviewed against source"
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json media export --project project-name
```

The dashboard’s **Project Reality** view shows readiness, Project Twin,
knowledge coverage, decision debt, change impact, conflicts, and media evidence.
Counts distinguish total records from displayed records, and every bounded list
states when it was truncated. Routine cognition uses the latest completed index;
run `stale-check --deep` before release, security, migration, or other
consequential work. A fresh index does not prove tests passed or an external job
completed.
This guide explains how to use Rta-Smriti Brain across multiple local software projects.

## The Simple Idea

Each project gets its own local brain database.

That brain remembers:

- important decisions
- project rules
- repo files and symbols
- long thread handoffs
- stale or changed files
- context that the next AI agent should know

When you start a new Codex, Claude Code, Cursor, or other agent chat, ask Rta-Smriti for a context pack and paste it into the chat before the task.

## Install The Local Launcher

From a cloned Rta-Smriti repository, run the command for your operating system.

Windows PowerShell:

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install .
$RtaBrain = Join-Path $PWD ".venv\Scripts\rta-brain.exe"
& $RtaBrain --json doctor
```

Use `& $RtaBrain` for the examples in this guide. Pip generates the launcher
from package metadata, so no source wrapper or global `PATH` is required.

macOS or Linux:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install .
RtaBrain="$PWD/.venv/bin/rta-brain"
"$RtaBrain" --json doctor
```

Use `"$RtaBrain"` for the Bash/Zsh examples. See the complete
[installation guide](INSTALLATION.md) for prerequisites, PATH setup,
troubleshooting, and uninstall instructions.

## Recommended Folder Layout

Use one central folder for all project brains:

```powershell
$env:USERPROFILE\Documents\Rta-Smriti\brains
```

```bash
$HOME/.local/share/rta-smriti/brains
```

Each project brain becomes one SQLite file:

```text
brains/
  app-one.sqlite
  backend-service.sqlite
  docs-site.sqlite
```

Do not commit this folder to GitHub.

## Bootstrap A Project

Run once per project:

```powershell
& $RtaBrain --json bootstrap-project C:\path\to\project --project project-name --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains" --write-agents
```

```bash
BrainDir="$HOME/.local/share/rta-smriti/brains"
"$RtaBrain" --json bootstrap-project /path/to/project --project project-name --brain-dir "$BrainDir" --write-agents
```

This creates:

- a SQLite brain database
- indexed repo evidence
- a project record
- optional `AGENTS.rta-smriti.md` instructions in that project

## Check A Project Brain

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json self-check --project project-name --check-files --root C:\path\to\project
```

```bash
"$RtaBrain" --db "$BrainDir/project-name.sqlite" --json self-check --project project-name --check-files --root /path/to/project
```

Look for:

- `ready: true`
- file counts greater than zero
- memories greater than zero, if you have added decisions
- low or zero stale files
- `integrity.binding.state: exact`
- `integrity.duplicate_root_count: 0`

## Move A Brain To Another Checkout

A clone or Git worktree is a distinct checkout even when it has the same repository history. Rta-Smriti never silently switches between them.

Stop the managed workers and any agent host using this project's single-project MCP server, then create a separate SQLite backup through the explicit migration command:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" watcher stop --project project-name
& $RtaBrain --db "$BrainDir\project-name.sqlite" continuity stop --project project-name
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json root-rebind C:\new\project --project project-name --backup C:\backups\project-name-before-rebind.sqlite
```

```bash
"$RtaBrain" --db "$BrainDir/project-name.sqlite" watcher stop --project project-name
"$RtaBrain" --db "$BrainDir/project-name.sqlite" continuity stop --project project-name
"$RtaBrain" --db "$BrainDir/project-name.sqlite" --json root-rebind /new/project --project project-name --backup "$HOME/backups/project-name-before-rebind.sqlite"
```

The destination must be the same verified repository lineage, the backup path must not already exist, and any failed reindex leaves the original binding and index intact. A missing old folder never authorizes an implicit move. Active watcher, continuity, or MCP ownership blocks migration. Restart those processes only after `integrity-diagnostics --root <new-checkout>` reports `operationally_ready: true`.

## Generate Context Before A Task

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" context-pack "describe the task here" --project project-name --max-tokens 4000
```

```bash
"$RtaBrain" --db "$BrainDir/project-name.sqlite" context-pack "describe the task here" --project project-name --max-tokens 4000
```

Paste the output into the agent chat, then ask the agent to do the task.

Good task examples:

```text
fix the checkout validation bug
prepare this repo for GitHub launch
review auth boundaries before changing user roles
continue the release hardening work from the previous thread
```

### Compile A Governed Agent Context

The legacy `context-pack` command is the quick copy-and-paste path. Use the
`context` command family when the task needs an explicit agent profile, immutable
acceptance and stop conditions, privacy scope, comparison variants, revocation,
and durable explanation receipts.

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json context authority-status
& $RtaBrain --db "$BrainDir\project-name.sqlite" context profile-register --help
& $RtaBrain --db "$BrainDir\project-name.sqlite" context contract-authorize --help
& $RtaBrain --db "$BrainDir\project-name.sqlite" context compile --help
& $RtaBrain --db "$BrainDir\project-name.sqlite" context explain --help
```

```bash
"$RtaBrain" --db "$BrainDir/project-name.sqlite" --json context authority-status
"$RtaBrain" --db "$BrainDir/project-name.sqlite" context profile-register --help
"$RtaBrain" --db "$BrainDir/project-name.sqlite" context contract-authorize --help
"$RtaBrain" --db "$BrainDir/project-name.sqlite" context compile --help
"$RtaBrain" --db "$BrainDir/project-name.sqlite" context explain --help
```

Profile and contract inputs are bounded JSON files read through stable unlinked
descriptors. Authorization is an operator action. Compilation and explanation are
bound to the named agent principal and session; capability secrets never appear in
normal JSON output. Use `context audit` for metadata-only operator receipts,
`context outcome` for an explicitly confirmed result, and `context revoke` to
invalidate the exact compilation grant. These commands prepare and explain
context; they do not execute the task.

## Use The Dashboard

For the first use, onboard the project and open the console in one command:

```powershell
& $RtaBrain start C:\path\to\project --project project-name --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains" --write-agents
```

```bash
"$RtaBrain" start /path/to/project --project project-name --brain-dir "$BrainDir" --write-agents
```

The command detects the canonical Git root, creates or migrates the project brain,
indexes it, starts managed repository sync, starts Codex task-continuity capture
when a local Codex sessions folder exists, starts the managed console, then opens
an authorized browser. It is safe to rerun. Later use `console open`; the console,
watcher, and continuity capture survive terminal closure.

```powershell
& $RtaBrain console status --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains" --json
& $RtaBrain console open --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains"
& $RtaBrain console restart --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains"
& $RtaBrain console stop --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains"
```

Login startup is optional, user-level, and reversible:

```powershell
& $RtaBrain console login-enable --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains"
& $RtaBrain console login-status --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains" --json
& $RtaBrain console login-disable --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains"
```

### The Daily Five-Step Loop

1. Open **Projects** and select the project you are working on.
2. Orient yourself in **Graph**, then inspect exact source in **Files** or structured facts in **Bases**.
3. In **Context-Pack Studio**, describe one concrete task. Use `Add to Task` in a file preview when a path matters.
4. Choose the target agent. `Universal / Any Agent` is the safest default; named and custom agents add a clear handoff label to the pack and receipt.
5. Generate the pack, copy it, and place it at the start of the agent chat. MCP-capable hosts can call the brain tools directly instead.

Before ending a meaningful session, open **Continue Work** and record the objective, verified evidence, remaining gaps, safest next action, and exploration that should not be repeated. Save the checkpoint, then use **Copy New Task Prompt** when opening the next agent task.

For Codex, the `start` command enables **Settings > Task continuity** automatically
when it can see the local sessions folder. Use `--no-continuity` to skip this, or
`--sessions-root` if Codex stores sessions somewhere else. The capture service only
imports sessions whose declared working directory belongs to that canonical
project, resumes after partial writes, redacts common credential shapes, and marks
automatic checkpoints as unverified until a human or agent reconciles them.

Graph is the map, Files is the source reader, Canvas is the working board, Bases is the structured database, and the Context-Pack Studio is the handoff point.

### Connect An MCP-Capable Agent

Generate host configuration with the installed command rather than composing an
OS-specific executable path by hand:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json mcp-config --project project-name --name rta-smriti-project
```

Add the returned `mcpServers` entry to the agent host. It is bound to one project
and read-only by default. To grant an advanced capability, append only the
required server argument to the generated `args`: `--allow-memory-writes`,
`--allow-repo-ingestion`, `--allow-continuity-control`, or
`--allow-thread-ingestion` together with one or
more `--allow-thread-root <absolute-path>` pairs. Repository ingestion still
uses the brain's registered canonical root. Thread files are confined to the
declared roots. Agent-authored memory remains unverified `anumana` with
confidence capped at `0.75`; agents cannot create or retire governance policy,
attest required checks, or override a block.

Configuration generation fails closed unless the stored root, repository
identity, and checkout identity are currently exact. The generated command
always includes `--root`. Stop the MCP host before `root-rebind`; a live server
holds a local lease specifically to prevent checkout changes during tool calls.

Probe the exact generated server before editing the host configuration:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" --json mcp-doctor --project project-name
```

```bash
"$RtaBrain" --db "$BrainDir/project-name.sqlite" --json mcp-doctor --project project-name
```

A `ready` result proves initialize, tools/list, and ping worked for that command.
Copy the returned config into the host, then start a fresh agent task. Existing
tasks cannot dynamically acquire newly registered MCP tools.

Governed context compilation is a narrower, fail-closed delegation. After the
operator authorizes a task contract, append its exact positive ID and SHA-256
digest to a **single-project** server's generated `args`:

```text
--context-contract ID:DIGEST
```

The argument may be repeated for multiple explicitly authorized contracts.
Without it, `brain_context_compile` and `brain_context_explain` are absent from
the server's tool list; clients cannot enumerate contract IDs. The server
rechecks the delegated digest against the selected project's stored contract on
every compile or explanation request. Multi-project gateways do not accept
contract delegations.

### Use Multi-Project Workspaces

Create a workspace in one owner brain, then add independently indexed project
brains. The databases remain separate.

```powershell
& $RtaBrain --db "$BrainDir\app.sqlite" workspace create --name product --json
& $RtaBrain --db "$BrainDir\app.sqlite" workspace add --name product --project app --json
& $RtaBrain --db "$BrainDir\app.sqlite" workspace add --name product --project api --member-db "$BrainDir\api.sqlite" --role backend --json
& $RtaBrain --db "$BrainDir\app.sqlite" workspace health --name product --json
& $RtaBrain --db "$BrainDir\app.sqlite" workspace search --name product --query "release contract" --json
```

Search returns healthy-project results even when one member is unavailable and
marks the response `degraded`. Removing a member or deleting a workspace changes
only workspace metadata; it never deletes a project brain.

### Create An Encrypted Snapshot

Generate a private 256-bit passphrase file outside the repository, keep it
separate from the snapshot. Cryptography and Ed25519 support ship with the
standard install. Generation refuses to replace an existing file.

```powershell
& $RtaBrain snapshot passphrase-keygen "$BrainDir\project-name.snapshot.passphrase" --json
& $RtaBrain --db "$BrainDir\project-name.sqlite" snapshot encrypt "$BrainDir\project-name.rtae" --passphrase "$BrainDir\project-name.snapshot.passphrase" --json
& $RtaBrain snapshot verify-encrypted "$BrainDir\project-name.rtae" --passphrase "$BrainDir\project-name.snapshot.passphrase" --json
& $RtaBrain snapshot restore "$BrainDir\project-name.rtae" --passphrase "$BrainDir\project-name.snapshot.passphrase" --output-db "$BrainDir\project-name-restored.sqlite" --json
```

The dashboard Vault provides the same explicit key-generation action. Restore
refuses to replace an existing database. It authenticates the encrypted
payload, verifies its SHA-256 digest and SQLite integrity, then atomically writes
the new brain.

### Compare Benchmark Runs

```powershell
& $RtaBrain benchmark --history "$BrainDir\public.benchmark-history.jsonl" --label before --report benchmark.md --json
```

Each run appends one bounded private-safe record. From the second run onward, the
Markdown report includes latest-versus-previous metric deltas. This synthetic
harness is regression evidence, not a superiority claim.

### What The Dashboard Shows

**Projects**

Every brain found in your brain folder. The switcher shows readiness, file count, memory count, Git branch and HEAD, and the project path without mixing data between projects. A yellow state warns when the same project name is bound to multiple folders; verify the canonical checkout before using that brain.

**Files**

The actual indexed project tree. Open folders, search by relative path, preview indexed source, copy a safe relative path, or add that file to the current task. Absolute local paths are not shown in previews.

**Brain Graph**

A semantic map of the active project. The center is the project brain; stable hubs group Files, Symbols, Imports, Memories, and Evidence. Hover or focus a compact leaf to read it, click a hub to collapse or expand it, and use pan, zoom, reset, or the minimap to navigate. Brighter links are repository evidence; faint dashed links only explain the visual grouping. Switch between Global, Local, and Task scopes to change the working set.

**Canvas**

A draggable working board for arranging the current evidence set. Double-click a card to inspect it, reset the layout when needed, and export the arrangement as JSON.

**Bases, Symbols, Imports, And Memories**

Filterable table views for facts that are easier to scan as rows than as a graph. The dedicated left-navigation items open the relevant base directly.

**Search Nodes**

Searches graph nodes so you can quickly find a file, memory, symbol, or generated context pack.

**Types**

Filters the graph by node type.

**Settings**

Controls the active project's indexing policy, repository watcher, and task-continuity service. Auto parsing uses bundled Tree-sitter grammars when supported and safely falls back to built-in regex. You can select regex explicitly, opt into a detected local language server, choose metadata-only or strict oversized-file handling, change hybrid retrieval, or enable loopback-only Ollama compaction. External providers are never installed automatically.

**Context-Pack Studio**

The main daily workflow. Choose `Universal / Any Agent`, a named agent, or a custom agent. Select a 2K, 4K, 8K, or 16K context budget, type the task, click `Generate Context Pack`, then copy the pack into the agent chat. Direct evidence is considered before lower-trust historical memory, and omitted material is declared. Each generation creates privacy-safe receipt metadata; the full pack stays available only in the current browser session.

**Evidence Inspector**

Open the detail-panel button in the graph toolbar to see what is selected, must-know memories, measured freshness counts, canonical root, Git branch, HEAD, dirty-file count, repo tree hints, and publish readiness. `Metadata only` means an oversized eligible source is tracked without reading or representing its content. `Blocked` is reserved for strict-policy or unsafe sources that could not be inspected. Use the refresh action to incrementally update the selected repo index.

**References**

Shows visible connections and backlinks for the selected graph node.

**Action Gate**

Checks a proposed action against typed constraints, failed approaches, fragile paths, required checks, and prohibited repetition. It shows why the result is `allow`, `warn`, or `block`, including policy scope, expiry, pramana, verification, and source hash. Only an owner can create or retire policies or override a block; every override creates a durable receipt.

Dashboard evaluations also include operational context: continuation readiness, Git dirty-file count, and index freshness. This makes consequential actions such as publish, deploy, commit, migration, or deletion warn before an agent acts on stale or incomplete project state.

**Intelligence**

Explains the active retrieval mode, provider, embedding coverage, parser fallback, freshness, rank components, latency, source hashes, and plain-language selection reasons for each returned file. Its graph query follows bounded dependencies, dependents, impact, evidence, or relevance links and labels approximate relationships with confidence.

**Workspaces**

Creates an explicit local group of independent project brains. Add only the projects you intend to search together. Each project retains its own database, canonical root, and memories; workspace search returns grouped results rather than merging stores.

**Memory Ledger**

Shows remembered decisions, their verification provenance when recorded, and lets you run reflection to suppress duplicate memories or flag simple contradictions.

**Continue Work**

Stores objective, verified evidence, remaining gaps, next action, and prohibited repetition as structured SQLite fields. The newest checkpoint leads future context packs and the one-click new-task prompt. Every save carries an optimistic version, so a stale agent is warned instead of overwriting newer state.

**Rta-Smriti Release**

Checks whether the Rta-Smriti tool checkout itself has the public files needed for a GitHub release. It is maintainer tooling, not a judgment that the selected user project is ready to launch.

**Bootstrap Brain**

Creates a new project brain from the UI.

**Command Palette**

Copies common commands so you do not have to remember syntax.

## Real-World Use Cases

**Continue after context compaction**

Ingest a long thread or handoff, then generate a focused pack for the next chat. The next agent receives decisions and evidence without receiving the entire transcript.

**Switch agents without starting over**

Generate one universal pack or label it for Codex, Claude Code, Cursor, GitHub Copilot CLI, Gemini CLI, or another agent. The brain stays agent-neutral; the target is handoff metadata, not a lock-in.

**Understand an unfamiliar repository**

Use Graph to see structure, Files to inspect source, Symbols and Imports to scan implementation boundaries, and Bases to compare structured records.

**Debug a specific problem**

Name the failure in the objective, add the relevant files, and generate a narrow pack containing matching code evidence plus prior constraints and fixes.

**Prepare a release or security review**

Run live or deep freshness checks, inspect evidence and launch readiness, and hand the resulting context to the reviewing agent.

**Operate several products privately**

Keep one SQLite brain per project. The dashboard switches between them while all repo content, memories, canvas layouts, and receipts remain local.

## Cross-Project Acceptance Check

You do not need to run a test before normal daily use. Before publishing the tool or after changing its indexing code, validate at least one tiny, one medium, and one large repository:

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json self-check --project project-name --check-files
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" context-pack "explain the architecture and safest next step" --project project-name
```

Confirm that the project is ready, Files opens, a preview can be added to the task, the selected target agent appears on the receipt, and the generated pack contains only that project's evidence.

## Add A Memory Manually

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" remember "Payments must fail closed when verification is missing." --project project-name --type constraint --pramana sabda --priority 9
```

Use memory types like:

- `decision`
- `constraint`
- `procedure`
- `fact`
- `risk`
- `idea`

Use pramana labels:

- `pratyaksha`: directly observed
- `sabda`: trusted instruction or docs
- `anumana`: inference
- `smriti`: prior memory
- `kalpana`: hypothesis

## Ingest A Long Thread Or Handoff

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json ingest-thread C:\path\to\handoff.md --project project-name --title "release handoff"
```

Use this after a long agent session so the next chat can recover the useful decisions and evidence.

## Refresh Repo Evidence

After significant code changes:

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json ingest-repo C:\path\to\project --project project-name
```

Then:

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json stale-check --project project-name
```

Use `--deep` for SHA-256 freshness with stat-keyed cache reuse. Fresh file rows are summarized by default so the receipt stays compact; add `--details --detail-limit 100` only when individual fresh rows are needed. Use `ingest-repo --force` when you need to re-read and re-index every eligible source regardless of cached metadata.

## Save A Continuation Checkpoint

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json checkpoint --project project-name --objective "Finish root protection" --verified-evidence "Regression test passes" --remaining-gaps "Dashboard review" --next-action "Run UI smoke" --prohibited-repetition "Do not rescan unrelated folders"
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" continue-prompt --project project-name
```

The equivalent macOS/Linux commands use `"$RtaBrain"` and `$BrainDir/project-name.sqlite` as shown earlier.

## Run Managed Task Continuity

Start once per active project after bootstrap:

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" continuity start --project project-name
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json continuity status --project project-name
```

The service considers sessions changed in the last 30 days. Oversized new or resumed backlogs retain a recent 2 MB tail and write an explicit `history_truncated` event before capturing every subsequent append. A project is not continuation-ready while `sessions_pending` is nonzero or capture errors exist. Stop it before moving or deleting the brain:

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" continuity stop --project project-name
```

For one native MCP registration across every brain, generate the gateway configuration:

```powershell
& $RtaBrain mcp-config --brain-dir "$env:USERPROFILE\Documents\Rta-Smriti\brains" --name rta-smriti
```

Add the emitted configuration to the MCP host and start a new agent task. Existing tasks cannot dynamically acquire newly registered MCP tools. In multi-project mode every tool call must name a project, duplicate project names fail closed, and only project-scoped read tools are exposed. Memories, checkpoints, ingestion, governance, continuity, temporal truth, capture mutation, and hash-cache refresh require a separately configured single-project MCP binding with explicit capabilities.

## Attach Claim Provenance

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json remember "Checkout verification fails closed." --project project-name --type evidence --pramana pratyaksha --source-path tests/test_checkout.py --source-hash abc123 --verification-command "python -m unittest tests.test_checkout" --verification-status verified
```

Verification status can be `unverified`, `verified`, `failed`, or `stale`. Rta-Smriti records the verification timestamp automatically unless one is supplied.

Keep a repository refreshed while you work:

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" watch-repo C:\path\to\project --project project-name --interval 2
```

This watcher stays in the foreground and stops cleanly with `Ctrl+C`. For managed background sync, use **Settings > Repository sync** in the dashboard or:

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" watcher start C:\path\to\project --project project-name --interval 2
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json watcher status --project project-name
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" watcher stop --project project-name
```

The managed worker survives terminal and dashboard closure. It is not a privileged operating-system service. Login startup remains disabled unless the owner explicitly enables it. Standard installs and standalone binaries include Watchdog event-driven updates. Event-driven workers content-hash touched paths even when metadata is unchanged. If the event backend cannot start, portable polling remains available, backs off automatically for repositories with 10,000 or more indexed files, and forces a full content verification at least every five minutes.

## Configure Retrieval And Parsing

The recommended bootstrap defaults are bundled Tree-sitter-with-regex-fallback parsing, FTS5 plus dependency-free hash hybrid retrieval, a 512 KB content cap, and metadata-only tracking for larger eligible files. A raw `init` remains lexical-only until configured. Read the active policy:

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json settings --project project-name
```

Enable the dependency-free local hash provider and a 1 MB source cap:

```powershell
& $RtaBrain --db "$env:USERPROFILE\Documents\Rta-Smriti\brains\project-name.sqlite" --json settings --project project-name --embedding-provider hash --max-file-mb 1
```

Changing an indexing policy invalidates the fast manifest. Run `ingest-repo` or use the dashboard refresh action to rebuild affected records. Sources above the selected cap remain visible as `metadata_only` warnings by default; select `--large-file-policy block` for the older strict behavior.

Tree-sitter is included. Install a model-backed retrieval option only when you need it:

```powershell
python -m pip install -e ".[embeddings]"
```

Use a supported language server already present on the operator PATH without
writing an adapter command:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" settings --project project-name --parser-adapter lsp --lsp-auto-discovery --json
```

Only enable LSP mode for operator-installed language servers you trust. Language servers can read
repository files and project configuration. Rta-Smriti rejects project-local discovery, binds the
resolved executable identity into the index manifest, and rechecks that identity before launch; it
cannot certify the behavior of the external server itself.

Optional local thread compaction is off by default. It accepts only a loopback
Ollama base URL, redacts common sensitive values, preserves the source events,
and stores the summary as unverified derived state:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" settings --project project-name --compaction-provider ollama --compaction-model qwen3:0.6b --json
```

## Govern A High-Risk Action

Create a hash-backed policy from trusted project evidence, then evaluate the intended action:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" policy add --project project-name --kind required_check --statement "Privacy proof is required before publishing" --effect block --action-contains publish --required-check privacy-proof --pramana pratyaksha --verification-status verified --source-path docs/release-policy.md
& $RtaBrain --db "$BrainDir\project-name.sqlite" preflight "publish release" --project project-name --json
& $RtaBrain --db "$BrainDir\project-name.sqlite" preflight "publish release" --project project-name --operational-context --json
& $RtaBrain --db "$BrainDir\project-name.sqlite" preflight "publish release" --project project-name --check privacy-proof --json
```

When `--source-path` points inside the canonical project root, Rta-Smriti hashes the current file. Low-trust or unverified memory can warn, but cannot independently block. Completed checks are owner attestations; agents using MCP cannot supply them or override a result. The `--operational-context` flag adds checkpoint, continuity, Git, and freshness warnings to CLI preflight without changing policy authoring.

## Explain Retrieval And Impact

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" retrieval-diagnostics "authentication boundary" --project project-name --json
& $RtaBrain --db "$BrainDir\project-name.sqlite" graph-query authorize --project project-name --type impact --depth 2 --limit 100 --json
& $RtaBrain benchmark --json
& $RtaBrain benchmark --report .\rta-smriti-benchmark.md --json
# Optional: requires the embeddings extra and an available local model
& $RtaBrain benchmark --include-semantic --semantic-model all-MiniLM-L6-v2 --json
```

Graph calls are approximate hints. Verify consequential changes against source and tests. The packaged benchmark is a synthetic regression harness, not competitive proof. The `--report` output is intended for public release notes and issue triage because it contains only the packaged synthetic corpus digest and aggregate metrics.

## Search Multiple Project Brains

The workspace record lives in one owner brain and references other local brain databases explicitly. Workspace search is query-only and does not add recall receipts to member brains; deleted, symlinked, or hard-linked member databases fail closed:

```powershell
& $RtaBrain --db "$BrainDir\api.sqlite" workspace create --name product-stack --description "API and web" --json
& $RtaBrain --db "$BrainDir\api.sqlite" workspace add --name product-stack --project api --member-db "$BrainDir\api.sqlite" --role backend --json
& $RtaBrain --db "$BrainDir\api.sqlite" workspace add --name product-stack --project web --member-db "$BrainDir\web.sqlite" --role frontend --json
& $RtaBrain --db "$BrainDir\api.sqlite" workspace search --name product-stack --query "shared envelope version" --json
```

## Export Or Authenticate Local Memory

Selective bundles exclude source code and redact home paths and common credential patterns by default:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" bundle-export .\project-memory.rta.json --project project-name --preview --json
& $RtaBrain --db "$BrainDir\project-name.sqlite" bundle-export .\project-memory.rta.json --project project-name --json
& $RtaBrain --db "$BrainDir\import.sqlite" bundle-import .\project-memory.rta.json --conflict rename --preview --json
& $RtaBrain --db "$BrainDir\import.sqlite" bundle-import .\project-memory.rta.json --conflict rename --json
```

Preview first. It performs the same integrity, redaction, schema, bounds, and conflict analysis without writing the export or changing the destination brain. A real import is staged in a temporary in-memory database and committed only after every record succeeds. Bundle SHA-256 proves content integrity, not sender identity: imported memories are downgraded to unverified `smriti`, while imported checkpoints and policies enter quarantine for owner review. Bundle inputs are capped at 25 MB.

Authenticated snapshots contain the complete SQLite brain. Keep both the snapshot and its separate key private:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" snapshot create .\project-brain.rta-snapshot --key "$BrainDir\snapshot.key" --json
& $RtaBrain snapshot verify .\project-brain.rta-snapshot --key "$BrainDir\snapshot.key" --json
```

HMAC-SHA256 detects tampering with a shared local key. For public-key identity, use the included Ed25519 support:

```powershell
& $RtaBrain snapshot keygen "$BrainDir\snapshot-ed25519-private.pem" --public-key "$BrainDir\snapshot-ed25519-public.pem" --json
& $RtaBrain --db "$BrainDir\project-name.sqlite" snapshot create .\project-brain.rta-snapshot --private-key "$BrainDir\snapshot-ed25519-private.pem" --json
& $RtaBrain snapshot verify .\project-brain.rta-snapshot --public-key "$BrainDir\snapshot-ed25519-public.pem" --json
```

Snapshots are not encrypted and are not safe to publish. Snapshot databases are capped at 64 MiB and legacy envelopes at 16 MiB; authentication and bounded reads occur before payload acceptance.

## Opt In To Checkpoints And Feedback

The managed Git hook resolves Git's configured hook directory, including linked worktrees, and refuses to replace an unknown, symlinked, or hard-linked `post-commit` hook:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" git-hooks install --root C:\path\to\project --project project-name --json
& $RtaBrain git-hooks uninstall --root C:\path\to\project --json
```

Record operator outcomes and age only eligible old, unverified inference or hypothesis memories:

```powershell
& $RtaBrain --db "$BrainDir\project-name.sqlite" memory-feedback 42 --project project-name --outcome helpful --evidence "Resolved incident 184" --json
& $RtaBrain --db "$BrainDir\project-name.sqlite" memory-decay --project project-name --minimum-age-days 90 --step 0.03 --json
```

Verified evidence and `pratyaksha` or `sabda` records are protected from decay.

## What Not To Publish

Never commit:

- `*.sqlite`
- `.rta-smriti/`
- private thread exports
- local screenshots with private project names
- logs containing local paths
- generated brain folders
- selective bundles or authenticated snapshots unless they were created from synthetic public data and reviewed
- snapshot HMAC keys
- credentials or API keys

The public GitHub repo should contain only the tool, docs, tests, and demo-safe assets.
