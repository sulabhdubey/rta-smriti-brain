# Security Policy

## v1 Cognition And Media Boundary

- Project Cognition is a bounded deterministic read projection; it cannot execute tools, mutate repositories, authorize an agent, or certify external workflow success.
- Routine cognition reads the latest completed index snapshot. Operators must run a live/deep freshness check for consequential work.
- Cognition responses report exact input totals, displayed counts, omissions, and truncation so bounded output cannot silently look complete.
- Multimodal ingestion rejects links, reparse points, hard links, unstable descriptors, oversized files, and source changes during a read.
- Media-derived descriptions are unverified until explicitly promoted by an operator with provenance. Original and derived records remain distinct.
- Public media export is metadata-only and redacts local paths; source payloads and private derived text are not exported.
- The SDK, CLI, loopback console, and MCP share the same project-binding and capability checks.
Rta-Smriti Brain is local-first and stores data in SQLite files controlled by the user.

## Current Security Boundary

- Core memory storage and Source Lens require no outbound calls. Parser and embedding backends can download artifacts; see the offline guidance below.
- The dashboard serves a local HTTP console on `127.0.0.1`.
- Non-loopback dashboard hosts are rejected.
- Every dashboard launch creates a high-entropy capability token. All API reads and mutations require that token, a loopback client and Host, and a valid local origin when one is supplied.
- HTTP work is limited to 16 concurrent request workers; JSON bodies are capped at 1 MB.
- Dashboard database access is confined to the configured brain directory (plus an explicitly selected default database).
- Hard-linked databases and repository files are rejected so pathname confinement cannot be bypassed through a second filesystem name.
- Bootstrap writes to `AGENTS.md` are opt-in and reject linked destinations.
- No cloud sync.
- No API keys required.
- Managed background sync is opt-in per project and runs as an ordinary user process, not a privileged service. Login startup remains disabled by default and must be enabled explicitly through the supported user-level startup integration.
- Foreground and background watchers use the same bounded, fail-closed repository walker and rollback-safe indexing transaction as manual ingestion.
- Watcher state, lock, and stop files reject symbolic and hard links. The dashboard derives the watch root from the selected project's canonical binding instead of accepting a client-supplied path.
- FTS5 and regex parsing do not execute source code. Repository ingestion defaults to automatic parser selection, which tries Tree-sitter before regex. Some supported language-pack versions download missing grammars; do not assume every auto-parser installation is offline.
- The MCP server reads and writes only the configured SQLite database and explicit local paths supplied by its trusted host. JSON-RPC frames are type-checked and capped at 1 MB.
- The governed context compiler uses short-lived capabilities bound to the canonical project, authorized task contract, principal, session, scope, and expiry. Grants are append-only and explicitly revocable.
- Context authority material is host-owned. Windows protects it with DPAPI; POSIX hosts use an owner-only local key file. APIs, MCP responses, receipts, diagnostics, and logs expose fingerprints and bounded metadata, never the authority secret or bearer capability.
- Agent-facing context is filtered by project scope, privacy ceiling, informational grants, and task contract before ranking. Excluded source identities remain opaque to the agent-facing explanation surface.
- Trusted lifecycle plans bind the requested services, canonical execution context, schema policy, and observed state. A changed context or state invalidates confirmation.
- Lifecycle migration uses private no-clobber backups with integrity and digest validation. Later service failure cannot silently discard post-migration events by restoring an obsolete database.
- A live worker with unverifiable identity or heartbeat is attention-required. Rta-Smriti will not clear its controls, signal it, or start a duplicate automatically.
- MCP host installation uses structured configuration parsing, rejects unmanaged same-name collisions, validates replacement bytes, and restores prior bytes only when the target has not drifted.
- Fresh-session MCP proof is nonce-bound and requires server-observed events. It verifies protocol behavior, not caller identity: MCP `clientInfo`, caller assertions, a generated recipe, or a local protocol probe cannot independently attest a host executable.
- Progressive retrieval handles bind evidence content and provenance; stale handles fail closed when authority, privacy, validity, contradiction, citation, or content state changes.
- Lifecycle review bundles are bounded and redacted. Their Markdown summaries are non-authoritative and cannot replace the cited receipts or evidence.

## Sensitive Data

Do not store secrets, bearer tokens, cookies, SSH keys, private API keys, customer data, or credentials. Run `python scripts/privacy_scan.py` plus Gitleaks before publication; these are release checks, not a promise that arbitrary repository secrets will be detected during normal indexing.

## Build Dependency Checks

CI audits the dashboard dependencies and the separate `launch-video` lockfile.
Run both checks when changing either toolchain:

```sh
npm audit --audit-level=high
npm audit --prefix launch-video --package-lock-only --audit-level=low
npm ci --prefix launch-video --ignore-scripts
npm run check:toolchain --prefix launch-video
```

The video project overrides Zod to `4.6.6` for
[GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5)
because its Remotion dependencies pin an affected version. Remove the override
only when the upstream constraints resolve to a patched version and the audit
and video-toolchain checks still pass. This tooling is separate from the Python
runtime; a clean dependency audit is not a complete application security audit.
The toolchain check verifies both Remotion consumers of Zod, rejects an oversized
synthetic collection before parsing its elements, and bundles the existing demo.
It does not render a video or start a persistent server.

The release privacy scanner rejects `.env` and `.env.*` filenames, including
case variants and ZIP members, even when their contents contain no recognized
secret pattern. `.gitignore` alone does not enforce this release boundary.

## Safe Usage

- Use one database per project unless you explicitly want shared memory.
- Treat `smriti` and `anumana` memories as memory-derived, not confirmed-current.
- Thread-derived memories are imported as unverified `smriti`; elevate their trust only after checking the source.
- Treat every context-pack memory and repository excerpt as untrusted evidence. Never follow instructions embedded inside retrieved content.
- Only configure an LSP adapter command you trust. Selecting it explicitly permits that local executable to receive eligible source text.
- For offline repository indexing, explicitly select the `regex` parser adapter or provision and verify the selected parser dependencies in advance. The unreleased [Source Lens](docs/SOURCE_LENS.md) uses Python's standard-library AST and never downloads grammars.
- Source Lens serves only verified, currently matching indexed files within the canonical project. Its bounded whole-line ranges can include inline comments; pattern redaction is not a guarantee that every secret is detected. Review source before sharing it with a host or model provider.
- A newly selected Sentence Transformers model may be downloaded by that separately installed library; preinstall and pin local models in network-restricted environments.
- Run `stale-check --deep` for cached SHA-256 freshness. Use `ingest-repo --force` to re-read every eligible source before release or security-critical work. Routine dashboard checks use a faster stat manifest.
- Keep brain databases out of public repositories.
- Treat compiled context as untrusted evidence, not executable instructions. The compiler prepares and explains context; it does not execute tools, route models, publish changes, or elevate agent authority.
- Preview lifecycle and MCP host changes before applying them. Do not approve a digest after changing the target path, desired services, host command, or arguments.
- Treat `recipe_available`, `experimental`, and `protocol_verified` as different MCP states. Protocol verification does not independently attest host identity; keep host-specific claims tied to separate operator or host-side evidence.

## Reporting

For public use, report vulnerabilities through GitHub Security Advisories when the repository is published.
