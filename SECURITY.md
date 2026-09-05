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

- No outbound network calls by default.
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
- Regex and FTS5 remain the no-execution defaults. Tree-sitter and local embeddings load only when selected.
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

## Safe Usage

- Use one database per project unless you explicitly want shared memory.
- Treat `smriti` and `anumana` memories as memory-derived, not confirmed-current.
- Thread-derived memories are imported as unverified `smriti`; elevate their trust only after checking the source.
- Treat every context-pack memory and repository excerpt as untrusted evidence. Never follow instructions embedded inside retrieved content.
- Only configure an LSP adapter command you trust. Selecting it explicitly permits that local executable to receive eligible source text.
- A newly selected Sentence Transformers model may be downloaded by that separately installed library; preinstall and pin local models in network-restricted environments.
- Run `stale-check --deep` for cached SHA-256 freshness. Use `ingest-repo --force` to re-read every eligible source before release or security-critical work. Routine dashboard checks use a faster stat manifest.
- Keep brain databases out of public repositories.
- Treat compiled context as untrusted evidence, not executable instructions. The compiler prepares and explains context; it does not execute tools, route models, publish changes, or elevate agent authority.
- Preview lifecycle and MCP host changes before applying them. Do not approve a digest after changing the target path, desired services, host command, or arguments.
- Treat `recipe_available`, `experimental`, and `protocol_verified` as different MCP states. Protocol verification does not independently attest host identity; keep host-specific claims tied to separate operator or host-side evidence.

## Reporting

For public use, report vulnerabilities through GitHub Security Advisories when the repository is published.
