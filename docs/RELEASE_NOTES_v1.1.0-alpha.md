# Rta-Smriti Brain v1.1.0-alpha

> Alpha prerelease. Back up an existing brain before upgrading.
> Rta-Smriti remains local-first and does not send project data to a hosted
> service.

The `v1.1.0-alpha` prerelease adds a Trusted Lifecycle Supervisor: one inspectable boundary
for understanding, planning, applying, verifying, repairing, stopping, and
removing Rta-Smriti's local services. It builds on Project Reality without
turning Rta-Smriti into an agent executor or model-routing harness.

Previous public release: v1.0.4-alpha

## What Changed

- Added independent database, repository, capture, continuation, MCP, and federation health axes. Overall readiness is derived from these states rather than from process liveness alone.
- Unified continuation readiness around current integrity, work conflicts, truth blockers, validators, capture state, checkpoints, and declared external work.
- Added preview-confirmed lifecycle plans bound to the execution context and observed state, with append-only execution journals and recovery-aware receipts.
- Added backup-first schema inspection and migration safeguards, exact backup validation, interruption recovery, and explicit newer-runtime diagnostics.
- Added quiet ownership rules for local workers. A live process whose identity cannot be verified is reported as attention-required instead of being cleared or duplicated.
- Added capability-profiled MCP recipes for Codex, Claude Code, Cursor, Zed, OpenCode, and Gemini CLI, including preview, collision detection, backup, rollback, removal, and host-specific activation guidance.
- Added a nonce-bound fresh-session proof workflow through `mcp-host challenge`
  and `mcp-host prove`. Two ephemeral environment variables bind a newly
  launched host to its installed receipt and one-use token; the MCP server then
  records real `initialize`, `tools/list`, `brain_capabilities`, and public
  Atlas `brain_search` activity. Caller-authored tool results cannot become a
  protocol proof, and caller-controlled `clientInfo` is never treated as host
  identity attestation.
- Added snapshot-bound progressive retrieval across index, selection, and evidence expansion. Changed evidence invalidates an earlier handle instead of being returned under an old digest.
- Added bounded, digest-sealed JSON and Markdown lifecycle review bundles with evidence references, privacy ceilings, redaction manifests, and explicit non-authoritative summary labels.

## Compatibility And Migration

- Python package metadata: `1.1.0a1`
- Display and tag: `v1.1.0-alpha`
- Existing project brains are inspected before mutation. A migration policy must be selected explicitly; migration uses a validated no-clobber backup and fails closed on unsupported schema states.
- Existing workers remain user-level local processes. Login restoration is optional and is never enabled implicitly.
- Existing MCP configurations keep their host's activation rules. Use a profile plan before changing a host file, then open a fresh host session for proof. A running session cannot acquire a newly registered server retroactively.

## MCP Host Evidence

The release contains configuration profiles for all six named hosts. Profile
support means Rta-Smriti can generate and validate the documented configuration
shape. It does not mean every native host was executed on every release
platform. The [release verification ledger](RELEASE_VERIFICATION.md) records
which host and operating-system journeys were actually run. A challenge or
recipe alone is not verification; only a sealed, server-observed receipt moves
a session to protocol-verified. A host-specific execution claim additionally
requires operator or host-side evidence. Unexecuted host recipes remain
recipe-available or experimental, never verified.

## Evidence Boundary

Release qualification covers the exact tagged source, installed package,
standalone artifacts, hosted operating-system matrix, browser journeys,
privacy and security checks, migration and interruption cases, and a sustained
local supervisor run. Results belong in the
[release verification ledger](RELEASE_VERIFICATION.md); this document does not
pre-claim a gate that has not produced evidence.

The existing 60-second demo and retained screenshots were captured from
`v1.0.2`. They remain an honest view of the Project Reality foundation and do
not depict the v1.1 Trusted Lifecycle Supervisor.

## Honest Boundaries

- Rta-Smriti supervises its own local services and evidence state. It does not execute project work, choose models, or grant an agent authority over a repository.
- Freshness proves the state of indexed bytes, not the correctness of a claim, test, external job, or human decision.
- MCP configuration and a passing local protocol probe are not substitutes for a fresh-session call in the target host.
- Workers are ordinary user processes, not privileged operating-system services.
- Review-bundle summaries are convenience projections. The cited receipts and source evidence remain authoritative.
- Call and impact edges remain bounded analysis hints rather than compiler-perfect graphs.
- The packaged benchmark is a synthetic regression harness, not external proof of superiority.

## Build Provenance

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. It was built with [OpenAI Codex](https://openai.com/codex/) as the primary
design, engineering, testing, and documentation agent under Sulabh's review and
release approval. This attribution does not imply OpenAI endorsement.
