# Rta-Smriti Brain v1.0.3-alpha

> Alpha prerelease. Back up an existing brain before upgrading.
> Rta-Smriti remains local-first and does not send project data to a hosted
> service.

`v1.0.3-alpha` is a narrow maintenance patch for the v1 Project Reality line.
It preserves the v11 SQLite schema and all stable v1 interfaces while making
launcher/database mismatches and expired console capabilities safe and
understandable during real operator use.

## What Changed

- A console opened without its current one-session capability now shows a dedicated authorization-recovery screen instead of a misleading empty-brain/bootstrap state.
- The recovery screen explains that no projects were removed and provides a copyable `rta-brain console open --brain-dir ...` command.
- API authorization failures cancel stale project discovery and clear session-only capability state before recovery.
- A launcher that encounters a newer brain schema now names both versions, instructs the operator to upgrade the active launcher, and explicitly refuses database downgrade or rewriting guidance.
- Installation guidance now documents safe upgrades, active-command discovery, MCP-host restart requirements, and stale-console recovery across Windows, macOS, and Linux.
- Regression coverage proves future-schema rejection is non-mutating and exercises expired-console recovery in the packaged mobile dashboard.

## Compatibility And Migration

- Python package metadata: `1.0.3a1`
- Display/tag target: `v1.0.3-alpha`
- SQLite schema: v11; no schema change from `v1.0.2-alpha`
- Upgrade baseline: immutable public `v1.0.2-alpha` commit `272674cca094447a35307c93ceb05863b84a1b50`
- Existing brains: upgrade the launcher; never downgrade or rewrite a brain database
- Existing console tabs: run `rta-brain console open --brain-dir <brain-directory>` and continue in the fresh authorized tab

## Evidence Boundary

The focused schema and rendered authorization regressions pass locally against
the packaged dashboard. Full source, installed-package, native artifact,
cross-platform CI, browser, privacy, and security qualification is recorded in
the [release verification ledger](RELEASE_VERIFICATION.md). Artifacts are built
from the immutable annotated tag; checksums verify download integrity but do
not provide platform code signing.

## Honest Boundaries

- The capability-bearing console URL is intentionally session-scoped; a plain loopback URL is not an alternate login path.
- Routine cognition uses the latest completed index; consequential work still requires a live or deep freshness check.
- Call and impact edges remain bounded hints, not compiler-perfect analysis.
- The packaged benchmark is a synthetic regression harness, not external proof of superiority.
- User-level workers are explicit local processes, not privileged operating-system services.

## Build Provenance

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. It was built with [OpenAI Codex](https://openai.com/codex/) as the primary
design, engineering, testing, and documentation agent under Sulabh's review and
release approval. This attribution does not imply OpenAI endorsement.