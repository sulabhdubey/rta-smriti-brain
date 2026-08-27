# Rta-Smriti Brain v1.0.4-alpha

> Alpha prerelease. Back up an existing brain before upgrading.
> Rta-Smriti remains local-first and does not send project data to a hosted
> service.

`v1.0.4-alpha` is a narrow launcher-integrity patch for the v1 Project Reality
line. It preserves the v11 SQLite schema and all stable v1 interfaces while
ensuring an installed Rta-Smriti command cannot be shadowed by an older source
checkout in the operator's current working directory.

## What Changed

- Installed-package CLI and MCP wrappers now invoke Python in isolated mode before loading `rta_brain.cli` or `rta_brain.mcp_server`.
- A global launcher therefore resolves its verified installed runtime even when invoked from an older checkout or another folder containing an `rta_brain` package.
- Source-checkout script launchers and standalone native binaries retain their existing launch paths.
- Windows and POSIX wrapper regressions verify the isolated command shape, including generated MCP host configuration.
- The installed-upgrade gate now proves the immutable public `v1.0.3-alpha` package can upgrade to this candidate without database downgrade or rewrite.

## Compatibility And Migration

- Python package metadata: `1.0.4a1`
- Display/tag target: `v1.0.4-alpha`
- SQLite schema: v11; no schema change from `v1.0.3-alpha`
- Upgrade baseline: immutable public `v1.0.3-alpha` commit `76961d475905cb528d7959fa3b0166afe8606d0a`
- Existing brains: upgrade the launcher; never downgrade or rewrite a brain database
- Existing MCP hosts: restart the host after reinstalling so it starts the updated isolated wrapper

## Evidence Boundary

Focused launcher regressions prove the generated installed-package command is
isolated from the working directory. Full source, installed-package, native
artifact, cross-platform CI, browser, privacy, and security qualification will
be recorded in the [release verification ledger](RELEASE_VERIFICATION.md).
Artifacts are built from the immutable annotated tag; checksums verify download
integrity but do not provide platform code signing.

## Honest Boundaries

- Isolated mode protects installed Python launchers from local module shadowing; it is not an operating-system sandbox.
- Routine cognition uses the latest completed index; consequential work still requires a live or deep freshness check.
- Call and impact edges remain bounded hints, not compiler-perfect analysis.
- The packaged benchmark is a synthetic regression harness, not external proof of superiority.
- User-level workers are explicit local processes, not privileged operating-system services.

## Build Provenance

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. It was built with [OpenAI Codex](https://openai.com/codex/) as the primary
design, engineering, testing, and documentation agent under Sulabh's review and
release approval. This attribution does not imply OpenAI endorsement.
