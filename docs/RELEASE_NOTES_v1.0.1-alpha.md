# Rta-Smriti Brain v1.0.1-alpha

> Alpha prerelease. Back up an existing brain before upgrading. Rta-Smriti
> remains local-first and does not send project data to a hosted service.

`v1.0.1-alpha` is the operator-readiness patch for the v1 Project Reality
release. It preserves the v1 schema, interfaces, and product boundary while
including two lifecycle corrections found during post-publication proof.

## What Changed

- Direct dashboard feedback now remains authoritative over delayed background refreshes.
- Temporal-truth API handlers close database state before sending the HTTP response, preventing follow-up requests from overlapping cleanup on slower runners.
- Release metadata, installation guidance, launch surfaces, and upgrade tests now target the corrected patch source.

## What Remains In v1

- Deterministic Project Cognition over repository evidence, bitemporal truth, observations, work state, decisions, and media
- Project Reality readiness, project-twin conflicts, knowledge coverage, decision debt, and bounded change-impact hints
- Governed local multimodal evidence with provenance, verification, redaction, retention, deletion, and metadata-only export
- Stable Python SDK plus CLI, authenticated loopback console, and read-only MCP parity
- Opt-in local capture, governed context compilation, canonical project integrity, and inspectable evidence classes

## Compatibility And Migration

- Python package metadata: `1.0.1a1`
- Display/tag target: `v1.0.1-alpha`
- SQLite schema: v11; no schema change from `v1.0.0-alpha`
- Upgrade baseline: immutable public `v1.0.0-alpha` commit `a1b05022aff6df3a066ae5abcad3877f6407eafb`
- Rollback: restore a pre-upgrade backup or reinstall the v1.0.0 public asset

## Evidence Boundary

The corrected source passed the full hosted Windows, macOS, and Ubuntu matrix,
installed upgrade/uninstall proof, rendered operator and launch-site journeys,
native binary smoke tests, dependency and workflow audits, privacy and secret
scans, SBOM and checksum verification, and anonymous download acceptance. Exact
runs, the bounded Windows retry, and artifact hashes are recorded in the
[release verification ledger](RELEASE_VERIFICATION.md).

## Honest Boundaries

- Routine cognition uses the latest completed index; consequential work still requires a live/deep freshness check.
- Call and impact edges remain bounded hints, not compiler-perfect analysis.
- Media descriptions remain unverified until explicitly promoted with provenance.
- The packaged benchmark is a synthetic regression harness, not external proof of superiority.
- User-level workers are explicit local processes, not privileged operating-system services.

## Build Provenance

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. It was built with [OpenAI Codex](https://openai.com/codex/) as the primary
design, engineering, testing, and documentation agent under Sulabh's review and
release approval. This attribution does not imply OpenAI endorsement.
