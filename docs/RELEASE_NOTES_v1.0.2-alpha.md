# Rta-Smriti Brain v1.0.2-alpha

> Alpha prerelease candidate. Back up an existing brain before upgrading.
> Rta-Smriti remains local-first and does not send project data to a hosted
> service. v1.0.1-alpha remains the current public prerelease until this
> candidate completes hosted CI, artifact, and publication gates.

`v1.0.2-alpha` is the operator-hardening patch for the v1 Project Reality
release. It preserves the v11 SQLite schema, stable interfaces, and product
boundary while correcting Windows onboarding, background lifecycle, large-repo
sync fallback, and one dashboard accessibility defect found in real local use.

## What Changed

- Windows login startup now uses a hidden direct `Win32_Process.Create` launcher instead of a visible Startup-folder `.cmd`; re-enabling startup migrates the legacy entry.
- Console, watcher, capture, and continuity workers share the same terminal-independent detached-process primitive, including explicit no-window flags on Windows.
- Standard packages and native binaries now include Watchdog for event-driven repository sync by default.
- The emergency polling fallback backs off to 30 seconds for repositories with at least 10,000 indexed files and 60 seconds at 50,000 files, while retaining five-minute deep verification.
- Windows private-directory hardening no longer reclaims an already-correct owner, closing onboarding failures on owner-controlled roots without weakening foreign-owner checks.
- Re-running `start` or `bootstrap-project` now preserves an existing brain's retrieval provider unless `--embedding-provider` is supplied explicitly; new brains continue to default to the built-in hash provider.
- The active-project secondary label now meets WCAG AA contrast in the dark dashboard theme.

## Compatibility And Migration

- Python package metadata: `1.0.2a1`
- Display/tag target: `v1.0.2-alpha`
- SQLite schema: v11; no schema change from `v1.0.1-alpha`
- Upgrade baseline: immutable public `v1.0.1-alpha` commit `c2dff01b368bdb4d2b759e7a077d07ae0985a966`
- Windows login startup: run `rta-brain console login-enable --brain-dir <brain-directory>` once after upgrade to replace a legacy `.cmd` registration
- Rollback: restore a pre-upgrade backup or reinstall the v1.0.1 public asset

## Evidence Boundary

Focused Windows startup, detached-worker, Watchdog packaging, polling fallback,
ACL, onboarding, and install-local regressions pass locally. Full source,
installed-package, native artifact, browser, privacy, security, and hosted CI
evidence is tracked in the
[release verification ledger](RELEASE_VERIFICATION.md). This document does not
claim publication before the tag and release exist.

## Honest Boundaries

- Routine cognition uses the latest completed index; consequential work still requires a live or deep freshness check.
- Call and impact edges remain bounded hints, not compiler-perfect analysis.
- Media descriptions remain unverified until explicitly promoted with provenance.
- The packaged benchmark is a synthetic regression harness, not external proof of superiority.
- User-level workers are explicit local processes, not privileged operating-system services.

## Build Provenance

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. It was built with [OpenAI Codex](https://openai.com/codex/) as the primary
design, engineering, testing, and documentation agent under Sulabh's review and
release approval. This attribution does not imply OpenAI endorsement.
