# Rta-Smriti Brain v1.1.0-alpha.4

Release wave: **v1.1B maintenance**
Package metadata: `1.1.0a4`
Maturity: **Alpha prerelease**

Previous public release: v1.1.0-alpha.3

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. OpenAI Codex was the primary AI engineering agent under Sulabh's review
and release approval.

## Why This Maintenance Release Exists

Real multi-project dogfooding exposed several operator-readiness gaps that unit
tests alone did not reveal. A large registry could delay the whole dashboard,
normal startup request bursts could exhaust the bounded local HTTP worker pool,
and a running continuity process with no matching Codex session could look more
ready than the evidence justified.

## What Changed

- Project brains appear immediately, then repository and SQLite health are
  verified independently with bounded concurrency and explicit progress.
- Expensive database integrity checks retain measured, stat-bound cache evidence
  and fail closed if a database changes while it is being inspected.
- Project-detail requests run through a four-worker queue. Switching brains
  invalidates the old queue and suppresses stale graph, capture, lifecycle,
  continuation, governance, cognition, truth, and federation results.
- The loopback console keeps its fixed worker cap but waits briefly for a slot,
  avoiding connection resets during ordinary dashboard bursts.
- Continuity readiness distinguishes a healthy bound session from an unbound or
  first-session state. Process liveness is never treated as data-flow proof.
- Lifecycle repair can restore an enrolled project to its exact canonical root,
  and detached workers start through an isolated trusted package path.
- Loading, partial, stale, empty, authorization-recovery, and exact-project
  states have broader rendered operator regression coverage.

## Qualification Boundary

The candidate passed the full Python suite, rendered Playwright operator suite,
repeated progressive-loading stress, frontend security tests, dependency audits,
privacy and secret scans, workflow linting, build checks, and a sealed Codex
Security diff review with no confirmed findings. Exact hosted CI, tagged binary,
checksum, SBOM, anonymous-download, and published-site receipts are recorded in
[Release Verification](RELEASE_VERIFICATION.md) after immutable publication.

## What Did Not Change

- No cloud account, telemetry, or hosted project database was added.
- No automatic or silent schema migration was introduced.
- Governed federation remains optional, encrypted, permissioned, and disabled
  by default.
- A clone, download, running process, or discovered session is not presented as
  a verified installation, successful capture, or fresh-session MCP proof.
- The v1.1B product boundary remains project memory and continuity, not agent
  execution or model orchestration.

## Upgrade Guidance

Install `1.1.0a4` over `1.1.0a3` or an earlier supported release. Use the
Trusted Lifecycle Supervisor to inspect and preview any required schema or
binding action. Approve `migrate-with-backup` only after reviewing the proposed
backup and migration steps, then verify the independent health axes from a fresh
operator session.
