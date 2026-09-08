# Rta-Smriti Brain v1.1.0-alpha.3

Release wave: **v1.1B maintenance**
Package metadata: `1.1.0a3`
Maturity: **Alpha prerelease**

Previous public release: v1.1.0-alpha.2

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. OpenAI Codex was the primary AI engineering agent under Sulabh's review
and release approval.

## Why This Maintenance Release Exists

Dogfooding an existing private brain found a narrow upgrade defect: a database
could report a supported schema version while one expected capture index was
missing. The Trusted Lifecycle Supervisor correctly required backup-first migration,
but the migration path did not repair and validate that index before recording
the newer schema version.

## What Changed

- Missing capture indexes now make the structural capture patch explicitly
  required.
- Supported older-schema upgrades repair the capture structure in the same
  supervised migration transaction.
- Capture schema validation must pass before migration completion is recorded.
- Current-schema structural repair remains gated by the existing
  `migrate-with-backup` lifecycle policy.
- Regression tests cover both a current-schema missing index and an older
  schema carrying the same defect into an upgrade.

## What Did Not Change

- No automatic or silent database migration was introduced.
- No downgrade, database rewriting, or bypass of backup authorization is
  permitted.
- Governed federation remains optional, encrypted, and disabled by default.
- The v1.1B feature set, maturity claim, privacy boundary, and MCP capability
  model are unchanged.

## Upgrade Guidance

Install `1.1.0a3` over an earlier release, then use the Trusted Lifecycle
Supervisor to inspect and preview any required schema action. Approve
`migrate-with-backup` only after reviewing the proposed backup and migration
steps. The supervisor verifies the resulting database structure before it
records migration completion.

Exact hosted tests, security checks, artifacts, checksums, and publication
receipts will be recorded in [Release Verification](RELEASE_VERIFICATION.md)
after the immutable tag and public assets exist.
