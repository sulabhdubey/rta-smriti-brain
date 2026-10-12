# Rta-Smriti Brain v1.1.0-alpha.8

**Alpha prerelease.** One consolidated Project Passport and reliability release.
Package version: `1.1.0a8`. No database schema change.
Previous public release: v1.1.0-alpha.7

## Project Passport

Open **Project Passport** from the authenticated local console for four focused
views: Resume, Changes, Decisions, and Handoff. Save a checkpoint without silently
overwriting another writer, inspect bounded indexed activity, record a decision,
and select exactly which fields to preview and export as Markdown or JSON.
Nothing is selected for sharing by default. Exports require a fresh preview and
explicit privacy review; checksums identify bytes, not the truth of their claims.

An optional read-only Passport MCP profile exposes inspection and selective
preview. A fictional two-project demo is available through
`python -m rta_brain.passport_demo`. See [Project Passport](PROJECT_PASSPORT.md).

## Reliability

- Bounded aggregate health refresh retains project identity and distinguishes
  ready, not ready, deferred, and unavailable evidence.
- Continuity reads only the bounded recent transcript tail where applicable;
  unchanged sessions do not repeatedly incur full-file work.
- Installed startup commands preserve Python isolation.
- Repository inspection agrees with the canonical checkout binding. If native
  Git verification fails, identity creation fails closed instead of creating a
  conflicting local identity. Existing identities are not silently rewritten.

The trusted lifecycle supervisor and governed federation remain available.
Federation, automatic capture, and indexing choices remain explicit.

## Upgrade and Limits

Back up the brain before replacing an installed runtime. Stop only its managed
workers, install the new package or matching native artifact, and restart through
the existing launcher. Keep the previous package for rollback. Do not mix a source
checkout with an installed launcher or downgrade a newer database schema.

Passport reuses the existing memory store. Activity is not a complete filesystem
diff; newly entered decisions remain unverified testimony. Redaction is imperfect
and does not replace reviewing the exact output. An authorized MCP host receives
the selected text and may send it to its model provider. No cloud service,
marketplace distribution, billing, native folder picker, or Office/email connector
is included. Cooperative background pacing is not a hard CPU or temperature cap.
Native artifacts carry GitHub provenance but are not vendor code-signed/notarized.

See [Release Verification](RELEASE_VERIFICATION.md) for source-bound qualification
and publication evidence. Historical release records remain unchanged.

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh Dubey;
built with Codex (OpenAI), under maintainer review. This is not an OpenAI product
or endorsement.
