# Rta-Smriti Brain v1.1.0-alpha.12

**Alpha prerelease.** Unified Agent Setup for consented capture and bounded recall.
Package version: `1.1.0a12`.
Previous public release: v1.1.0-alpha.11
Feature baseline: `c529ba3fd7185ddd4c09a11527a7a1a4a75692ef` (PR #86).
No schema migration, new persistent worker, cloud service or Rta-Smriti account.

## One Reviewed Setup

[Unified Agent Setup](AGENT_SETUP.md) joins the existing private capture spool,
read-only memory core and host configuration lifecycle in one CLI workflow:

```text
Preview -> review backups and disclosure -> explicitly consent
        -> work in the selected host -> capture future prompts/final replies
        -> recall bounded, unverified history in a fresh session
```

- Plan, apply, inspect status, pause, drain the selected queue and review removal.
- Configure Codex, Claude Code or both for one canonical project brain.
- Capture and disclosure need separate consent. Existing registrations are not
  silently replaced. Native host trust must still be reviewed by the operator.
- Owned configuration drift is rejected. Unrelated host-written preferences are
  preserved during validation and reviewed removal.
- Native setup uses the standalone MCP entrypoint. Versioned binary filenames
  are accepted only when bound to the current frozen runtime's file identity.
- Host configuration policies use the same trusted system-root normalization for
  home and target paths on macOS, without accepting arbitrary symlinks.
- Dashboard sync controls wait for observed watcher status; loading or
  unavailable status is not treated as permission to start another worker.
- Capture uses at most 4,000 characters per prompt/reply field. Recall is bounded
  to 12 eligible records from the latest 64 events, seven days and 8 KiB.
- Corrections remain chronological unverified history, not approved decisions.
  Tool payloads, arbitrary files and historical transcript backfills are excluded.

## What Has and Has Not Been Proven

A bounded native Windows Codex pilot used three turns across two sessions and
captured six prompt/reply events. A fresh session recovered a corrected decision,
the superseded value and its unverified status. The recall prompt and project
files did not contain those answers; delivered hashes matched the journal.
This is synthetic maintainer evidence on the feature baseline, not independent
adoption or proof of every installed Codex version.

**Native Claude capture/recall and cross-host handoff remain unverified.** The
available account did not provide eligible Claude model access. A native MCP
connection and synthetic two-host tests do not prove successful model use.
Earlier bridge transport checks are not substituted for this missing evidence.

Selected context can reach the chosen host's model provider. Host subscriptions
or API usage may have a cost; Rta-Smriti does not supply model access. Local
storage is not a promise that disclosed model context remains local.

## Install, Verify and Recover

Follow [Installation](INSTALLATION.md), then [Unified Agent Setup](AGENT_SETUP.md).
Keep brain databases outside the repository. Back up before replacing a runtime,
stop only its selected services, retain the previous runtime, and refresh MCP.
The installed upgrade/rollback/reupgrade checks use the pinned alpha.11 tag.
No private startup settings, credentials, transcripts or live brains are bundled.

The release contains exactly eight assets: Windows x86-64, Linux x86-64 and
macOS ARM64 binaries, one universal Python wheel, three CycloneDX SBOMs and
`SHA256SUMS.txt`. Verify every payload and its GitHub build provenance. Provenance
is not Windows vendor signing or macOS notarization; keep normal OS protections.

Project Passport, Verified Source Lens and Explainable Change Impact remain.
The trusted lifecycle supervisor and governed federation remain available. Impact is indexed
evidence, not proof of current-file freshness or actual breakage. Existing media
keeps its original capture labels; it is not relabelled as a new setup demo.

See [Release Verification](RELEASE_VERIFICATION.md) and the
[versioned release receipt](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.1.0-alpha.12)
for exact-source CI, native workflow, checksums, SBOM/provenance and downloaded
package checks. Passing those gates does not establish an exhaustive security
audit, independent-user acceptance, cross-host model handoff or thermal safety.

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh Dubey;
built with Codex (OpenAI), under maintainer review. This is not an OpenAI product
or endorsement.
