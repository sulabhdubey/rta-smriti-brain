# Rta-Smriti Brain v1.1.0-alpha.7

Package metadata: `1.1.0a7`
Maturity: **Alpha prerelease**
Previous public release: v1.1.0-alpha.6

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. OpenAI Codex was the primary AI engineering agent under maintainer review.

## Consolidated Background-Efficiency Maintenance

This release preserves guided first-project setup, read-only recovery, the
trusted lifecycle supervisor and optional governed federation. It reduces unnecessary
background work instead of adding another feature surface.

- Filesystem events follow the ingestion policy: excluded generated trees,
  temporary files and non-text files do not schedule repository refreshes.
- Changed directories check their descendants without re-parsing unrelated files.
  Native watchers also reconcile metadata periodically for missed events.
- Indexing has a cooperative target of 20% of one CPU core per watcher; continuity
  discovery and SQLite work target 5% per continuity worker. Stop requests remain
  responsive, with unfinished repository refreshes rolled back atomically.
- Quiet polling and failed refreshes back off. Empty capture spools poll every
  two to ten seconds, unless an operator explicitly selected a longer interval,
  and return to the requested cadence while queued work remains.
- Unchanged transcript discovery results are reused for at most five minutes,
  bound to file identity, stat values and canonical root. Observed stat changes
  invalidate them immediately. Ingestion still checks roots and rebind markers.
- The transcript nesting guard scans structural bytes efficiently while preserving
  its bytewise depth and escape behavior.
- Incremental ingestion reuses FTS row identifiers and resolves changed calls or
  newly introduced symbols instead of revisiting unrelated graph links.

## Upgrade

Use the platform executable or universal Python wheel attached to this release.
Verify it against `SHA256SUMS.txt` and the available GitHub provenance attestation.
Back up existing brains and stop their verified managed workers before upgrading;
restart them through the new runtime so long-lived processes load the repaired code.
See [installation](INSTALLATION.md) and [usage](USAGE_GUIDE.md).

No database schema change is introduced. Existing alpha.6 tags and downloads remain
immutable. Native targets are Windows x86_64, Linux x86_64 and macOS ARM64. Executables
remain unsigned by an OS code-signing certificate; a checksum alone does not establish
publisher identity.

## Evidence and Limits

The mechanism qualification passed 1,318 local Python tests, 718 subtests, and an
independent ten-worker synthetic event-storm check. Thirty platform/privilege tests
were explicitly skipped. The optimized depth guard matched an independent bytewise
oracle across 20,000 comparisons. Installed read-only retrieval remained available
while background workers ran. Private laptop and project measurements are not shipped.

Initial discovery of a large transcript archive can take longer at the lower CPU
target. The first event after an idle capture period may wait up to its polling
interval. Targets are cooperative, not hard OS quotas: parser bursts, observer and
heartbeat threads, and multiple concurrent projects may add load. This release does
not claim a temperature guarantee, battery-life benchmark, production support, external
pilot success, or the complete live MCP-host matrix. Capture remains opt-in and
federation disabled by default.

Publication requires the source-bound hosted, upgrade, soak, native, download and
website gates. The release body will link their completed evidence rather than
pre-claiming it here. See [release verification](RELEASE_VERIFICATION.md).
