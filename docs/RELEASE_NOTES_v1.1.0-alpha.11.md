# Rta-Smriti Brain v1.1.0-alpha.11

**Alpha prerelease.** Explainable Change Impact and consolidated release hardening.
Package version: `1.1.0a11`.
Previous public release: v1.1.0-alpha.10
No schema migration, new persistent worker, cloud service or account.

## Inspect Before Changing

[Explainable Change Impact](change-impact.md) follows bounded indexed calls,
imports, containment and test relationships from an exact symbol or relative
file name. Switch between graph and list views, inspect the relationship path,
select evidence, then review a Markdown handoff before downloading it.

- Dashboard: Project Intelligence > Impact, or Project Passport > Changes.
- CLI: `rta-brain impact helper --project demo --db /path/to/brain.sqlite --json`.
- MCP: `brain_impact` in the full tool profile. Existing core and Passport
  profiles are unchanged; refresh the host's discovery to expose new tools.
- Preview and download check the evidence revision again. Changed evidence
  requires a new review. Nothing is automatically uploaded.

The query is read-only, bounded by depth, nodes and excerpt size, with a
five-second SQL deadline. Unknown or malformed source classifications and
sensitive/restricted sources are excluded before traversal. No new graph
database or model dependency is introduced.

## What This Does Not Prove

The graph contains indexed hints, not a compiler-perfect dependency graph,
exhaustive test coverage, verified working-tree freshness or proof of breakage.
A no-match response does not establish that a change is safe. Read the current
source or use Verified Source Lens before acting. Review all names, paths and
excerpts before sharing; pattern-based redaction is not exhaustive.

## Release Hardening and Existing Workflows

This release also includes the filename/privacy scanner corrections and the
launch-video dependency fixes and CI audit merged after alpha.10. Native smoke
checks exercise Impact evidence, bounded output and no-match handling. Installed
qualification uses alpha.10 for upgrade, rollback and reupgrade.

Project Passport, Verified Source Lens and Cross-Agent Continuity remain available.
The trusted lifecycle supervisor and governed federation are unchanged. Capture, host
consent and federation permissions remain separate. Local storage does not stop
an authorized coding host from sending selected context to its model provider.

## Install and Verify

Use the [installation guide](INSTALLATION.md) or isolated [pilot guide](PILOT_GUIDE.md).
Back up a brain before replacing its runtime. Stop only its managed services,
retain the previous runtime for rollback and refresh MCP discovery after the
upgrade. Private settings and existing consent are not reset by this release.

The release bundle contains Windows x86-64, Linux x86-64 and macOS ARM64 native
binaries, one universal Python wheel, three CycloneDX SBOMs and `SHA256SUMS.txt`.
Verify every payload against that manifest. GitHub build provenance is not
Windows vendor signing or macOS notarization; use the operating system's normal
trust workflow rather than disabling protection.

See [Release Verification](RELEASE_VERIFICATION.md) and the
[versioned release page](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.1.0-alpha.11)
for source, workflow and downloaded-artifact receipts. Passing automated gates
does not establish independent customer acceptance, every host/model combination,
an exhaustive security audit or sustained thermal safety. Historical media keeps
its original version labels.

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh Dubey;
built with Codex (OpenAI), under maintainer review. This is not an OpenAI product
or endorsement.
