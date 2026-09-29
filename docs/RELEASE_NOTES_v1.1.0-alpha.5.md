# Rta-Smriti Brain v1.1.0-alpha.5

Package metadata: `1.1.0a5`
Maturity: **Alpha prerelease**
Previous public release: v1.1.0-alpha.4

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. OpenAI Codex was the primary AI engineering agent under maintainer review.

## Consolidated Pilot Build

This release keeps the trusted lifecycle supervisor and governed federation
capabilities of v1.1B while simplifying the first useful project-memory loop.

- Guided dashboard setup: choose a project, save an intentional decision, and
  recover it through a read-only request. Decisions remain explicitly unverified.
- Capture stays opt-in. Project setup is not proof of MCP host activation;
  fresh-session tool use must be verified separately in the chosen host.
- Watcher refresh failures retry without requiring another filesystem event.
- An optional Windows pilot ZIP includes the executable, Python wheel, synthetic
  Atlas project, guide, manifest, and per-file checksums. It contains no private
  databases, transcripts, credentials, or operator workspaces.

## Installation and Verification

Use the platform-specific executable or Python wheel attached to this release.
Verify downloads against `SHA256SUMS.txt`. The pilot ZIP also has its own internal
checksum manifest. Follow [the pilot guide](PILOT_GUIDE.md) in a separate pilot
brain directory before using a real project. Back up existing brains before any
runtime upgrade; use [the installation guide](INSTALLATION.md) for normal setup.

Windows x86_64, Linux x86_64, and macOS ARM64 are the native release targets.
The Windows pilot flow does not imply every MCP host has been tested live.
Checksums detect changed bytes, not publisher identity. Native executables are
not OS code-signed; follow your organization's software policy.

## Evidence and Limits

The onboarding and watcher source was integrated through PR #59 at `3fbaa59`.
Its seven post-merge CI checks passed across Windows, macOS, and Linux. Release
alignment and rebuilt artifacts require their own checks before publication.
See the release's CI/native-build links and attached SBOMs for exact build
evidence. Packaging, automated tests, and outreach invitations are not proof of
external installation, repeat usage, or willingness to pay.
