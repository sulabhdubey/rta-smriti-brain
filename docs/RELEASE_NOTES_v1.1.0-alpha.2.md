# Rta-Smriti Brain v1.1.0-alpha.2

Release wave: **v1.1B Governed Federation**  
Package metadata: `1.1.0a2`  
Maturity: **Alpha prerelease**

Previous public release: v1.1.0-alpha

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. OpenAI Codex was the primary AI engineering agent under Sulabh's review
and release approval.

## What This Release Adds

The Trusted Lifecycle Supervisor from the first v1.1 alpha now gains an
optional collaboration layer for sharing selected project memory without
turning a relay into the source of truth.

- passphrase-protected Ed25519 and X25519 device identities;
- append-only, signed, end-to-end encrypted federation events;
- local, team, review, and custom protection scopes;
- capability grants, suspension, revocation, re-admission, and scope-key
  rotation;
- permission checks before projection, retrieval, context compilation, sync,
  export, and diagnostics;
- deterministic offline reconciliation that retains concurrent disagreement;
- provenance-linked comments, review requests, proposals, approvals, and
  explicit decisions;
- tamper, replay, missing-parent, revoked-author, and malformed-input
  quarantine;
- selective, signed, encrypted review bundles with audience, privacy-ceiling,
  included-evidence, exclusion, and integrity manifests;
- content-addressed filesystem transport and an optional bounded HTTP relay
  that stores opaque envelopes;
- preview-first CLI, capability-gated MCP, managed sync, lifecycle health, and
  operator-console flows using one state vocabulary.

## Portability And Upgrade Qualification

- Managed workers and generated host launchers preserve a POSIX virtual
  environment's interpreter path instead of dereferencing it to the system
  Python and silently losing installed dependencies.
- The installed-package harness now proves `1.1.0a1` install, `1.1.0a2`
  upgrade, rollback to `1.1.0a1`, re-upgrade to `1.1.0a2`, and uninstall in
  one isolated lifecycle.

## What Remains Local By Default

Federation is off until an operator creates a space and explicitly enrolls a
peer. The existing single-user project brain, capture, truth, retrieval,
context, MCP, and lifecycle workflows continue to operate without a relay or
cloud account.

The relay cannot read encrypted event bodies or become authoritative. Private
identity files, scope keys, passphrase files, local databases, transcripts,
and operator receipts remain local artifacts and must not be published.

## Important Limits

- Public-key fingerprints identify devices, not verified real-world people.
- Revocation prevents future authorized writes and access to newly rotated
  keys; it cannot erase plaintext a peer legitimately received earlier.
- v1.1B uses an auditable append-only event protocol and does not claim MLS or
  Signal protocol compatibility.
- The optional HTTP relay is a self-hosted transport primitive, not a managed
  collaboration service.
- Codex has a protocol-verified MCP fresh-session receipt. Other documented MCP
  hosts remain recipe-tested until a native fresh-session receipt exists.
- The public retrieval benchmark is a small synthetic regression harness, not
  external proof of superiority.
- This release is for technical early adopters. A simplified nontechnical
  personal second-brain experience is a later product wave, not a hidden mode
  in this release.

## Start Here

1. Install and start one local project brain using
   [Installation](INSTALLATION.md).
2. Complete the synthetic [10-minute Atlas path](ATLAS_10_MINUTE_PATH.md).
3. Read [Governed Federation](FEDERATION_GUIDE.md) before creating identities,
   invitations, or relay configuration.
4. Review the [v1.1B threat model](security/v1.1b-federation-threat-model.md)
   before sharing sensitive project evidence.

Exact tests, security checks, artifacts, checksums, hosted CI, and publication
receipts are recorded in [Release Verification](RELEASE_VERIFICATION.md). A
passing local test is evidence for that test, not a universal correctness or
production-readiness claim.
