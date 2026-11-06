# Rta-Smriti Brain v1.1.0-alpha.13

**Alpha prerelease.** Preserve evidence status through governed context compilation.
Package version: `1.1.0a13`. Previous public release: v1.1.0-alpha.12.
No schema migration, new persistent worker, cloud service or paid model call.

## What Changed

A synthetic end-to-end example exposed a gap between the truth ledger and the
context compiler: a failed recorded check could make the ledger claim stale,
while compiled context still supplied the assertion without that status.

The repair carries effective state, assertion verification and recorded-check
status into truth candidates and their rendered evidence. Expiry and explicitly
registered contradictions are preserved as well. The compiler can retain stale
material as labelled evidence; it must not silently present it as a current fact.

Historical reads use the requested recorded boundary, not future validator
results. Validation-derived information retains the strictest contributing
privacy class. Validator IDs, paths and configurations are not disclosed by the
new status summary. Existing token budgets include the rendered status text.

## Inspect the Proof

- [Recorded executable demo](https://sulabhdubey.github.io/rta-smriti-brain/evidence-demo/)
- [Memory trust: decisions, receipts, security and conflicts](MEMORY_TRUST.md)
- Reproduce with `python scripts/demo_truth_lifecycle.py --source . --output output/truth-proof`.

The fixture uses fictional data and actual engine calls. It demonstrates
preserved corrections, explicit revalidation, labelled conflicts, blocked agent
self-verification, privacy filtering and an integrity-checked compilation receipt.
It is not a native model session, independent-user acceptance or a security audit.

## Qualification Boundary

Validators run when explicitly requested. A fresh index does not mean every
decision has been re-proven. Registered conflicts are not a general resolver
for disagreements between arbitrary host instruction files or skills.

Native Claude capture/recall and cross-host handoff remain unverified. The earlier
synthetic Codex pilot retains its original host/version scope. Captured history
remains unverified. Selected context may reach the chosen model provider.

Project Passport, Verified Source Lens, Explainable Change Impact, the
trusted lifecycle supervisor and governed federation remain available. Existing media
retains its original capture labels. No private project databases or settings
are bundled. See [Release Verification](RELEASE_VERIFICATION.md) and the
[versioned receipt](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.1.0-alpha.13)
for exact-source CI and artifact results.

The release bundle comprises three native binaries, a universal wheel, three
CycloneDX SBOMs and `SHA256SUMS.txt`. Verify hashes and build provenance; these
are not Windows vendor signing or macOS notarization. Back up before upgrading,
retain the prior runtime, and refresh MCP. Upgrade/rollback checks use alpha.12.

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh Dubey;
built with Codex (OpenAI), under maintainer review. This is not an OpenAI product
or endorsement.
