# Rta-Smriti Brain v1.1.0-alpha.10

**Alpha prerelease.** Opt-in Cross-Agent Continuity and native Windows host repairs.
Package version: `1.1.0a10`.
Previous public release: v1.1.0-alpha.9
No schema migration, new persistent worker, cloud service, or account.

## Selected Memory Across Sessions

The [Cross-Agent Continuity Bridge](CROSS_AGENT_CONTINUITY.md) supplies explicitly
selected checkpoint fields and decision IDs at Codex or Claude Code session start.
Preview the exact selection and disclosure, approve its digest for each host and
project, then review and install the generated hook through the host's normal
trust workflow. It does not install itself, read transcripts, or create memories.
Capture, MCP writes, and federation permissions remain separate.

Recall is read-only and bounded by input, context, wire-size, age, and a five-second
query deadline. Database identity, canonical checkout, consent, privacy, schema,
and selection failures supply no context. Revocation stops future delivery, not
text already received by a host. Selected checkpoint fields include future saved
values; selected decision IDs never silently select replacement decisions.

## Reliability and Qualification

- Windows Codex commands use PowerShell's call operator and literal arguments.
- Continuity discovery retains matching live sessions while transcripts grow,
  rather than treating ordinary concurrent append as an unusable session.
- The outer host budget is fifteen seconds for shell/startup/cleanup; the query
  deadline remains five seconds. No automatic retry or extra daemon is added.
- Windows kill-on-close jobs and POSIX process groups contain query helpers.
- Native Windows Codex 0.164.0-alpha.11.1 and Claude Code 2.1.310 accepted selected
  context, resumed with a corrected checkpoint, and respected independent consent
  and revocation. Native interruption/shutdown checks observed no remaining bridge
  workers before test-harness cleanup. Only fictional data and localhost model
  receivers were used; no paid provider inference or model-usefulness test ran.
- A flaky shutdown test now distinguishes an interrupted scan from a controlled
  idle stop; production shutdown behavior is unchanged.
- Frozen-binary qualification exercises selection, malformed-input refusal, and
  revocation. Installed upgrade/rollback uses the exact alpha.9 baseline.

Project Passport, Verified Source Lens, the trusted lifecycle supervisor, and
governed federation remain available. See [Release Verification](RELEASE_VERIFICATION.md)
for source-bound hosted and artifact receipts; previous receipts retain their
original scope. Windows native-host proof does not prove native macOS/Linux host
activation, every agent/model switch, model correctness, or long-duration thermals.

## Upgrade and Privacy

Back up the brain before replacing its runtime. Stop only its managed services,
install the matching wheel or native artifact, and retain the previous package
for rollback. Keep private host settings, consent records, and backups out of Git.
Enable the bridge only after reviewing the guide and host trust prompt.

Local storage does not make model-visible output local-only: an authorized host
may send selected text to its provider. Redaction is not exhaustive. Treat the
handoff as untrusted evidence, not instructions or newly verified truth. Removing
consent cannot erase prior host history. No paid offering or marketplace is added.

Verify downloads with `SHA256SUMS.txt`. Native provenance is not vendor signing
or notarization. Older videos and screenshots keep their original version labels.

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh Dubey;
built with Codex (OpenAI), under maintainer review. This is not an OpenAI product
or endorsement.
