# Rta-Smriti Brain v1.1.0-alpha.9

**Alpha prerelease.** Verified Source Lens and cross-platform startup repairs.
Package version: `1.1.0a9`.
Previous public release: v1.1.0-alpha.8
No database schema change, new background worker, cloud service, or account.

## Verified Source Lens

Use CLI or the extended/full MCP profile to find indexed Python symbols, outline
a current file, and expand a selected definition using its outline revision.
Source hashes, canonical project binding, privacy classification, and bounded
file/parser/output limits are checked before serving source. Stale, unindexed,
unsupported, private, and unsafe inputs are refused rather than guessed.

The first increment supports Python through the standard-library AST parser.
Expansion returns complete LF-normalized source lines, not byte-identical files
or a guarantee that the code is correct. The default core MCP profile remains
12 tools; Source Lens is opt-in through extended/full discovery. See the
[Source Lens guide](SOURCE_LENS.md) for commands, limits, and privacy behavior.

## Reliability and Security

- MCP startup and progressive retrieval use query-only connections rather than
  acquiring a writer during ordinary reads.
- Fresh project bootstrap lets the database connector create an owner-private
  POSIX brain directory. Existing nonprivate directories are refused by read-only
  clients, never silently chmodded; review permissions using the guide.
- The Vite build dependency resolves to patched 6.4.5. No audit gate was lowered.
- Installed-wheel upgrade/rollback checks now use alpha.8 as their pinned baseline.
  Wheel and native smoke tests exercise Source Lens success and refusal paths.

Project Passport, the trusted lifecycle supervisor, and governed federation
remain available. Capture, federation, and background indexing remain explicit.

## Upgrade and Limits

Back up the brain before replacing its runtime. Stop only that runtime's managed
workers, install the matching wheel or native artifact, then restart through the
existing launcher. Keep the previous package for rollback. A newer database schema
must not be opened by an older runtime, and an installed launcher must not be
confused with a source checkout.

An authorized MCP host receives selected source and may send it to its model
provider. Local storage does not mean selected output stays off-cloud. Redaction
is imperfect; review exact output before sharing. Source Lens is a bounded
retrieval tool, not an execution harness, a full code auditor, or all-language
navigation. No hosted marketplace or paid offering is included.

Native artifacts carry GitHub build provenance, not vendor code-signing or
notarization. Verify downloads with `SHA256SUMS.txt`. See
[Release Verification](RELEASE_VERIFICATION.md) for source-bound qualification
and publication receipts. Historical evidence retains its original scope.

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh Dubey;
built with Codex (OpenAI), under maintainer review. This is not an OpenAI product
or endorsement.
