# Rta-Smriti Brain v1.1.0-alpha.6

Package metadata: `1.1.0a6`
Maturity: **Alpha prerelease**
Previous public release: v1.1.0-alpha.5

Rta-Smriti Brain was conceived, researched, and product-directed by Sulabh
Dubey. OpenAI Codex was the primary AI engineering agent under maintainer review.

## Consolidated Reliability Maintenance

This maintenance release preserves the trusted lifecycle supervisor, guided
first-project onboarding and optional governed federation of v1.1B.

- Selective imports use one transaction rather than copying the entire database
  back over the destination. Concurrent commits are preserved; interrupted imports
  roll back, including when called inside an existing transaction.
- Export and snapshot destinations cannot overlap their source database, SQLite
  sidecars or authentication inputs. Private and public key paths must differ.
- Empty-graph messages no longer overlap the project icon. Collapsed groups are
  no longer reported as missing evidence.
- All seven hash-locked release toolchains use urllib3 2.8.0, addressing three
  upstream chunked-response and HTTPS-proxy advisories.

## Installation and Verification

Use the platform-specific executable or universal Python wheel attached to this
release. Verify downloads against `SHA256SUMS.txt` and available GitHub provenance
attestations. See [installation](INSTALLATION.md) and the [pilot guide](PILOT_GUIDE.md).
Back up existing brains before upgrading. No database schema change is introduced.

Native targets are Windows x86_64, Linux x86_64 and macOS ARM64. Native executables
remain unsigned by an OS code-signing certificate. Checksums detect changed bytes;
they do not by themselves authenticate the publisher.

## Evidence and Limits

The local audit reproduced the data-loss and graph-state defects before repair.
Its final regression passed 1,301 Python tests, 718 subtests and 31 browser tests.
Thirty local platform/privilege-specific tests were explicitly skipped, not
counted as successful coverage. Dependency, privacy, secrets, installed-package
upgrade/rollback and bounded performance checks passed locally.

Publication requires hosted cross-platform CI, the extended lifecycle soak,
native artifact validation and public download verification. The GitHub release
body will link the exact successful runs; this source record does not pre-claim
their completion. See [release verification](RELEASE_VERIFICATION.md).

This is not proof of production support, external pilot success, every optional
model configuration, or the complete live MCP-host matrix. Capture remains opt-in;
federation remains disabled by default.
