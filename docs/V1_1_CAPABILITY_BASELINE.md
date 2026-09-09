# v1.1 Capability And Evidence Baseline

- Baseline date: 2026-09-08
- Candidate baseline commit: `c92d3f462f36cf1eb6f94f07e3e9a60b3b1f0fdf`
- Published release: `v1.1.0-alpha.4`
- Python package metadata: `1.1.0a4`

This document freezes the evidence floor for v1.1B. It distinguishes shipped
implementation, reproducible verification, external host evidence, and planned
work. A green test or configuration recipe is not promoted into a broader
compatibility claim.

`v1.1.0-alpha.4` retains the v1.1B capability boundary established by
`v1.1.0-alpha.2`. It includes the backup-gated schema repair from alpha.3
and adds progressive multi-project verification, truthful continuity states,
bounded console admission, canonical-root repair, and broader rendered
operator regressions. It does not promote any pending native MCP host receipt,
federation outcome, adoption result, or production-support
claim.

## Evidence Labels

- **Verified**: reproduced against the named source commit or backed by the
  published release ledger.
- **Implemented, evidence limited**: the capability exists and has deterministic
  tests, but a required native host or operator receipt is missing.
- **Pending**: required by the v1.1 goal but not yet implemented or qualified.
- **Not applicable**: intentionally outside the Rta-Smriti product boundary.

## v1.1A Capability Matrix

| Capability | State | Evidence boundary |
| --- | --- | --- |
| Trusted Lifecycle Supervisor | **Verified** | Inspect, plan, apply, verify, repair, stop, and remove are covered by published regression, installed-package, browser, interruption, and sustained-run evidence. |
| Independent health axes | **Verified** | Database, repository, capture, continuation, MCP, and federation states are separate; overall readiness is derived rather than inferred from process liveness. |
| Quiet single-supervisor operation | **Verified** | The published two-hour Windows run recorded 10,552 samples, zero failures, a deliberate restart, state mutations, and complete cleanup. Hosted process and browser journeys cover Windows, macOS, and Linux. |
| Backup-first schema negotiation and recovery | **Verified** | The fresh baseline below passes 81 migration, portability, and trusted-lifecycle tests plus 15 subtests. Newer schemas fail closed; interrupted operations retain explicit recovery state. |
| Progressive retrieval | **Verified** | Index, timeline, and cited-evidence stages are snapshot-bound and budgeted. The synthetic public benchmark remains a regression harness, not external superiority proof. |
| Provenance-preserving review bundles | **Verified** | Bounded Markdown and JSON transactions retain evidence references, redaction manifests, non-authoritative summaries, and recovery receipts. |
| Six MCP host configuration profiles | **Verified as recipes** | Codex, Claude Code, Cursor, Zed, OpenCode, and Gemini CLI profiles pass deterministic configuration lifecycle tests. |
| Codex fresh-session MCP protocol proof | **Verified** | One Windows Codex session produced the sealed proof recorded in `MCP_HOST_MATRIX.md`. Caller-provided client identity is not treated as executable attestation. |
| Claude Code fresh-session proof | **Implemented, evidence limited** | Recipe exists; qualifying native-host receipt is pending. |
| Cursor fresh-session proof | **Implemented, evidence limited** | Recipe exists; qualifying native-host receipt is pending. |
| Zed fresh-session proof | **Implemented, evidence limited** | Recipe exists; qualifying sealed receipt is pending. Earlier manual use is not substituted for the release protocol. |
| OpenCode fresh-session proof | **Implemented, evidence limited** | Recipe exists; qualifying native-host receipt is pending. |
| Gemini CLI fresh-session proof | **Implemented, evidence limited** | Recipe exists; qualifying native-host receipt is pending. |
| Installed operator wrapper on the qualification machine | **Verified in isolation; final refresh gated** | Candidate source and the hostile-environment upgrade harness report `1.1.0a4`. The final qualification sequence refreshes the user-level installation from the frozen candidate before publication. |

The five pending native-host receipts limit compatibility claims but do not
block local v1.1B implementation. They remain external evidence tasks and must
be reconciled before a final v1.1 completion claim.

## Frozen Benchmark Baseline

Command:

```bash
python rta-brain.py benchmark --json
```

Fresh result on the baseline commit:

| Measure | Result |
| --- | ---: |
| Dataset | `Rta-Smriti Public Retrieval Corpus v1` |
| Dataset SHA-256 | `e6b64d89ad5e3838312f644c3240e43cbf514912a8b08443764ea3449e6e03d7` |
| Lexical nDCG / recall / MRR | `1.0 / 1.0 / 1.0` |
| Hash-hybrid nDCG / recall / MRR | `1.0 / 1.0 / 1.0` |
| Lexical p95 | `6.370 ms` |
| Hash-hybrid p95 | `7.889 ms` |
| Cognition, continuation, contradiction, decision debt, authority abstention, governance, stale rejection | `1.0` each |
| Context compiler continuation | `1.0`, up from the packaged v0.6 comparison baseline of `0.25` |
| Optional semantic comparison | `not_requested` |

These perfect scores apply only to the small synthetic corpus. v1.1B must not
weaken them, and v1.2 must replace them as the primary quality evidence with
larger public and original continuity benchmarks.

## Frozen Performance Baseline

Command:

```bash
python scripts/performance_probe.py --profiles 100 1000 --assert-bounds
```

Environment: Windows AMD64, Python 3.13.7. Results vary by hardware,
filesystem, antivirus, parser selection, and optional models.

| Files | Index | Deep freshness | Search p95 | Context p95 | Cognition p95 | Brain size | Peak traced allocation |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 1.739 s | 0.069 s | 12.342 ms | 18.584 ms | 12.647 ms | 1.23 MiB | 0.83 MiB |
| 1,000 | 16.273 s | 0.325 s | 59.650 ms | 68.018 ms | 14.483 ms | 4.63 MiB | 1.78 MiB |

Federation adds separate budgets. It must not make local-only indexing,
retrieval, context compilation, or cognition exceed the existing generous
regression ceilings when federation is disabled.

## Frozen Privacy And Recovery Baseline

| Gate | Fresh result |
| --- | --- |
| Repository privacy scan | **Pass**: no credential signatures, absolute user paths, forbidden files, or configured denied terms |
| Migration, portability, and trusted-lifecycle suite | **Pass**: 81 tests and 15 subtests |
| Public data rule | Only synthetic projects, opaque peer identifiers, and generated test keys may enter fixtures or screenshots |
| Local-first default | Collaboration remains disabled unless the operator explicitly creates a federation space |
| Recovery invariant | An interrupted or rejected operation must leave the prior local brain and private key material usable or report incomplete rollback explicitly |

## v1.1B Required Delta

The following remain **Pending** at this baseline:

1. Peer and device identity with protected private keys and stable public
   fingerprints.
2. Selective end-to-end encrypted append-only replication.
3. Per-memory protection scopes enforced before ingest, retrieval, context,
   sync, export, and diagnostics.
4. Offline deterministic reconciliation that retains contradiction,
   attribution, valid time, transaction time, and explicit decisions.
5. Comments, approval proposals, decisions, and immutable audit history.
6. Epoch rotation, revocation, replay rejection, tamper quarantine, device-loss
   recovery, and honest prior-plaintext limitations.
7. Signed and encrypted review bundles with audience and privacy-ceiling proof.
8. Optional self-hosted relay that stores opaque ciphertext and cannot become
   the source of truth.
9. CLI, MCP, and dashboard operator journeys for novice, maintainer,
   security-reviewer, and offline roles.
10. Full Windows, macOS, Linux, migration, packaging, security, privacy,
    performance, browser, and human-operator release evidence.

## v1.1B Published Reconciliation

The published `v1.1.0-alpha.2` release implements items 1-9 above. Qualification
exercised schema migration, protected identity files, signatures,
encryption, scope authorization, invitation exchange, deterministic offline
merge, temporal projection, comments, review decisions, revocation, epoch
rotation, quarantine, encrypted review bundles, filesystem and HTTP relay
transport, managed sync, CLI, MCP, lifecycle, and dashboard contracts.

The release does not convert the frozen v1.1A baseline into a retroactive
claim. The final release record names the candidate and merge commits, exact
test counts, security and privacy results, performance deltas, sustained-soak
result, installed-package and native-artifact acceptance, hosted
Windows/macOS/Linux CI, and post-publication checks.

| v1.1B area | Published state | Evidence boundary |
| --- | --- | --- |
| Identity, signatures, and encrypted event envelopes | **Published; verified** | Local adversarial tests plus tag-built Windows, macOS, and Linux native smoke |
| Protection scopes and capability ledger | **Published; verified** | Frozen candidate review, tests, security scans, and owner approval |
| Offline reconciliation and temporal projection | **Published; verified** | Local Windows/Linux and hosted cross-platform execution |
| Revocation, rotation, replay, tamper, and quarantine | **Published; verified** | Local adversarial coverage plus hosted policy, privacy, and artifact gates |
| Encrypted invitations and review bundles | **Published; verified** | Local round trips plus tag-built artifact acceptance |
| Filesystem and optional HTTP relay | **Published; verified** | Local transport tests and hosted native federation smoke; no managed relay claim |
| CLI, MCP, lifecycle, managed sync, and dashboard | **Published; verified** | Hosted cross-platform, rendered website, and anonymous wheel acceptance |
| Public release and cross-platform qualification | **Complete for v1.1B alpha scope** | [Release](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.1.0-alpha.2), [main CI](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/34188509475), and [tag build](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/34190615497) |

The final local qualification passed Windows and Ubuntu regressions, installed
`1.1.0a1` to `1.1.0a2` upgrade/rollback/re-upgrade/uninstall, Windows native
smoke, `17` rendered operator journeys, dependency and secret audits, privacy
inspection, and a two-hour federation soak. The soak completed `1190` cycles,
recovered `39` simulated outages and `19` database restarts, rotated keys `9`
times, converged, exposed no relay plaintext, and removed temporary state.

The targeted post-fix Codex security scan completed with zero findings. A later
whole-repository coordinator invocation did not return a report and was
terminated after an abnormal multi-hour wait; it is recorded as unavailable
additional coverage, not as a pass or a finding-free result.

Codex remains the only MCP host with a sealed native fresh-session protocol
receipt on the qualification machine. Other host recipes remain evidence
limited and must not be described as live verified.

The public tag resolves to main commit
`39e77a9fdfb9639dfd4d8d82fc96ab92cd32fe4e`. All eight uploaded assets were
downloaded anonymously; the seven payloads matched the checksum manifest with
SHA-256 `a3586b9c21977a983e25882420252fbc9132a45b1bcc75b71cde1ef6763b5310`.

## Outreach Gate

Proof-led outreach to Codex Workshop and other relevant operators should begin
after this baseline is reviewed and the latest public build is named precisely.
Use one request: run the ten-minute Atlas path or one real project and report
installation, continuity, and MCP evidence. Feedback is external evidence for
v1.1B; it does not replace reproducible release qualification.
