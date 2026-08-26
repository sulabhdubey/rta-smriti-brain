# Release Verification

## Published v1.0.2-alpha Verification

`v1.0.2-alpha` is the current public operator-hardening prerelease for v1. Its
formal annotated tag and GitHub prerelease contain the native artifacts,
universal wheel, CycloneDX SBOMs, and checksum manifest built from tagged source.

Qualification combined local Windows operator evidence with hosted CI:

| Release gate | Verified evidence |
| --- | --- |
| Local source regression | `805` Python tests passed, `24` explicit platform or optional-capability skips, and `651` subtests passed |
| Hosted source regression | Publication [PR #33](https://github.com/sulabhdubey/rta-smriti-brain/pull/33) [run 32989286716](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32989286716) and final main [run 32991084143](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32991084143) passed all five Windows, macOS, and Ubuntu jobs |
| Onboarding correction | CLI omission and repeated-onboarding regressions pass; new brains default to hash while existing brains preserve their configured provider unless the option is explicit |
| Real-project lifecycle | All seven enrolled local brains report watcher, capture, and continuity workers running; a 31,449-source large-repository brain retained lexical-only retrieval with `0` updated files and `0` embedded chunks |
| Installed distribution | The anonymously downloaded public `1.0.2a1` wheel installed into a clean temporary environment and passed version, CLI, SQLite, FTS, and doctor smoke |
| Standalone Windows executable | The anonymously downloaded public executable passed version and doctor smoke; SHA-256 `5e0aae8a163f670f95952b9eebe9155282d916bd6c99500beeb465f14cd3767d` |
| Rendered operator UX | Dashboard production build, five unit/security tests, all eight Playwright operator journeys, and launch-site desktop/mobile/interactions/media/links/accessibility QA passed |
| Process UX | Hidden startup and adversarial quoting regressions pass; the real managed lifecycle shows no visible PowerShell, Command Prompt, Windows Terminal, or console-host windows |
| Security and privacy | Actionlint, Gitleaks, npm audit, strict repository-scoped pip-audit, privacy scan, and Microsoft Defender passed; sealed Codex Security diff scan `1bbc3d7a-60b7-42e7-b747-b8963c8bddbb` completed with zero findings |
| Tagged native artifacts | [Run 32992418211](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32992418211) audited, built, smoke-tested, privacy-scanned, and staged Windows x64, Linux x64, and macOS arm64 artifacts from the annotated tag |
| Website publication | Final GitHub Pages [run 32991084093](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32991084093) passed build and deploy; the live site returned HTTP `200` with `v1.0.2-alpha` and no stale `v1.0.1-alpha` marker in the deployed HTML |

### Publication State

- Formal annotated tag: `v1.0.2-alpha`, resolving to main commit `272674cca094447a35307c93ceb05863b84a1b50`
- Formal prerelease: [Rta-Smriti Brain v1.0.2-alpha](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.0.2-alpha)
- Release classification: alpha prerelease
- Published bundle: three standalone binaries, one universal wheel, three CycloneDX SBOMs, and one combined checksum manifest
- Combined `SHA256SUMS.txt` SHA-256: `1ebcf74de7125bfb7a80333be42a1c88882bafb99e35270136a98fe00c4b1744`
- Anonymous post-publication acceptance: all eight assets downloaded without credentials; all seven payload hashes matched the public manifest

## Published v1.0.1-alpha Verification

`v1.0.1-alpha` is the corrected-source operator-readiness patch for v1. The
immutable tag resolves to main commit
`c2dff01b368bdb4d2b759e7a077d07ae0985a966`; the frozen pull-request candidate
was `ae6e8f47d1f4179d822c91d6b52d560deb22332b`.

| Release gate | Verified evidence |
| --- | --- |
| Full local regression | `817` Python tests passed with `23` explicit platform or optional-capability skips; dashboard unit tests and production builds passed |
| Rendered operator acceptance | All `8` Playwright operator journeys passed locally, including five repeated daemon-lifecycle runs and ten repeated stale-preview isolation runs; launch desktop/mobile, interaction, media, link, and accessibility QA passed |
| Pull-request compatibility | [PR #30](https://github.com/sulabhdubey/rta-smriti-brain/pull/30) and [run 32907647386](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32907647386) passed Windows, macOS, and Ubuntu across Python 3.11, 3.12, and 3.13 |
| Post-merge compatibility | [run 32909842646](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32909842646) passed all five jobs on the tagged main commit |
| GitHub Pages | [run 32909842687](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32909842687) passed on the tagged main commit |
| Native artifacts | Tag [run 32910950538](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32910950538) passed Windows, macOS, and Linux binary build, smoke, dependency audit, SBOM, privacy, and checksum stages |
| Security and privacy | Repository privacy scan, staged/history Gitleaks, actionlint, npm audit, pip-audit, package inspection, and Microsoft Defender scan passed; sealed Codex Security diff scan `66844f6f-bd9e-4a5e-8957-1c98ec6504a1` covered all 12 code-bearing surfaces with zero findings |
| Exact-wheel acceptance | The downloaded wheel installed in a clean environment and passed neutral-project bootstrap, indexing, deep identity/freshness checks, structured checkpointing, continuation readiness, context-pack generation, and MCP negotiation with `29` tools |
| Anonymous public acceptance | All eight release files downloaded without authentication; every payload matched the public manifest and the downloaded Windows binary reported `rta-brain 1.0.1a1` |

### Publication State

- Formal annotated tag: `v1.0.1-alpha`
- Formal prerelease: [Rta-Smriti Brain v1.0.1-alpha](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.0.1-alpha)
- Release classification: alpha prerelease
- Published assets: three standalone binaries, one universal wheel, three
  CycloneDX SBOMs, and one combined SHA-256 manifest

The first pull-request Windows attempt passed the complete Python and installed
package stages, then one progressive-loading browser test reached the runner's
90-second ceiling after seven of eight journeys. Ten focused local repetitions
passed, and one bounded rerun passed the unchanged commit's entire Windows job.
The retry is recorded here rather than hidden or counted as independent proof.

### Public Artifact Acceptance

On 2026-08-26, all eight release files were downloaded from public release URLs
without authentication. The seven files covered by `SHA256SUMS.txt` matched:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `rta_smriti_brain-1.0.1a1-py3-none-any.whl` | 526,913 | `afb6e893962810ac5bf842d4e329fec6822fa5d6dee7dd132f9709b345bbbde1` |
| `rta-brain-1.0.1a1-linux-x86_64` | 32,918,720 | `06731d7eb7b32e08305cae897e00df4e44b52e72e2c89b02656a34db9760febb` |
| `rta-brain-1.0.1a1-macos-arm64` | 16,914,736 | `9855807a640408f5bc6a0c257f28b09a5af14d627e34ec46b4f6bde36ccf5c30` |
| `rta-brain-1.0.1a1-windows-x86_64.exe` | 18,156,486 | `8417fdf11dcaf7bdcfe83abfa528f4bebd11fcc9e86a7598087fbb527a169c44` |
| Linux CycloneDX SBOM | 1,164 | `b9995d24f08bb85be4f767a706329c6897446c78cfd0b275984b8d0b7101d014` |
| macOS CycloneDX SBOM | 1,166 | `34a785c50d07a477170ac7bb1a3afa416392335f2ed37107f86762034fb627e8` |
| Windows CycloneDX SBOM | 1,163 | `bcc9eb461b5a6730521ca7848a8098a58e778fb4dbd732fdf31b65734159fee2` |

The combined public manifest has SHA-256
`2a736f3d068ce52495dd15a986d28bdcf77319400bae18cb93aa45b8e261d200`.

The immutable `v1.0.0-alpha` evidence remains below. Its artifacts do not
silently receive the later operator lifecycle corrections.

## Published v1.0.0-alpha Verification

This section records the frozen source, hosted compatibility, immutable tag
build, public artifacts, and anonymous-download acceptance for `v1.0.0-alpha`.
It does not treat source tests as artifact proof or a clone as a verified
installation.

| Release gate | Current evidence |
| --- | --- |
| Project Cognition behavior | Focused reconciliation, budgets, work debt, multimodal lifecycle, interfaces, console, and benchmark tests pass |
| Full Python regression | Hosted Windows ran `817` tests with `12` explicit platform skips; the hosted matrix passed on Windows, macOS, and Ubuntu across Python 3.11, 3.12, and 3.13 |
| Dashboard and launch builds | Dashboard unit suite: `5` passed; dashboard and launch production builds passed |
| Rendered operator acceptance | `8` Playwright operator journeys passed; launch desktop/mobile, interaction, media, link, and accessibility QA passed |
| Synthetic benchmark | Lexical/hash hybrid Recall@K, MRR, and nDCG were `1.0`; cognition gates were `1.0`; governed continuation was `1.0` against the packaged historical baseline of `0.25`. This is synthetic regression evidence, not a market-superiority claim |
| 10,000-source performance | First index `233.56 s`; cached deep freshness `2.427 s`; cognition median `25.7 ms`, p95 `28.089 ms`; context-pack p95 `271.037 ms`; search p95 `258.849 ms` |
| Privacy and security | Exact public-diff privacy and Gitleaks scans passed; a 99-commit Gitleaks history scan passed; npm and Python dependency audits found no known vulnerabilities; actionlint passed; sealed Codex Security scan `8ab0e2aa-a366-4c4a-b60c-8fbccd36e7e2` completed eight surfaces with zero findings |
| Installed package/native Windows | Clean upgrade `0.9.1a1` to `1.0.0a1` and uninstall passed; Windows standalone CLI, SQLite/FTS, MCP, benchmark, Tree-sitter, capture, encrypted and Ed25519 snapshots, background sync, and managed-console smoke passed |
| Live daemon and MCP dogfood | Continuity daemon captured the active task with zero new errors; the generated MCP configuration negotiated successfully, exposed `29` tools, and reported server `1.0.0a1` ready |
| Hosted Windows/macOS/Linux CI | Final repair PR [run 32892589775](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32892589775) and final `main` [run 32894041608](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32894041608) passed all five jobs |
| Native preflight and tag build | Final-main preflight [run 32895430079](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32895430079) and immutable-tag [run 32895977890](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32895977890) passed Windows, macOS, and Linux |
| GitHub Pages | v1 launch-site [run 32889833838](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32889833838) passed; the later operator-console race repair did not change Pages inputs |
| Anonymous download acceptance | All eight public files downloaded without authentication; the seven payload files matched the published SHA-256 manifest |

### Publication State

- Published source commit: `a1b05022aff6df3a066ae5abcad3877f6407eafb`
- Formal annotated tag: `v1.0.0-alpha`
- Formal prerelease: [Rta-Smriti Brain v1.0.0-alpha](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.0.0-alpha)
- Release classification: alpha prerelease
- Published assets: three standalone binaries, one universal wheel, three
  CycloneDX SBOMs, and one combined SHA-256 manifest

### Public Artifact Acceptance

On 2026-08-26, all eight release files were downloaded from public GitHub URLs
without authentication. The seven files covered by `SHA256SUMS.txt` matched:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `rta_smriti_brain-1.0.0a1-py3-none-any.whl` | 526,856 | `16d1a1c14cbf736c02bc5920f03d186e279095c1855196e1dae086726534e03f` |
| `rta-brain-1.0.0a1-linux-x86_64` | 32,916,960 | `0e74fe2ef369e4230688ecd1925ea6cc8d59f57fa2cfa99af3e0afe4d692cb29` |
| `rta-brain-1.0.0a1-macos-arm64` | 16,913,136 | `a0ce50e3b723eaef1b4f2188b82fed31f2b7976721396700f2bd22c52188dbad` |
| `rta-brain-1.0.0a1-windows-x86_64.exe` | 18,157,373 | `c3dfde9834c7dcbf8c01febe39bcee1f29702c625747968262971a30e258b800` |
| Linux CycloneDX SBOM | 1,162 | `3947a65ffea16a7d5ee315a785c06461ee63bde1b9a8e5c360066d76f34cf815` |
| macOS CycloneDX SBOM | 1,154 | `30928e09b6130c23b7459fd026e6e2df3b26ac0e840e369d78826f8fc7e7736b` |
| Windows CycloneDX SBOM | 1,165 | `6c834b5e4b5f690093a5072981eb2a10a639b94e102d029baa0da488096cd923` |

The combined public manifest has SHA-256
`f86c5e197debe71dcf23dfc636c7fb49e2d7186db2ae549d9e6d425618b41376`.
The anonymously downloaded Windows binary reported `rta-brain 1.0.0a1`. The
anonymous wheel installed in a second clean Python environment with its
declared dependencies and reported `1.0.0a1`.

Before publication, the same wheel bytes were exercised end to end against an
isolated project: initialization, indexing, provenance-bearing memory,
structured checkpointing, cached deep SHA-256 freshness, focused context-pack
generation, continuity start/status/stop, and operational readiness passed. A
brain under a shared Windows temporary ACL was rejected fail-closed; the flow
passed after using a dedicated owner-only brain directory.

## Published v0.9.1-alpha Verification

The v0.9.1 patch preserves the published v0.9 architecture and tightens the
operator surface around progressive loading, project isolation, lifecycle
status, and explicit multi-project MCP routing.

| Candidate gate | Result |
| --- | --- |
| Package metadata | `0.9.1a1` / `v0.9.1-alpha` |
| Full local Python regression | 788 passed; 23 explicit platform or optional-capability skips |
| Dashboard unit tests | 5 passed |
| Progressive loading and project-switch isolation | 4 rendered adversarial journeys passed |
| Complete operator browser suite | 7 rendered journeys passed |
| Real local multi-project audit | Passed without browser errors, failed API responses, persistent loading states, false integrity alerts, or mobile overflow |
| Frozen Codex Security diff scans | 13 of 13 operator-readiness surfaces and 12 of 12 release/website code-bearing surfaces covered; zero findings. The later seven-entry concurrency repair was manually reviewed and separately passed regression, privacy, secrets, dependency, workflow, and patch-integrity checks; it is not misrepresented as part of those frozen scans. |
| Privacy and secrets | Repository privacy scan and Gitleaks staged/history checks passed |
| Dependency integrity | npm audit found zero vulnerabilities; Python dependency check found no broken requirements |
| Patch integrity | `git diff --check` and actionlint passed |
| Hosted Windows/macOS/Linux CI | PR [run 32719412677](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32719412677) and post-merge [run 32722109549](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32722109549) passed all five jobs |
| Native binaries, wheel, SBOMs, and checksums | Tag [run 32724105024](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32724105024) passed all three platforms |
| GitHub Pages and anonymous download acceptance | Pages [run 32722110481](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32722110481) passed; eight public assets downloaded anonymously and verified |

### Publication State

- Published source commit: `721bd2ec98395f2be36a3b7ebb60c14bfa63c882`
- Formal annotated tag: `v0.9.1-alpha`
- Formal prerelease: [Rta-Smriti Brain v0.9.1-alpha](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v0.9.1-alpha)
- Release classification: alpha prerelease
- Published assets: three standalone binaries, one universal wheel, three
  CycloneDX SBOMs, and one combined SHA-256 manifest

The first post-merge Windows attempt passed the complete Python and installed
package stages, then Chromium reported runner-level `ERR_NO_BUFFER_SPACE` during
rendered acceptance. One bounded rerun passed the entire Windows job without a
code change. The retry is recorded here rather than hidden or counted as two
independent confirmations.

### Public Artifact Acceptance

On 2026-08-24, all eight release files were downloaded from public release URLs
without authentication. The seven files covered by `SHA256SUMS.txt` matched:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `rta_smriti_brain-0.9.1a1-py3-none-any.whl` | 498,026 | `eb0d526effd5c3cb836e7ba1b1659b614ad1909830a908a5bc78a7e335d44eb1` |
| `rta-brain-0.9.1a1-linux-x86_64` | 32,856,192 | `246706ffd0323d2865f8fff7acd76695118518fa7d7969258fdd5b9eab7a2052` |
| `rta-brain-0.9.1a1-macos-arm64` | 16,856,816 | `b312ea01e20ab6c1ca0657b42e233ed1b02f6b4523b487ac0167597cd3b87e7d` |
| `rta-brain-0.9.1a1-windows-x86_64.exe` | 18,101,869 | `980a3f4aaaee9de97dca050eb81e4bbcf623c6b13148ef4db572da30af54a323` |
| Linux CycloneDX SBOM | 1,160 | `21b8144ca4a7998c01309443c13c9b343e74e6794bb05063a08935ef90018a37` |
| macOS CycloneDX SBOM | 1,164 | `6717dbe8fbca722b6f3132c9f3e818c966b3eb835550f81c108879cce4b02605` |
| Windows CycloneDX SBOM | 1,165 | `b0d3965fb988c8ae744832bae0dadbccacf45635f1a909586e8b493749624778` |

The combined public manifest itself has SHA-256
`03a9e40844a47e9a3d643c67d65e9ca701c3853125c613d3ee6b1028f12bcdb4`.
The anonymously downloaded Windows binary reported `rta-brain 0.9.1a1`. The
anonymous wheel installed in a clean Python environment with its declared
dependencies, reported `0.9.1a1`, and returned an `ok` doctor result. The public
bundle also passed the bounded artifact privacy scan.

### Public Website Acceptance

The deployed website was rendered at 1440 by 900 and 390 by 844. Both views had
zero horizontal overflow, zero page or console errors, zero WCAG 2.0/2.1 A/AA
violations, loaded all images, and loaded the 60.053-second product video. The
release page, installation document, and website URLs all resolved publicly.

The real-project audit used private local brains only as operator fixtures.
Project names, roots, database contents, capability tokens, and local scan paths
are not included in this repository or its release evidence. Managed watchers,
continuity workers, and capture daemons remain explicit opt-in services; stopped
services are reported honestly and are not silently enabled by the dashboard.

The successful security result is a diff scan of the frozen v0.9.1 patch. It
does not replace the repository's existing threat model, privacy scanner,
Gitleaks coverage, dependency audits, hosted matrix, or artifact acceptance
gates. Hosted CI and release artifacts must pass before this candidate is
published.

## Published v0.9.0-alpha Baseline


This page records the evidence boundary for `v0.9.0-alpha`. It separates
source qualification, hosted compatibility, tag-generated artifacts, and
post-publication download checks so a passing test is never presented as proof
of a different release gate.

## Publication State

- Source version: `0.9.0-alpha` (`0.9.0a1` in Python package metadata)
- Published branch: `main`
- Universal Capture source merge: `4f40aff1953d73080aff14dbb7e98034d76af735`
- Final tag commit: `c8002a29c25d63fce5249ff60289966c9dbd3dc4`
- Formal tag: `v0.9.0-alpha`
- Formal release: [Rta-Smriti Brain v0.9.0-alpha](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v0.9.0-alpha)
- Release classification: alpha prerelease

The release workflow produces Windows x64, Linux x64, and macOS standalone
binaries, a universal wheel, CycloneDX SBOMs, and a combined SHA-256 manifest.
Artifact acceptance additionally requires redownloading the public files and
matching them to `SHA256SUMS.txt`.

## v0.9 Scope

The v0.9 line combines four governed foundations:

1. Canonical project identity prevents silent switching between duplicate roots,
   clones, or worktrees.
2. The event-sourced bitemporal truth kernel records what was asserted, when it
   was valid, when it was learned, supporting evidence, contradictions,
   validation, and abstention.
3. The governed context compiler selects agent-specific context under immutable
   task contracts, privacy grants, trust ordering, and hard token budgets.
4. Universal Capture normalizes opt-in agent events through a private bounded
   spool and one per-brain daemon into a redacted hash-chained journal.

Captured content remains untrusted evidence. Replay never executes captured
actions. Read-only MCP responses are project-scoped and path-free by default;
process control, retention, export, redaction, and deletion remain separate
capabilities.

## Verified Source Evidence

| Gate | Result |
| --- | --- |
| Local Python regression | 783 passed, 23 explicit optional-dependency or privilege skips, 649 subtests |
| Focused console, onboarding, and spool suite | 84 passed, 6 skipped |
| Managed console fallback identity tests | 2 passed |
| Dashboard unit and production build | Passed |
| Rendered operator journey | Passed, including Universal Capture export integrity and privacy assertions |
| Installed package lifecycle | Upgrade and uninstall from `0.8.0a1` to `0.9.0a1` passed |
| Windows native smoke | CLI, SQLite/FTS, MCP, benchmark, Tree-sitter, Universal Capture, encrypted snapshot, Ed25519, sync, and console passed |
| Capture performance | 10,000 events at 170.445 events/s; replay page p99 43.071 ms; bounded backpressure verified |
| Feature PR hosted CI | [Run 32635867425](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32635867425) passed Windows, macOS, and Ubuntu |
| Post-merge hosted CI | [Run 32636448594](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32636448594) passed all five jobs |
| Publication metadata PR CI | [Run 32640375142](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32640375142) passed all five jobs |
| Publication merge CI | [Run 32641467412](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32641467412) passed all five jobs |
| Nested-artifact privacy repair | [PR CI 32642651151](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32642651151) and [main CI 32643303151](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32643303151) passed |
| Large native-artifact privacy repair | [PR CI 32644657258](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32644657258) and [main CI 32645754456](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32645754456) passed |
| Final native release workflow | [Run 32646317248](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32646317248) passed Windows, macOS, and Linux |
| GitHub Pages deployment | [Run 32641467447](https://github.com/sulabhdubey/rta-smriti-brain/actions/runs/32641467447) passed; rendered desktop and 390 px mobile checks found no browser errors or horizontal overflow |

The first two native-release attempts failed closed and were not accepted. They
identified incomplete scanning of an ignored nested artifact directory and a
Linux binary larger than the default 25 MiB scan ceiling. The fixes preserved
the 25 MiB archive-member limit while adding an explicit, hard-bounded 128 MiB
top-level release-artifact scan. Only the final green native run above supplied
the public release assets.

## Security And Privacy Evidence

The v0.9 source candidate passed the repository privacy scanner, Gitleaks history
and working-tree scans, actionlint, npm audit, Python dependency audit, wheel
inspection, checksum verification, package-content checks, and focused
security-control tests.

A later Codex Deep Security Scan coordinator attempt is **not** counted as
coverage: both workers were blocked before workspace inventory or source review,
and completion rejected a non-UUID scan identifier. It produced no usable sealed
report and found no file-level issue only because it inspected no files. The
release record does not convert that failed scan into a clean result.

Release publication excludes local brain databases, spools, transcripts,
capability tokens, keys, private project content, raw diagnostics, generated
context packs, operator paths, and the private local v0.9 design/implementation
documents. Public screenshots and media use synthetic data.

## Public Artifact Acceptance

On 2026-08-23, all eight public release assets were downloaded anonymously from
the formal GitHub prerelease. The seven files covered by `SHA256SUMS.txt` matched
their published SHA-256 values:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `rta_smriti_brain-0.9.0a1-py3-none-any.whl` | 494,920 | `9d698d2b75892f0d303b45619b4da3f9663adcaab80bc650cbe851fe1dc31b8b` |
| `rta-brain-0.9.0a1-linux-x86_64` | 32,849,128 | `eb81ef800462eb49244312fe6381158394fe13a7f36d6719ce392e9047ce7896` |
| `rta-brain-0.9.0a1-macos-arm64` | 16,851,760 | `2bdf79dd79b7f18db02e41168b52fdf7696baa33f69319c11fccaec2d1473d4d` |
| `rta-brain-0.9.0a1-windows-x86_64.exe` | 18,095,617 | `4588604261b92e213fd130257e9232e370dd1a77b6f16175aead0bf65829bd91` |
| Linux CycloneDX SBOM | 1,158 | `cf39121d7c7583c7877d75ebd939d6ccc5559583a601bfdc32300a800ce37c28` |
| macOS CycloneDX SBOM | 1,154 | `0717a3ba4cbccb5866fb18fa5c8a11327808ac9c60a0ea7c054f88e7a1ad9c3d` |
| Windows CycloneDX SBOM | 1,163 | `34d1128c251269ff9bb74695b135c0ecc1a7d1d3b065731e5e79acf93f52c18e` |

The public wheel installed successfully in a new Python 3.13 virtual
environment with its declared dependencies. From that clean environment,
`rta-brain --version` returned `0.9.0a1`; initialization in an owner-only brain
directory, repository ingestion, SHA-256 freshness, structured checkpointing,
continuation readiness, and the 24-tool MCP probe passed. The anonymously
downloaded Windows executable also returned `rta-brain 0.9.0a1`.

## Reproduction

Run from the repository root:

```powershell
npm run test:unit
npm run build
npm run build:launch
npm run test:launch
python -m pytest -q
python -m compileall -q rta_brain tests scripts
python scripts/build_installed_smoke.py
python scripts/privacy_scan.py --root .
python scripts/performance_probe.py --profiles 100 1000 --assert-bounds
python rta-brain.py publish-readiness --json
actionlint
gitleaks git --redact --no-banner --verbose .
git diff --check
```

The native release workflow additionally audits dependencies, generates SBOMs,
builds and smoke-tests each operating-system artifact, packages versioned files,
privacy-scans the staged bundle, and uploads it for release assembly.

## Residual Boundaries

- Managed workers are user-level local processes; login startup is explicit.
- Same-user malware or administrator/root access can read operator-owned data.
- Secret detection is defense in depth, not proof against every unknown format.
- Vendor event formats and optional local adapters can change.
- Filesystem deletion cannot guarantee erasure from SSD wear leveling or copies.
- Call edges and unsupported-language parsing remain bounded impact hints.
- The synthetic benchmark is reproducibility evidence, not external superiority
  proof.

See [Publishing Privacy](PUBLISHING_PRIVACY.md), the
[v0.9 threat model](security/v0.9-capture-threat-model.md), and
[Security Policy](../SECURITY.md).

## Historical Evidence

- [v0.6 release notes](RELEASE_NOTES_v0.6.0-alpha.md)
- [v0.4 release notes](RELEASE_NOTES_v0.4.0-alpha.md)
- [v0.3 launch snapshot](archive/LAUNCH_READINESS_v0.3.0-alpha.md)

Historical records describe their own frozen versions and must not be interpreted
as the current v0.9 release state.
