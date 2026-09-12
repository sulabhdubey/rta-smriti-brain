# GitHub Release Checklist

This checklist governs updates to the existing public repository. A locally
green working tree is not a published release. Every check must apply to the
exact committed bytes that will be tagged.

## 1. Freeze The Public Candidate

- [ ] Verify the canonical repository root, branch, base commit, upstream, worktrees, and duplicate clones.
- [ ] List every modified, deleted, and untracked entry.
- [ ] Exclude private plans, transcripts, brain databases, logs, context packs, local paths, credentials, and internal reports.
- [ ] Rebuild dashboard assets and verify that `index.html` references exactly the packaged assets.
- [ ] Confirm Python, dashboard, citation, lockfile, CLI, and release-note versions agree.
- [ ] Stage only reviewed public files and compute a deterministic fingerprint from staged Git blobs.
- [ ] Present the exact staged list, fingerprint, diff summary, and privacy boundary for owner approval.

## 2. Qualify The Exact Candidate

Run from the canonical repository root:

```powershell
npm ci
npm audit --audit-level=high
npm run test:unit
npm run build
npm run build:launch
npm run test:operator
npm run test:launch
python -m unittest discover -s tests -v
python -m compileall -q rta_brain tests scripts
python -m pip install -e . --dry-run --no-deps
python scripts/build_installed_smoke.py
python -m rta_brain.cli benchmark --json
python scripts/privacy_scan.py --root .
python -m rta_brain.cli publish-readiness --json
git diff --check
```

- [ ] Run the release-scale performance and Universal Capture probes.
- [ ] Run Gitleaks over Git history and the exact public candidate.
- [ ] Run actionlint over every workflow.
- [ ] Audit Python and npm dependencies and record unavailable checks honestly.
- [ ] Build the wheel and native artifact; inspect contents and scan every archive.
- [ ] Generate and inspect the SBOM and checksum manifest.
- [ ] Complete a security diff review and a frozen-candidate security scan.
- [ ] Re-run any gate invalidated by subsequent byte changes.

## 3. Hosted Integration

- [ ] Commit only after explicit owner approval.
- [ ] Push the feature branch and open a pull request, or explicitly dispatch CI for the candidate.
- [ ] Require green Windows, macOS, and Ubuntu jobs and supported Python versions.
- [ ] Require rendered browser, installed-package, benchmark, packaging, and native-binary checks.
- [ ] Review the committed tree and hosted evidence before merge approval.
- [ ] Merge without rewriting the reviewed candidate, then verify `main` CI.

## 4. Tag And Publish

- [ ] Obtain explicit approval for the annotated `vX.Y.Z-alpha` tag and formal prerelease.
- [ ] Tag the frozen release commit and push only that tag.
- [ ] Verify tag-triggered Windows x64, Linux x64, and macOS native builds.
- [ ] Combine the three binaries, wheel, `SHA256SUMS.txt`, SBOM, and release notes.
- [ ] Verify every checksum and privacy-scan the final release directory.
- [ ] Create the GitHub prerelease and upload the exact verified assets.
- [ ] Download every public asset, verify it against the manifest, and run clean public installation smoke tests.

## 5. Synchronize Public Surfaces

- [ ] Update README, changelog, installation, architecture, usage, security, privacy, release verification, citation, fact sheet, and asset manifest.
- [ ] Replace candidate wording with the actual tag, commit, CI runs, artifact names, hashes, and honest limitations.
- [ ] Refresh synthetic desktop, capture, evidence, and mobile screenshots without local or private data.
- [ ] Update the launch website version, release link, feature copy, CI links, native-build links, screenshots, metadata, and social preview.
- [ ] Build and browser-test the site before the post-release documentation commit.
- [ ] Verify GitHub Pages after deployment at desktop, tablet, and mobile widths.

## 6. Final Public Audit

- [ ] Confirm the default branch, tag, Release, README, website, package metadata, binaries, wheel, checksums, SBOM, screenshots, and documentation identify the same version.
- [ ] Confirm no private path, project content, database, transcript, token, key, internal report, or local artifact is public.
- [ ] Confirm public install and uninstall behavior without deleting user data.
- [ ] Record release receipts and a structured Rta-Smriti checkpoint.

## Repository Metadata

**Description:** Local-first, evidence-aware project memory for AI coding agents.

**Topics:** `ai-memory`, `coding-agents`, `mcp`, `context-engineering`,
`second-brain`, `sqlite`, `local-first`, `codex`, `claude-code`,
`developer-tools`

**Maturity:** Alpha local-first project cognition and MCP context system. Release
claims must remain narrower than the evidence attached to the exact tag.
