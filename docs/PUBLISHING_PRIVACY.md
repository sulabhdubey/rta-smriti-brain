# Publishing Privacy Guide

Rta-Smriti Brain is designed to index private repositories and private agent threads. That makes publishing hygiene important.

Local storage is scoped to the operator's OS account, not a security boundary between mutually untrusted processes using that same account. POSIX installs enforce owner-only modes for brain and daemon artifacts; Windows installs inherit directory ACLs. Public examples and release assets must use synthetic data regardless of those local controls.

Continuity capture stays local but may contain sensitive conversation and tool output. The adapter redacts common credential fields and token shapes and truncates oversized payloads, but this is defense in depth, not a guarantee that arbitrary secrets cannot appear. Never publish brain databases, daemon logs, captured events, checkpoints, or generated context packs from real projects.

## Never Commit

- `.rta-smriti/`
- `*.sqlite`
- `*.sqlite-shm`
- `*.sqlite-wal`
- private thread exports
- local dashboard logs
- screenshots containing real project names, file paths, customer data, or unreleased products
- generated context packs from private projects
- API keys, tokens, cookies, credentials, or `.env` files

## Safe To Commit

- source code
- tests with demo data
- docs with neutral paths
- demo screenshots made from synthetic projects
- static dashboard build assets
- package manifests
- security policy
- contribution guide
- license

## Pre-Publish Scan

Run the bundled scan over every tracked or unignored public candidate. Add each private client, project, employer, or unreleased product name as a deny term:

```powershell
python scripts/privacy_scan.py
python scripts/privacy_scan.py --deny-term '<replace-with-private-name>'
python scripts/privacy_scan.py --root '<release-artifact-directory>'
```

The bundled check covers credential signatures, Windows/POSIX/UNC user paths, forbidden release files, static bundles, and media bytes up to 25 MB. It never prints a matched secret value.
Artifact-directory mode does not require Git metadata. It rejects missing, empty,
linked, reparse-point, special-file, and unreadable roots; scans standalone files
plus bounded members inside wheel, ZIP, nested ZIP, and renamed ZIP containers;
parses archives from the descriptor-bound bytes already inspected; applies
platform-neutral member-path rules; and enforces scan-wide file, byte, expanded
byte, archive-entry, nesting, and time budgets.

Also run a maintained secret scanner over Git history and the current release candidates. Install Gitleaks from its official release, then run:

```powershell
gitleaks git --redact --no-banner --verbose .
gitleaks dir --redact --no-banner launch-assets
gitleaks dir --redact --no-banner launch-site/public
git diff --check
```

Expected result:

- no real local paths
- no private project names
- no credentials or Gitleaks findings
- no private SQLite brain files
- no unreviewed image/video metadata or embedded text

The scans must pass before release. A documented detector pattern may be a reviewed false positive; a real project name, path, credential, database, or context pack is always a blocker. Record allowlists narrowly and review them in the pull request.

## Demo Data Rule

Every public screenshot, video, or GIF should be produced from synthetic demo projects such as:

- `demo-web`
- `demo-api`
- `demo-docs`

Do not use personal, client, employer, unreleased, or private product data in public launch assets.

## Default Brain Location For Users

Documentation should use:

```powershell
$env:USERPROFILE\Documents\Rta-Smriti\brains
```

On macOS or Linux, the recommended location is:

```bash
$HOME/.local/share/rta-smriti/brains
```

Avoid publishing machine-specific examples such as:

```powershell
C:\Users\<real-name>\...
```

## Release Checklist

Before every public release:

```powershell
npm run build
python scripts/privacy_scan.py
python -m pytest -q
python -m compileall -q rta_brain tests
pip install -e . --dry-run --no-deps
python rta-brain.py publish-readiness --json
```

Then run Gitleaks and inspect the final Product Hunt gallery, social preview, poster, and representative video frames before publishing.
