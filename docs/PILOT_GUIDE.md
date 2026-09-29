# Local Pilot: One Project, One Decision, One Recovery

This guide covers the **Windows x86_64 alpha pilot bundle**. Use the version,
`PILOT_MANIFEST.json`, and bundle checksum to identify the exact build. Obtain
published bundles from the official GitHub release, not an unverified mirror.
macOS/Linux native packages and every live MCP host are not qualified by this
Windows pilot. Automated qualification is not evidence of external pilot adoption.

## Start Without Touching Existing Brains

1. Extract the complete bundle into a new folder. Open PowerShell there.
2. Verify each payload against `SHA256SUMS.txt` before running it:

   ```powershell
   Get-Content .\SHA256SUMS.txt | ForEach-Object {
     $hash, $file = $_ -split '  ', 2
     if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ne $hash) {
       throw "Checksum mismatch: $file"
     }
   }
   ```

   Checksums detect changed bytes; they do not establish publisher identity.
   Accept the bundle only from a trusted source. The executable is not code-signed.
   Follow your organization's software policy; do not bypass security warnings.

3. Start an isolated pilot console, not your existing brain directory:

   ```powershell
   $PilotBrains = Join-Path $env:LOCALAPPDATA 'Rta-Smriti-Pilot\brains'
   .\rta-brain-pilot.exe console start --brain-dir $PilotBrains --port 8775
   ```

   The command opens an authorized loopback browser session and uses a managed
   background process. It does not install login startup. If port 8775 is in use,
   choose another unused port. Keep this folder until the pilot console is stopped.
   Never share the authorization URL or token.

4. Open **New Brain** (or **Projects > Add project brain**). Choose the bundled
   `atlas-demo` folder first. Leave capture off. For a disposable first run, turn
   off **Keep repository index current** too. AGENTS.md and host configuration
   remain unchanged unless separately enabled/configured.

## Prove the Useful Loop

5. Select **Set Up & Start**. Local project readiness is separate from host
   activation. A setup error is not success; read its stage and setup receipt.
6. Save a non-sensitive decision, for example:
   `Atlas uses UTC timestamps for every decision.`
   Operator decisions are stored as **unverified**, not established facts.
7. Select **Recover decision**. Expect the same text, memory ID and project with
   **Read-only recovery**. Close the browser, then reopen the running console:
   ` .\rta-brain-pilot.exe console open --brain-dir $PilotBrains `.
   Select the same project, open First project, select
   **Use selected project**, and recover the decision again.
8. Optional: test the local MCP server, inspect its configuration, then follow
   your host's installation instructions. A local server test does **not** prove
   host registration. Use **Copy fresh-session prompt** in a new agent session
   and verify the actual tool call and returned decision. Until then, host
   activation remains unverified. No host configuration is changed automatically.

The repository includes host-specific recipes in `docs/`. Use current official
host documentation when configuring an agent; do not guess activation behavior.
For a real project, repeat with explicit permission and a new pilot brain. Do not
point this candidate at a production brain or migrate one as part of a trial.

## What to Record

Record the candidate fingerprint, OS/host versions, time to first successful
recovery, whether a fresh agent actually called the tool, and any confusing or
failed step. A successful browser test is not a successful native-host test.
Share only sanitized descriptions or synthetic Atlas screenshots. Do not share
SQLite databases, transcript spools, authorization URLs, tokens, private paths,
or proprietary decisions. No telemetry or feedback is sent by this guide.

## Stop and Recover

```powershell
.\rta-brain-pilot.exe console stop --brain-dir $PilotBrains
```

If you enabled repository sync or capture, stop those workers in Settings before
stopping the console. Stopping the console alone does not stop project workers.
Do not delete a brain while a worker is using it. Keep the pilot data for review
or archive it privately after all workers stop; no deletion is automated here.
To reopen an expired authorization session, rerun `console open`.

The wheel is an alternative for an isolated Python 3.11+ environment, not an
instruction to replace a global installation. Its dependencies may need network
access to install. The Windows executable is the simpler pilot path.

## Maintainer Packaging

Build the dashboard, then the native executable and wheel with the existing
release scripts. Stage to a **new** directory, then run:

```text
python -m scripts.package_pilot_bundle --artifacts <staged-artifacts> --output <new-pilot.zip>
```

Only the two checksum-verified Windows/wheel artifacts, the explicit public
Atlas file list, this guide, license, and manifests enter the bundle. Tests and
privacy review remain separate gates. No commit, release, upload, or outreach
is performed by the packager.
