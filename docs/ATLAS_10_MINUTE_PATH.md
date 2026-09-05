# Atlas 10-Minute Target Path

This is the target operator path from a clean source install to a complete,
reversible Trusted Lifecycle Supervisor journey over the public synthetic Atlas
project. It is **not yet a measured timing claim**. Record elapsed time from a
clean machine before describing the path publicly as completed in ten minutes.

Atlas is fictional and contains no private repository or transcript data. The
commands below create an isolated copy, bootstrap one local SQLite brain, start
only the repository watcher, verify it, inspect a path-free review, stop the
watcher, and remove supervisor enrollment. They do not register an MCP host.

## Safety Model

- `inspect`, `plan`, `plan-stop`, and `plan-remove` are read-only.
- `apply`, `stop`, and `remove` require the exact plan and observed-state
  digests returned by the immediately preceding preview.
- If the observed state changes, the command fails closed. Run the preview
  again; do not reuse or edit the old digest.
- `remove` removes lifecycle enrollment after stopping managed services. It
  does not delete the Atlas checkout or SQLite brain.
- The review is non-authoritative and path-free. Verify its evidence before
  using it for a release or recovery decision.
- Keep the brain directory private to the current operating-system account.

## PowerShell

Run in PowerShell with Python 3.11 or newer and Git installed:

```powershell
$RunRoot = Join-Path $env:TEMP ("rta-smriti-atlas-" + [guid]::NewGuid().ToString("N"))
$Source = Join-Path $RunRoot "rta-smriti-brain"
$AtlasRoot = Join-Path $RunRoot "atlas-demo"
$BrainDir = Join-Path $RunRoot "brains"
$BrainDb = Join-Path $BrainDir "atlas-demo.sqlite"

git clone --branch main --depth 1 https://github.com/sulabhdubey/rta-smriti-brain.git $Source
python -m venv (Join-Path $Source ".venv")
$Python = Join-Path $Source ".venv\Scripts\python.exe"
& $Python -m pip install $Source
$RtaBrain = Join-Path $Source ".venv\Scripts\rta-brain.exe"
& $RtaBrain --json doctor

Copy-Item -LiteralPath (Join-Path $Source "examples\atlas-demo") -Destination $AtlasRoot -Recurse
git -C $AtlasRoot init -q
New-Item -ItemType Directory -Path $BrainDir -Force | Out-Null
& $RtaBrain bootstrap-project $AtlasRoot --project atlas-demo --brain-dir $BrainDir --db $BrainDb --json

$Inspect = & $RtaBrain lifecycle inspect --db $BrainDb --project atlas-demo --root $AtlasRoot --brain-dir $BrainDir --json | ConvertFrom-Json
$Inspect | ConvertTo-Json -Depth 12

$Plan = & $RtaBrain lifecycle plan --db $BrainDb --project atlas-demo --root $AtlasRoot --brain-dir $BrainDir --watcher --schema-policy current-only --json | ConvertFrom-Json
$Plan | ConvertTo-Json -Depth 12
if ($Plan.blocked) { throw "Lifecycle plan is blocked: $($Plan.blockers -join ', ')" }

$Applied = & $RtaBrain lifecycle apply --db $BrainDb --project atlas-demo --root $AtlasRoot --brain-dir $BrainDir --watcher --schema-policy current-only --confirm-plan-digest $Plan.plan_digest --confirm-observed-state-digest $Plan.observed_state_digest --json | ConvertFrom-Json
$Applied | ConvertTo-Json -Depth 12

$Verified = & $RtaBrain lifecycle verify --db $BrainDb --project atlas-demo --root $AtlasRoot --brain-dir $BrainDir --proof-level process --json | ConvertFrom-Json
$Verified | ConvertTo-Json -Depth 12
if (-not $Verified.ready) { throw "Lifecycle verification is not ready: $($Verified.reason_codes -join ', ')" }

$ReviewPath = Join-Path $RunRoot "atlas-lifecycle-review.json"
& $RtaBrain lifecycle review --db $BrainDb --project atlas-demo --root $AtlasRoot --brain-dir $BrainDir --json | Set-Content -LiteralPath $ReviewPath -Encoding utf8
Get-Content -LiteralPath $ReviewPath

$StopPlan = & $RtaBrain lifecycle plan-stop --db $BrainDb --project atlas-demo --root $AtlasRoot --brain-dir $BrainDir --json | ConvertFrom-Json
$Stopped = & $RtaBrain lifecycle stop --db $BrainDb --project atlas-demo --root $AtlasRoot --brain-dir $BrainDir --confirm-plan-digest $StopPlan.plan_digest --confirm-observed-state-digest $StopPlan.observed_state_digest --json | ConvertFrom-Json
$Stopped | ConvertTo-Json -Depth 12

$RemovePlan = & $RtaBrain lifecycle plan-remove --db $BrainDb --project atlas-demo --root $AtlasRoot --brain-dir $BrainDir --json | ConvertFrom-Json
$Removed = & $RtaBrain lifecycle remove --db $BrainDb --project atlas-demo --root $AtlasRoot --brain-dir $BrainDir --confirm-plan-digest $RemovePlan.plan_digest --confirm-observed-state-digest $RemovePlan.observed_state_digest --json | ConvertFrom-Json
$Removed | ConvertTo-Json -Depth 12
```

Expected terminal states are `complete` for apply and stop, `verified` with
`ready: true` for process verification, and `removed` for lifecycle removal.
Keep the run directory if you need the brain or review evidence. Delete it only
after deciding those local artifacts are no longer needed.

## Bash

Run on macOS or Linux with Python 3.11 or newer and Git installed:

```bash
set -euo pipefail

RunRoot="$(mktemp -d "${TMPDIR:-/tmp}/rta-smriti-atlas.XXXXXX")"
Source="$RunRoot/rta-smriti-brain"
AtlasRoot="$RunRoot/atlas-demo"
BrainDir="$RunRoot/brains"
BrainDb="$BrainDir/atlas-demo.sqlite"

git clone --branch main --depth 1 https://github.com/sulabhdubey/rta-smriti-brain.git "$Source"
python3 -m venv "$Source/.venv"
Python="$Source/.venv/bin/python"
"$Python" -m pip install "$Source"
RtaBrain="$Source/.venv/bin/rta-brain"
"$RtaBrain" --json doctor

cp -R "$Source/examples/atlas-demo" "$AtlasRoot"
git -C "$AtlasRoot" init -q
mkdir -p "$BrainDir"
"$RtaBrain" bootstrap-project "$AtlasRoot" --project atlas-demo --brain-dir "$BrainDir" --db "$BrainDb" --json

"$RtaBrain" lifecycle inspect --db "$BrainDb" --project atlas-demo --root "$AtlasRoot" --brain-dir "$BrainDir" --json

PlanJson="$("$RtaBrain" lifecycle plan --db "$BrainDb" --project atlas-demo --root "$AtlasRoot" --brain-dir "$BrainDir" --watcher --schema-policy current-only --json)"
printf '%s\n' "$PlanJson"
PlanDigest="$(printf '%s' "$PlanJson" | "$Python" -c 'import json,sys; print(json.load(sys.stdin)["plan_digest"])')"
ObservedDigest="$(printf '%s' "$PlanJson" | "$Python" -c 'import json,sys; print(json.load(sys.stdin)["observed_state_digest"])')"
Blocked="$(printf '%s' "$PlanJson" | "$Python" -c 'import json,sys; print(str(json.load(sys.stdin)["blocked"]).lower())')"
test "$Blocked" = "false"

"$RtaBrain" lifecycle apply --db "$BrainDb" --project atlas-demo --root "$AtlasRoot" --brain-dir "$BrainDir" --watcher --schema-policy current-only --confirm-plan-digest "$PlanDigest" --confirm-observed-state-digest "$ObservedDigest" --json

VerifyJson="$("$RtaBrain" lifecycle verify --db "$BrainDb" --project atlas-demo --root "$AtlasRoot" --brain-dir "$BrainDir" --proof-level process --json)"
printf '%s\n' "$VerifyJson"
printf '%s' "$VerifyJson" | "$Python" -c 'import json,sys; assert json.load(sys.stdin)["ready"] is True'

ReviewPath="$RunRoot/atlas-lifecycle-review.json"
"$RtaBrain" lifecycle review --db "$BrainDb" --project atlas-demo --root "$AtlasRoot" --brain-dir "$BrainDir" --json > "$ReviewPath"
cat "$ReviewPath"

StopPlanJson="$("$RtaBrain" lifecycle plan-stop --db "$BrainDb" --project atlas-demo --root "$AtlasRoot" --brain-dir "$BrainDir" --json)"
StopPlanDigest="$(printf '%s' "$StopPlanJson" | "$Python" -c 'import json,sys; print(json.load(sys.stdin)["plan_digest"])')"
StopObservedDigest="$(printf '%s' "$StopPlanJson" | "$Python" -c 'import json,sys; print(json.load(sys.stdin)["observed_state_digest"])')"
"$RtaBrain" lifecycle stop --db "$BrainDb" --project atlas-demo --root "$AtlasRoot" --brain-dir "$BrainDir" --confirm-plan-digest "$StopPlanDigest" --confirm-observed-state-digest "$StopObservedDigest" --json

RemovePlanJson="$("$RtaBrain" lifecycle plan-remove --db "$BrainDb" --project atlas-demo --root "$AtlasRoot" --brain-dir "$BrainDir" --json)"
RemovePlanDigest="$(printf '%s' "$RemovePlanJson" | "$Python" -c 'import json,sys; print(json.load(sys.stdin)["plan_digest"])')"
RemoveObservedDigest="$(printf '%s' "$RemovePlanJson" | "$Python" -c 'import json,sys; print(json.load(sys.stdin)["observed_state_digest"])')"
"$RtaBrain" lifecycle remove --db "$BrainDb" --project atlas-demo --root "$AtlasRoot" --brain-dir "$BrainDir" --confirm-plan-digest "$RemovePlanDigest" --confirm-observed-state-digest "$RemoveObservedDigest" --json
```

The Bash path has the same expected terminal states as PowerShell. Removal does
not erase `$RunRoot`; retain it for review or remove it manually after deciding
the local evidence is disposable.

## Add MCP After the Lifecycle Path

Generate a local multi-project MCP gateway only after the lifecycle journey is
healthy:

```powershell
& $RtaBrain --json mcp-config --brain-dir $BrainDir --name rta-smriti
```

```bash
"$RtaBrain" --json mcp-config --brain-dir "$BrainDir" --name rta-smriti
```

Then use the [MCP host matrix](MCP_HOST_MATRIX.md) to select the current host
scope, preview and install the configuration, and follow its activation
lifecycle. Recipe availability is not live verification. A host remains pending
until the operator issues `mcp-host challenge`, launches a fresh host that
inherits `RTA_SMRITI_HOST_PROOF_RECEIPT` and the one-use
`RTA_SMRITI_HOST_PROOF_CHALLENGE`, and the server observes real `initialize`,
`tools/list`, `brain_capabilities`, and Atlas `brain_search` requests. Seal that
evidence with `mcp-host prove`, clear the ephemeral variables, and include only
the sanitized receipt in a release ledger. Never put the token in host
configuration, screenshots, logs, or Git.

Rta-Smriti is local-first: the synthetic repository, SQLite brain, lifecycle
receipts, and review stay on the operator's machine unless the operator chooses
to share a deliberately reviewed artifact.

Rta-Smriti was researched and ideated by Sulabh Dubey and built with Codex by
OpenAI. This attribution describes the development process and does not imply
OpenAI endorsement.
