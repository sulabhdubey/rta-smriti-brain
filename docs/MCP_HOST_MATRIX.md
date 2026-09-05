# MCP Host Matrix

Rta-Smriti Brain v1.1A includes preview-first configuration profiles for six
MCP-capable coding hosts. A profile or recipe is not proof that a host has been
tested live. This matrix keeps those two claims separate.

Last documentation review: 2026-09-05. Host behavior changes independently of
Rta-Smriti, so review the linked host documentation before applying a plan.

## Evidence Labels

- **Recipe available**: Rta-Smriti can describe and preview the host's current
  configuration shape. It does not mean a live host session passed.
- **Protocol verified**: a sealed, nonce-bound receipt proves configuration and
  server-observed MCP activity from one fresh process session: initialize, tool
  discovery, `brain_capabilities`, and an Atlas `brain_search`. MCP `clientInfo`
  is caller-controlled, so the receipt does not independently attest which host
  executable originated the session.
- **Pending**: no qualifying repository receipt exists for this release.

Synthetic unit tests, a valid configuration file, a running server process, or
a visible tool name are useful checks, but none alone is live verification.

## Compatibility Matrix

| Host | Official documentation | Configuration format and scope | Transport | Activation lifecycle | Rta-Smriti recipe status | Fresh-session evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Codex | [MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) | TOML under `[mcp_servers.<name>]`; user `~/.codex/config.toml` or trusted-project `.codex/config.toml` | STDIO, Streamable HTTP | Save, restart the desktop host or IDE extension when required, open a fresh task, then inspect `/mcp` or `codex mcp list` | Recipe available in the v1.1A candidate | **Protocol verified** on Windows during an operator-observed Codex CLI 0.153.1 run; host identity is not independently attested; proof digest `3fd5db9b893db2ed5f9f720615ab171c1e6db0d526969ad2c35bdab92d102718` |
| Claude Code | [MCP documentation](https://code.claude.com/docs/en/mcp) | JSON `mcpServers`; local and user entries in `~/.claude.json`, or project `.mcp.json` | STDIO, SSE, HTTP | Save or use `claude mcp add`, approve project trust when prompted, inspect `/mcp`, then open a fresh session | Recipe available in the v1.1A candidate | Pending |
| Cursor | [MCP documentation](https://cursor.com/docs/mcp) | JSON `mcpServers`; project `.cursor/mcp.json` or user `~/.cursor/mcp.json` | STDIO, SSE, Streamable HTTP | Save, inspect the MCP server and enabled tools in Customize, then open a fresh agent session | Recipe available in the v1.1A candidate | Pending |
| Zed | [MCP documentation](https://zed.dev/docs/ai/mcp) | JSON `context_servers` in Zed settings | Local STDIO for the Rta-Smriti recipe; Zed also documents remote servers | Save, inspect the MCP server panel, then open a fresh agent thread. Connected Zed versions can refresh changed tool lists without a full restart | Recipe available; see [Zed MCP](ZED_MCP.md) | Pending |
| OpenCode | [MCP documentation](https://opencode.ai/docs/mcp-servers/) | JSON `mcp.<name>` in `opencode.json`; the managed recipe emits `type: "local"` and a command array | Local STDIO, remote Streamable HTTP | Save, enable only the required server/tools, inspect `opencode mcp list`, then open a fresh session | Recipe available in the v1.1A candidate; the managed writer intentionally does not edit JSONC | Pending |
| Gemini CLI | [MCP documentation](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md) | JSON `mcpServers`; user `~/.gemini/settings.json` or project `.gemini/settings.json` | STDIO, SSE, Streamable HTTP | Save, restart Gemini CLI, inspect the configured server and allow-listed tools, then open a fresh session | Recipe available in the v1.1A candidate; server aliases containing `_` are rejected | Pending |

The table makes only the host claims supported by the named evidence. A host
moves from **Pending** to **Protocol verified** only when a fresh session
produces a sanitized sealed receipt. A host-specific execution claim also needs
separate operator or host-side evidence because MCP client identity is not an
attestation. The Codex proof used the public Atlas
fixture and candidate binary on 2026-09-05; it did not expose the operator's
project paths, transcript content, challenge token, or local brain data. The
other five recipes remain pending because their native CLIs were unavailable
on the qualification machine. Cross-platform package and lifecycle execution
is tracked independently in hosted CI.

## Preview Before Any Host Change

List the built-in profiles:

```powershell
& $RtaBrain mcp-host profiles --json
```

```bash
"$RtaBrain" mcp-host profiles --json
```

Generate the server command and arguments first with `mcp-config`, then preview
the exact host target selected from that host's current documentation:

```powershell
& $RtaBrain --json mcp-config --brain-dir $BrainDir --name rta-smriti
& $RtaBrain mcp-host plan-install --profile codex --target $CodexConfig --server-name rta-smriti --command $GeneratedCommand --arg $GeneratedArgument --json
```

```bash
"$RtaBrain" --json mcp-config --brain-dir "$BrainDir" --name rta-smriti
"$RtaBrain" mcp-host plan-install --profile codex --target "$CodexConfig" --server-name rta-smriti --command "$GeneratedCommand" --arg "$GeneratedArgument" --json
```

Do not put a token, secret, private transcript, or publishable project content
in the command or arguments. The preview classifies the target against the
selected host's documented path policy and shows the effective server entry
with local paths and sensitive values replaced by fingerprints or redaction
markers. Inspect that classification, effective change, proposed digest,
replacement warning, activation state, and plan digest. Apply only the exact
digest the operator reviewed. A completed plan is terminal and cannot be
replayed. Rta-Smriti also refuses unmanaged same-name collisions, target or
parent identity changes after preview, and restores the prior configuration on
removal only while the target remains unchanged.

## Nonce-Bound Fresh-Session Verification

A qualifying proof is a one-use challenge tied to the installed configuration
receipt. Issue it before the verification session starts:

```powershell
$Challenge = & $RtaBrain mcp-host challenge --receipt $InstallReceiptPath --confirm-plan-digest $InstallPlanDigest --json | ConvertFrom-Json
$env:RTA_SMRITI_HOST_PROOF_RECEIPT = $InstallReceiptPath
$env:RTA_SMRITI_HOST_PROOF_CHALLENGE = $Challenge.challenge_token
```

```bash
ChallengeJson="$("$RtaBrain" mcp-host challenge --receipt "$InstallReceiptPath" --confirm-plan-digest "$InstallPlanDigest" --json)"
ChallengeToken="$(printf '%s' "$ChallengeJson" | python3 -c 'import json,sys; print(json.load(sys.stdin)["challenge_token"])')"
export RTA_SMRITI_HOST_PROOF_RECEIPT="$InstallReceiptPath"
export RTA_SMRITI_HOST_PROOF_CHALLENGE="$ChallengeToken"
```

Launch the target host as a new child of that shell so it inherits both
ephemeral variables. Do not add either value to the permanent MCP host
configuration. The receipt path is local control metadata. The challenge token
is a one-use secret: do not print it, paste it into a ticket, capture it in a
screenshot, enable shell tracing around it, or commit it. The challenge file
and sealed proof retain only a digest of the raw token.

The MCP server boundary must then observe, from one fresh host session:

1. a real MCP `initialize` request; its caller-supplied client name and version
   are not accepted as host identity evidence;
2. a real `tools/list`, binding the discovered catalog to the fresh session;
3. a successful `brain_capabilities` call showing that mutating tools are not
   available under the read-only proof profile; and
4. a successful read-only `brain_search` against the public Atlas fixture.

The observations are written by the running MCP server, not supplied to
`mcp-host prove` by the caller. After the fresh host session has completed those
calls, seal the evidence:

```powershell
& $RtaBrain mcp-host prove --receipt $InstallReceiptPath --challenge-token $Challenge.challenge_token --confirm-plan-digest $InstallPlanDigest --json
Remove-Item Env:RTA_SMRITI_HOST_PROOF_RECEIPT -ErrorAction SilentlyContinue
Remove-Item Env:RTA_SMRITI_HOST_PROOF_CHALLENGE -ErrorAction SilentlyContinue
$Challenge = $null
```

```bash
"$RtaBrain" mcp-host prove --receipt "$InstallReceiptPath" --challenge-token "$ChallengeToken" --confirm-plan-digest "$InstallPlanDigest" --json
unset RTA_SMRITI_HOST_PROOF_RECEIPT RTA_SMRITI_HOST_PROOF_CHALLENGE ChallengeToken ChallengeJson
```

The proof stores fingerprints and digests rather than the raw session ID, host
version, local path, token, or Atlas content. It is rejected if the token is
missing or reused, the session or tool catalog changes, the configuration
drifts, Atlas is not the searched project, or the read-only capability evidence
is absent. Clear the two environment variables and shell variables after
`prove`, then close the proof session.

The public CLI exposes challenge issuance and proof sealing. Server observation
has no caller-facing command by design: it happens only inside the MCP request
path. Until a native host completes this workflow and its sanitized receipt is
included in the release ledger, keep that host **Pending**. Do not translate
manual screenshots, a successful `mcp-doctor`, caller-supplied booleans, or
`clientInfo` into host identity verification.

## Local-First Boundary

Rta-Smriti's MCP server is local STDIO in the recommended flow. Brain databases,
configuration backups, lifecycle receipts, and proof material remain on the
operator's machine. Project-scoped host configuration can be version-controlled
by the host, so inspect it before commit and never embed a private absolute path
that another operator should not receive.

Rta-Smriti was researched and ideated by Sulabh Dubey and built with Codex by
OpenAI. This attribution describes the development process and does not imply
OpenAI endorsement.
