# Cross-Agent Continuity Bridge

An opt-in, local SessionStart hook for Codex and Claude Code. It supplies selected
checkpoint fields and decisions from an existing project brain. It does not read
the host transcript, start a daemon, call a model, or change host settings.

Available from `v1.1.0-alpha.10`; alpha.9 downloads do not contain it. Native
Windows Codex 0.164.0-alpha.11.1 and Claude Code 2.1.310 accepted selected context,
resumed with a correction, and respected separate revocation. Codex interruption
and abrupt Claude shutdown left no observed query workers before harness cleanup.
These checks used fictional data and a localhost receiver, not provider inference.
Native macOS/Linux host activation and model usefulness are not established by
these Windows checks or by the cross-platform protocol tests.

```text
Host A -> existing, separately authorized checkpoint/capture path -> local brain
                                                                     |
                                 per-project + per-host consent ------+
                                                                     |
Host B SessionStart -> bounded read-only projection -> selected handoff evidence
```

## Review and Enable

Use the same canonical project checkout and database already registered with
Rta-Smriti. Save a useful checkpoint through the dashboard, `checkpoint` CLI, or
an explicitly write-enabled MCP server. The hook does not create one for you.
MCP memory writes and capture permissions remain separate from bridge consent.

The following uses fictional absolute paths. Substitute your existing database
and canonical checkout; on Windows use the actual absolute Windows paths and
the installed `rta-brain` launcher or executable.

1. Preview only the fields you want available at session start:

   ```sh
   rta-brain continuity-bridge plan --db /private/atlas.sqlite --project atlas --root /work/atlas --host codex --checkpoint-field objective --checkpoint-field remaining_gaps
   ```

   Inspect `context`, `disclosure`, `claims`, `plan_digest`, and the generated
   `configuration_fragment`. This command changes neither consent nor host settings.
   Keep its output private: claims and configuration contain local paths.

2. Enable using the exact digest just reviewed:

   ```sh
   rta-brain continuity-bridge enable --db /private/atlas.sqlite --project atlas --root /work/atlas --host codex --checkpoint-field objective --checkpoint-field remaining_gaps --expected-digest REVIEWED_DIGEST --allow-model-context
   ```

   A changed preview is rejected. Review a new plan rather than substituting an
   unchecked digest. This writes private consent only. It does not install hooks.

3. Review and merge the generated hook fragment into the host's configuration.
   Preserve existing hooks, keep a backup, and add this entry only once. Follow the
   host's current trust and activation workflow; do not bypass it.

4. Repeat plan and enable with `--host claude-code` for the second host.
   Consent for Codex never authorizes Claude Code, or the reverse.

The selection is explicit:

- `--checkpoint-field` can repeat for `objective`, `verified_evidence`,
  `remaining_gaps`, `next_action`, and `prohibited_repetition`.
- `--decision-id` selects a specific active decision from this project's visible
  Passport selection. Inspect it first; do not guess IDs. Up to 20 IDs are allowed.
  Passport currently exposes the latest 40 eligible decisions; an older selected
  ID moving outside that window causes recall to fail closed.
- Selected checkpoint fields include **future saved values**, not only the text
  in the initial preview. Only the named decision IDs are authorized. Replaced,
  restricted, retired, or unavailable decisions are not silently substituted.
- `--max-bytes` defaults to 8192 UTF-8 bytes, including the safety boundary;
  accepted range is 1024-16384. Whole records that do not fit are omitted and
  counted. Identical decision text is deduplicated. Passport may mark long
  decision text as truncated; the bridge preserves that marker.
- `--max-age-hours` defaults to 168; accepted range is 1-8760. A stale selected
  record rejects the handoff. Age is based on when the record was saved, not proof
  that its statements are still true.

## Native Host Configuration

| Host | Reviewed integration boundary |
| --- | --- |
| Codex | Local `SessionStart` hook fragment, using the native JSON output contract. On Windows `commandWindows` uses PowerShell's call operator and literal argument quoting. |
| Claude Code | Local `SessionStart` hook fragment using the native JSON output contract. The Windows `command` is Bash-compatible and requires the host's supported shell environment. |

The generated matcher covers `startup`, `resume`, `clear`, `compact`, and `fork`.
Mid-session model-switch hooks and other agents are not supported by this bridge.
Do not infer universal agent support from an MCP connection.

Sources checked 2026-10-24:
[Codex hooks](https://learn.chatgpt.com/docs/hooks) and
[Claude Code hooks](https://code.claude.com/docs/en/hooks).
Host contracts can change; verify current placement, trust, and activation rules
before installation. Hooks may run before MCP becomes ready; recall therefore
uses the local database directly instead of depending on an MCP handshake.

## Verify Before Relying on It

Use a non-sensitive test project and an unmistakable saved checkpoint. From its
canonical checkout, start a fresh host session and inspect the host's hook output.
Confirm the selected objective appears, omitted fields do not appear, and no
foreign project content appears. Correct the checkpoint in host A, start or resume
host B, and check the correction; repeat in the opposite direction.

Treat these as distinct observations:

1. `enable` succeeded: consent exists, not proof of installation.
2. A manual hook invocation returned context: local protocol execution worked.
3. The native host recorded the hook output: host delivery was observed.
4. The assistant used the right evidence correctly: task usefulness was observed.

A hook response alone never establishes steps 3 or 4. Real model turns may consume
host usage or credits; obtain any required spending approval first. Repeated
resume events intentionally re-read current evidence. There is no durable
exactly-once delivery receipt, so duplicate host registrations can repeat context.

## Privacy, Resource and Recovery Boundaries

- Recall uses query-only SQLite connections and makes no logical database or
  capture-event writes. SQLite may use its normal WAL read coordination.
- Consent binds the database file identity, project, canonical checkout, host,
  selected records, byte budget, and age window. Rebinding or replacing a database
  requires a fresh reviewed plan. Linked paths and unsafe consent files are rejected;
  only the existing checked macOS system-root aliases are normalized.
- Unknown projects, foreign working directories, changed consent, incompatible
  schema, stale data, and malformed input return no context. Hook errors use short
  fixed states instead of private paths or raw exceptions.
- The hook never follows `transcript_path`. Existing capture adapters and the
  private spool remain separately configured and consented.
- Returned text may be sent to the host's model provider. A local database does
  **not** make model-visible text local-only. Known sensitive patterns are screened,
  but redaction is not exhaustive. Treat handoff text as evidence, not instructions,
  permission, or newly verified truth.
- Each call starts one short-lived query child, not a persistent service. The
  parent enforces a five-second child deadline, including blocked input, then kills
  and reaps it. Unix process groups and Windows kill-on-close jobs contain helpers
  launched by the worker, so timeout cleanup also covers them. This is lifetime
  containment for trusted local helpers, not a security sandbox for arbitrary code.
  The host fragment allows fifteen seconds for shell startup and cleanup; the
  query child's five-second deadline is unchanged. Native Windows qualification
  found that seven seconds could cancel a valid result during host startup.
  OS scheduling and filesystem stalls can still exceed ordinary timings; this is
  not a hard real-time guarantee or long-duration thermal qualification.
  Abrupt cancellation by a native host is a separate host-qualification check;
  the automated timeout tests exercise the bridge parent's own deadline path.
- Input is capped at 64 KiB. Context is separately bounded; ASCII-escaped JSON on
  the wire has a 128 KiB ceiling. No network client or additional dependency is added.

To revoke one host immediately:

```sh
rta-brain continuity-bridge disable --db /private/atlas.sqlite --project atlas --host codex
```

Then remove only that Rta-Smriti hook entry from the host configuration. Revocation
preserves the prior consent record as a private backup, leaves brain contents
untouched, and cannot erase context already received by an earlier session. Revoke
each host separately. Keep the adjacent private capture-control directory and its
backups out of version control and public exports.

| Hook warning | Operator action |
| --- | --- |
| `not_enabled` | Review and explicitly enable the intended project and host. |
| `scope_mismatch` / `consent_changed` | Check the checkout and database binding; review a fresh plan. |
| `stale_handoff` | Review the old evidence and save a genuinely updated checkpoint or decision. |
| `timeout` | Continue without this handoff; inspect local health before retrying. No automatic retry is performed. |
| `isolation_unavailable` | The host could not establish worker lifetime containment. No project data was read; check local process restrictions. |
| `invalid_input` / `unsupported_event` | Check the host hook payload and supported event contract. |
| `unavailable` | Run `plan` locally to diagnose schema, selection, permissions, or binding; do not post its private output. |

This bridge does not summarize arbitrary conversations, migrate a brain, change
startup settings, guarantee model behavior, or replace the existing host-specific
capture and installation guides.
