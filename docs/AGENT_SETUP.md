# Unified Codex and Claude Code Setup

**Local candidate, not yet published.** This command is not present in the
published alpha.11 package. Use the candidate runtime when evaluating it.

## What It Does

```text
Review setup and data sharing
           |
           v
Back up and merge owned host settings
           |
           v
Accept each host's native trust prompt
           |
           v
Work in Codex OR Claude Code
  user prompt + final assistant reply
           |
           v
Private spool -> validated capture journal
           |
           v
New session in EITHER host
  bounded, unverified history + provenance
```

This is a developer workflow for one canonical project brain, using existing
capture, privacy, Passport and read-only continuity machinery. It adds no
background service, model provider, schema migration or cloud API call.
Normal use of either AI host can still consume that host's subscription or API
budget. Rta-Smriti does not pay for, bypass or control those charges.

## Privacy and Limits

- Capture and model-context disclosure require separate explicit consent flags.
- Only future user prompts and final assistant replies are captured. No tool
  payloads, old transcript files or arbitrary files named by a hook are read.
- Each text field is bounded to 4,000 characters. Known sensitive patterns are
  screened. Screening is not a guarantee that all confidential information is absent.
- Eligible history is limited to seven days. Physical cleanup follows the
  existing retention maintenance policy; expiration is not secure deletion.
- Recall selects up to 12 consented records from the latest 64 journal events,
  within an 8 KiB output budget. Recent records are preferred when records do not fit.
  This is not a complete transcript or an automatic semantic summary.
- Returned context can reach the selected host's model provider. Local storage
  does not make context sent to a cloud model local-only.
- Captured statements remain **unverified history**. They do not become approved
  decisions, verified tests or a replacement for current source files. Corrections
  are retained in chronological order; an agent must resolve their meaning.
- The MCP server is project-bound, uses the core tool profile and has no delegated
  write capabilities. Hook writes are a separate, narrowly consented path.
- Configuration is user-scoped. Hooks refuse events outside the canonical root.
  Existing Rta-Smriti MCP registrations or an independently enabled recall bridge
  require review instead of creating a duplicate or silently replacing consent.

## Set Up

First select an existing, current-schema brain registered to the exact project
root. The dashboard's existing first-project flow can create that brain. For a
new synthetic CLI project, `rta-brain init --db <private-db> --project <name>
--root <project-root>` initializes it. Store the database outside the source repo.
Existing databases needing migration must use the backup-first lifecycle flow.

1. Preview both hosts without changing their configuration:

   ```text
   rta-brain agent-setup plan --db <private-db> --project <name> --root <project-root>
   ```

   Review target paths, hook commands, read-only MCP configuration, the disclosure
   and `plan_digest`. The preview is local and may contain private paths or selected
   history. Do not post it publicly. Add `--host codex` or `--host claude-code` to
   select one host; omitting it selects both.

2. Apply only the reviewed plan:

   ```text
   rta-brain agent-setup apply --db <private-db> --project <name> --root <project-root> --expected-digest <reviewed-digest> --allow-capture --allow-model-context
   ```

   Repeat the same host selection used in the preview. Any change to the reviewed
   plan invalidates its digest. Existing settings are preserved, backed up and
   rechecked by the existing configuration lifecycle. An interrupted multi-host
   installation is reported as partial, not rolled back. Capture/recall remain
   disabled until all setup steps succeed; re-preview and apply to resume.

3. Inspect and accept trust in each host, then open a fresh session. Setup never
   auto-accepts native host trust. Codex loads user hooks from `.codex/hooks.json`
   and MCP from `.codex/config.toml`. Claude Code uses `.claude/settings.json`
   and user MCP configuration in `.claude.json`.

   Claude Code must support command hooks with an `args` array (exec form).
   This avoids shell interpolation on Windows and POSIX. An older host that does
   not support that contract needs an upgrade or a separately reviewed manual
   configuration, not a silently substituted shell command.

## Prove Usefulness

Use a disposable project and harmless text first. Ordinary host inference may
cost money; get the operator's approval before a paid trial.

1. In host A, record a concrete constraint, for example: "Use UTC timestamps."
2. Correct it in a later turn or clarify an exception. Do not claim tests ran
   when they did not.
3. Inspect status:

   ```text
   rta-brain agent-setup status --db <private-db> --project <name>
   ```

4. Start a fresh session in host B. Inspect its hook output and ask it to state
   the constraint, correction and what remains unverified.
5. Compare the answer with the original turns and actual source. A prepared
   context proves transport, not attention, usefulness or correct model reasoning.

`waiting_for_capture` is an honest empty state. `recall_available` means eligible
history exists and owned settings still validate. Native host activation and
model use are **not** inferred from event counts or process-level tests.

## Recovery and Removal

- Busy writer: capture stays in the private durable spool. The hook returns a
  queued warning rather than claiming successful recall. The next capture can
  drain it, or run `agent-setup sync --db <private-db> --project <name>` once.
  Sync processes only this setup's selected sources, in a bounded batch.
- Pause: `agent-setup stop --db <private-db> --project <name>` revokes capture
  ingress and recall. It does not delete existing history or host settings.
- Resume: review and apply a fresh plan. A new capture-source generation avoids
  automatically including the previous consent period's history.
- Uninstall: run `agent-setup plan-remove --db <private-db> --project <name>`,
  then `agent-setup remove --db <private-db> --project <name>
  --expected-digest <reviewed-digest>`. Only owned entries are removed. Existing
  settings and unrelated hooks remain. History is not deleted. Interrupted removal
  keeps delivery disabled; re-preview the remaining steps before retrying.
- Native hosts can save UI, onboarding or trust preferences in the same settings
  file. Unified setup validates its authenticated owned MCP entry and launcher
  independently of those unrelated changes. Reviewed removal preserves the new
  preferences. Changes to the owned command, arguments or environment still fail
  validation. Older receipts without an owned-entry digest require review when
  the file changes; setup never silently upgrades that evidence. Whole-file
  fresh-session proof validation remains strict.
- If configuration or identity has drifted, stop and review. Do not bypass the
  guard by deleting receipts or rewriting the database.

## Qualification Boundary

Tests exercise both directions using synthetic hook inputs, real SQLite capture
and recall, generated commands in fresh processes, writer contention, duplicate
delivery, correction ordering, consent, private filtering and recovery. This is
not an independent-user pilot or proof that every installed Codex/Claude Code
version accepts the configuration. Native host trust and model-use validation
remain separate checks.

Official contracts reviewed for this increment:
[Codex hooks](https://learn.chatgpt.com/docs/hooks) and
[Claude Code hooks](https://code.claude.com/docs/en/hooks).
