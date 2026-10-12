# Project Passport

Project Passport is a focused return-to-project workflow built on the existing
Rta-Smriti engine. It does not require a model, account, API key or subscription.
Available in the v1.1.0-alpha.8 prerelease. This is a local workflow, not a hosted
or paid service. See [release verification](RELEASE_VERIFICATION.md) for the
qualified scope and current publication evidence.

## Open It

Start the existing authenticated operator console and choose **Project Passport**
under Overview. The same browser session authorizes the simpler Passport view.
The URL uses `?view=passport`; preserve the console's capability fragment when
opening it in a fresh browser session. Never share that capability URL.
If authorization expires, obtain the launcher's current private URL and open it
in a new tab. A fragment-only navigation does not reload the application's session.

For an isolated demonstration after installing the package:

```sh
python -m rta_brain.passport_demo
```

The demo opens two fictional projects on a free loopback port. No personal brains
are discovered or changed. The terminal displays the private demo directory. Use
`--data-dir <empty-directory>` to choose its location, and reuse that directory
to keep your demo edits. `--no-open` suppresses browser opening. Stop the process
with Ctrl+C. The demo does not install startup tasks or launch capture workers.

## First Project

Select **Add project**, enter the intended folder, and optionally name it.
Automatic folder indexing and Codex session capture both start unchecked.
Selecting capture authorizes local ingestion of matching sessions, including text.
No agent instruction file is written. Standard engine exclusions apply, including
Git metadata and common secret files. Check the operator console's file inventory
and index settings for exclusions, large-file policy and source coverage.

Folder selection is a typed local path. PDF, Office, email and
meeting connectors, native folder pickers and cloud sync are not included.

## Four Views

1. **Resume:** review the last checkpoint and deliberately save your next objective,
   next action, reported evidence, open questions and repetition warnings. Saves
   use a version fence so another writer's checkpoint is not silently overwritten.
2. **Changes:** see bounded indexed activity since the checkpoint. **Refresh folder
   index** is an explicit local operation and may take time on a large folder.
   The activity view is not a complete diff: it does not establish deletions,
   unindexed edits or current filesystem freshness. It never declares the working
   folder unchanged from a matching timestamp alone.
3. **Decisions:** record what was decided and why. New entries remain unverified
   operator testimony. Historical verification labels are not reverified by opening
   Passport. Private/restricted/malformed privacy metadata is excluded.
4. **Handoff:** choose a neutral label and individual checkpoint fields, decisions
   or index summary. Selection starts empty. Preview, inspect redactions, acknowledge
   your privacy review, then copy or download Markdown/JSON. No assistant is contacted.

Saving a decision preserves a checkpoint draft. Switching projects clears the
handoff selection; unsaved edits require confirmation. Drafts and handoffs are not
persisted to localStorage. A reload recovers saved records, not unsaved text.

## Portable Contract

JSON identifies `format: rta-project-passport` and `format_version: 1`. It contains
only selected evidence and a user-chosen project label, not the brain database path
or canonical folder binding. Lists are capped at 40 rows, decision excerpts at
4,000 characters, and portable JSON at 256 KB. Truncation is explicit.

The displayed SHA-256 is for the exact UTF-8 JSON bytes, including the final newline.
The Markdown digest is available in the API response. These are checksums, not
signatures, encryption, proof of authorship or proof that the evidence is true.
Markdown places source text inside literal code fences, including hostile markup.
Text clipboards may normalize line endings; use downloaded files for byte checksums.

Preview and delivery recheck the visible snapshot revision. A changed visible
snapshot requires a new preview; omitted records and unindexed filesystem changes
are not monitored by that revision. This is a point-in-time handoff, not a lease
that constrains an external assistant or guarantees nothing changes after download.

Known secret and absolute-path patterns are redacted, but detectors can miss names,
client information and sensitive meaning, or over-redact benign text. Always review
the exact handoff. Downloaded files and the clipboard are outside the brain's access
controls. Clearing a brain does not recall copies already shared elsewhere.

## MCP Integration

An optional read-only profile exposes only `brain_capabilities` and
`brain_project_passport`. The normal core profile is unchanged.

```sh
python -m rta_brain.mcp_server --db <brain.sqlite> --project <project-name> --root <project-folder> --tool-profile passport
```

Use the host's documented stdio registration process with that executable and those
arguments. No write or capture permissions are required. The profile supports:

```json
{"action":"inspect"}
```

This returns metadata, available decision IDs and an opaque revision, without
checkpoint/decision text. For an explicitly authorized next-action handoff:

```json
{
  "action": "preview",
  "revision": "<revision from inspect>",
  "selection": {"label": "Project", "checkpoint_fields": ["next_action"]}
}
```

MCP preview shares the selected result directly with its calling host. The dashboard
review checkbox is not an MCP permission boundary. Grant this profile only to a host
authorized to read that project; do not assume local storage means the host cannot
send returned text to a cloud model. Public-only privacy profiles cannot retrieve
these internal project records.

A fresh stdio client is tested in the local acceptance suite. Activation inside each
desktop host is a separate step; this build does not silently change Codex, Claude,
Cursor or other host configurations. Public ChatGPT distribution, OAuth, tunnels,
marketplace submission, inference and billing are not part of this local build.

## Recovery and Removal

Passport reuses the existing checkpoint, memory, database and backup lifecycle.
It creates no second memory store or new schema. The **Operator console** link
retains access to backup, lifecycle, capture, privacy and project-management controls.
Use the existing backup-first process before migration, reset or database removal.
Do not treat a portable handoff as a complete brain backup.

To remove an isolated demo, stop its local console/demo process and remove its isolated
environment. Preserve any demo edits or exports you need first. Do not delete source
project folders. Existing production installations and MCP registrations are unchanged
unless you explicitly replace them.

## Validation Boundary

Automated synthetic checks cover query-only concurrent reads, field selection,
project isolation, privacy classification, redaction, malformed requests, stale
previews, UTF-8, browser workflows, accessible controls and packaging. They do not
establish real-user willingness to pay, all-host activation, perfect confidentiality,
complete source-diff coverage or universal host compatibility. Hosted qualification
is recorded separately in [release verification](RELEASE_VERIFICATION.md).

Research and product direction: Sulabh Dubey. Implementation: Codex (OpenAI).
