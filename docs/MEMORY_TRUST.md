# What Can You Trust in Project Memory?

Rta-Smriti keeps project memory with evidence and explicit limits. Local storage,
a successful search, and a valid receipt are different guarantees.

## What Happens When a Decision Changes?

Captured conversations retain the old statement and the correction in order.
Both remain unverified history. Structured claims separately support revisions,
superseded/retracted states and recorded-time queries. A later message is not
automatically promoted to verified truth. Rationale must have been recorded to
be recovered; missing intent is not invented.

## Does Changing Code Automatically Re-Prove Every Claim?

No. Source freshness tracks source change. A configured validator checks a
specific assertion when run. Its latest recorded result can mark that assertion
stale, disputed or refuted according to its policy. Expiry is another explicit
signal. Neither a current source index nor an old passing result establishes
that every decision is still correct.

From alpha.13, the governed compiler preserves these states in truth candidate
ranking and rendered evidence. Historical compilation does not import future
check results. Stale evidence may remain available with its status visible;
it is not silently relabelled as current knowledge.

## What If Instructions or Claims Conflict?

An explicitly registered contradiction preserves both branches and surfaces
their disputed state. This is not automatic interpretation of every CLAUDE.md,
AGENTS.md or skill conflict. The host's instruction hierarchy and the operator's
authority remain in control. Ranking or recency does not confer permission.

## What Does a Receipt Prove?

The governed context compiler records selected sources, exclusions, reasons,
token costs and integrity bindings. The receipt explains what was supplied and
the recorded selection process. It does not prove every claim semantically true.
Privacy-excluded information is not revealed just to explain its exclusion.

## How Is Memory Selected?

Unified setup recalls bounded recent consented history: up to 12 records from
the latest 64 journal events, under an 8 KiB budget. That is not a complete
transcript or automatic semantic summary. Task-specific compilation separately
filters scope/privacy, ranks evidence, deduplicates content and enforces budgets.
Eligibility expiry, physical retention cleanup and secure erasure are distinct.

## Is Local Memory Secure by Definition?

No. Local storage reduces dependencies but does not remove the attack surface.
Captured/retrieved text is untrusted evidence, not execution authority. Project
scope, consent, privacy ceilings and capability checks provide boundaries;
they are not immunity from prompt injection or a complete security audit.
See [SECURITY.md](../SECURITY.md) for safeguards and reporting guidance.

Capture and disclosure to the model host require separate consent. Selected
context may reach that host's provider. Secret screening is not perfect: do not
store credentials in project memory. Normal host use may consume subscription
or API usage. Native Claude capture/recall and cross-host handoff remain unverified.

## Try the Reproducible Example

[Open the evidence demo](https://sulabhdubey.github.io/rta-smriti-brain/evidence-demo/).
It uses fictional data and real engine API calls, with no model turn, new worker,
private brain or hosted service. It demonstrates mechanisms, not customer results.

From a source checkout with its package dependencies installed:

```text
python scripts/demo_truth_lifecycle.py --source . --output output/truth-proof
```

Only the generated `public/proof.json` is designed as the shareable result.
Keep raw diagnostics private and review any artifact before posting it.
