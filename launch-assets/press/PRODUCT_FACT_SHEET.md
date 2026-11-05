# Rta-Smriti Brain Fact Sheet

**Category:** Open-source developer tool, local AI project memory

**Current public prerelease:** [`v1.1.0-alpha.12`](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v1.1.0-alpha.12) (`1.1.0a12` package metadata).

**Current update:** Unified Agent Setup connects reviewed host configuration,
consented prompt/reply capture and bounded session recall for Codex and Claude
Code. A three-turn native Codex pilot recovered a corrected decision in a fresh
session. Native Claude capture/recall and cross-host handoff remain unverified.
No new persistent worker, schema migration or model provider is added. Captured
history is not automatically approved truth; selected context may reach the host's
model provider, and normal host use can consume its subscription or API budget.

Project Passport, Verified Source Lens, Explainable Change Impact, Cross-Agent
Continuity and background pacing remain available. Indexed impact hints are not
proof of current-file freshness or breakage. Cooperative pacing is not a CPU cap
or thermal guarantee.

**Release bundle:** SHA-256 checksums, a universal wheel, CycloneDX SBOMs, and standalone Windows, Linux, and macOS artifacts built and smoke-tested from the annotated v1 tag.

**v1.1 milestone:** v1.1A added the Trusted Lifecycle Supervisor, independent health axes, preview-confirmed operation, schema-safe recovery, progressive retrieval, and MCP host profiles. v1.1B adds optional end-to-end encrypted federation with explicit protection scopes, peer permissions, offline reconciliation, revocation, quarantine, encrypted review bundles, and an opaque self-hosted relay. The evidence still distinguishes a documented host recipe from a live fresh-session verification.

**Creation:** Conceived and researched by Sulabh Dubey; built with [OpenAI Codex](https://openai.com/codex/) as the primary AI engineering agent under maintainer review. See [`CONTRIBUTORS.md`](../../CONTRIBUTORS.md).


**License:** MIT

**Runtime:** Python 3.11+, SQLite/FTS5, Cryptography, and bundled Tree-sitter language packages; native artifacts package the runtime for operators who do not want to manage Python dependencies.

**Interfaces:** CLI, stdio MCP server, packaged React operator console

**Problem:** AI coding sessions repeatedly lose repository context, durable decisions, release rules, and prior-session knowledge.

**Solution:** One private brain per project that indexes repository structure, records bitemporal truth and opt-in agent events, compiles governed task context, and projects readiness, coverage, decision debt, change impact, conflicts, and local multimodal evidence without becoming an execution harness.

**Privacy:** Local SQLite storage, loopback-only console, no account, no telemetry, no hosted database, and federation disabled by default. Optional relays receive opaque encrypted envelopes rather than project plaintext.

**Validation:** See [`docs/RELEASE_VERIFICATION.md`](../../docs/RELEASE_VERIFICATION.md) for current, reproducible checks and [`docs/PUBLIC_BENCHMARK.md`](../../docs/PUBLIC_BENCHMARK.md) for the privacy-safe synthetic benchmark. Historical test counts and private-project scale claims are intentionally excluded from this fact sheet.

**Primary differentiator:** Repository evidence, bitemporal truth, durable human memory, session handoffs, evidence class, freshness, governed agent-specific context, deterministic Project Reality, auditable local lifecycle operation, and permissioned encrypted collaboration are combined in one inspectable layer.

**Product boundary:** Rta-Smriti supervises its own local memory services. It does not execute project work, select models, or replace an agent harness.

**Visual evidence:** Project Reality and lifecycle screenshots show v1.1A. The governed-federation screenshot is captured from the synthetic v1.1B Atlas fixture. The retained 60-second demo was captured from `v1.0.2` and is labelled accordingly.
