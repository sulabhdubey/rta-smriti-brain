# Rta-Smriti Brain Fact Sheet

**Category:** Open-source developer tool, local AI project memory

**Local candidate:** `v1.0.0-alpha` (`1.0.0a1` package metadata; not yet published)

**Current public prerelease:** [`v0.9.1-alpha`](https://github.com/sulabhdubey/rta-smriti-brain/releases/tag/v0.9.1-alpha)

**Published release:** v0.9.1-alpha adds progressive operator loading and race-safe multi-project isolation. Its public bundle includes SHA-256 checksums, a universal wheel, CycloneDX SBOMs, and standalone Windows, Linux, and macOS artifacts verified from the annotated tag.

**Creation:** Conceived and researched by Sulabh Dubey; built with [OpenAI Codex](https://openai.com/codex/) as the primary AI engineering agent under maintainer review. See [`CONTRIBUTORS.md`](../../CONTRIBUTORS.md).

**License:** MIT

**Runtime:** Python 3.11+, SQLite/FTS5, Cryptography, and bundled Tree-sitter language packages; native artifacts package the runtime for operators who do not want to manage Python dependencies.

**Interfaces:** CLI, stdio MCP server, packaged React operator console

**Problem:** AI coding sessions repeatedly lose repository context, durable decisions, release rules, and prior-session knowledge.

**Solution:** One private brain per project that indexes repository structure, records bitemporal truth and opt-in agent events, compiles governed task context, and projects readiness, coverage, decision debt, change impact, conflicts, and local multimodal evidence without becoming an execution harness.

**Privacy:** Local SQLite storage, loopback-only console, no account, no telemetry, no hosted database.

**Validation:** See [`docs/RELEASE_VERIFICATION.md`](../../docs/RELEASE_VERIFICATION.md) for current, reproducible checks and [`docs/PUBLIC_BENCHMARK.md`](../../docs/PUBLIC_BENCHMARK.md) for the privacy-safe synthetic benchmark. Historical test counts and private-project scale claims are intentionally excluded from this fact sheet.

**Primary differentiator:** Repository evidence, bitemporal truth, durable human memory, session handoffs, evidence class, freshness, governed agent-specific context, and deterministic Project Reality are combined in one inspectable local layer.
