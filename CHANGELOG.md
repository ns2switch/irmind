# Changelog

This file records user-visible changes. IRMind remains a pre-release for evaluation with synthetic data.

## Unreleased

- Add experimental Zeek TSV/JSON and Suricata EVE parser modules with bounded detection, exact indexed timestamps, endpoint-host partitions, source provenance and unconfirmed source detections. They are available after this change; v0.1.x did not ship these modules.

- Add an experimental, separately contained EVTX decoding helper with bounded output, precise timestamps and file-offset provenance. Linux uses Landlock and seccomp; macOS and Windows require their native sandbox to pass a startup probe.

## 0.1.6 — Complete bounded JSON ingestion

### Known issue fixed

- Correct bounded document probing so large single-line JSON exports retain every source byte. In v0.1.1–v0.1.5, JSON files without a `.jsonl` or `.ndjson` extension could fail or omit records when their first line exceeded 4 MiB. The same reader was used for cloud object ingestion. A valid original hash and signed chain authenticate the stored bytes; they do not prove that a parser extracted every record.
- Use `json-stream-v3` for new JSON ingestion. Version the affected ECS, OCSF, DFIR and declarative readers, and count oversized line records as rejected instead of treating a whitespace prefix as an empty line. Preserve record, field, depth and cancellation limits.
- Retire historical parsing implementations. To regenerate evidence with current readers, create a new case and ingest verified originals again. Existing signed entries and export encodings are unchanged; authenticating existing bytes does not require a retired parser. Reinstall approved declarative definitions to select their current reader identity.
- Bind object-storage parsing to the logical object name and reconstruct retained copies from case-local originals. Record the actual parser identity in every new source manifest.
- Add streaming 5, 50 and 200 MiB regressions, signed local/object-ingestion checks and separate current-version format goldens; retain historical golden bytes.

## 0.1.5 — Automatic demo presentation

- Replace the command-driven tutorial with an automatic ten-scene presentation. The real TUI types and runs commands against its isolated synthetic case, with full-width narration and a highlighted investigation area.
- Add Enter, Backspace, Space and Esc navigation, proportional reading time, a clear minimum-terminal notice, visible failures and final exploration/start/exit choices.
- Show scripted responses as a word-preserving stream with source hashes. Sign the simulated enrichment and custody confirmations only within the explicitly isolated demo; no provider is probed and no network is used.
- Exercise every scene in automatic and manual PTYs, including cancellation and terminal/data cleanup. Refresh the complete VHS recording and scene captures from the actual versioned binary.

## 0.1.4 — Card expansion

- Make Ctrl+O expand or fold the selected card from any case-screen focus, falling back to the last expandable card. Keep text drafts and open forms intact.
- Add `/expand` to the shared command menu and help as an alternative for terminal keymaps that intercept Ctrl+O.
- Reveal full multiline notices when expanded; retain guarded display and unchanged policy, custody and signed formats.
- Add TestBackend and cross-platform PTY regression coverage. Native terminal applications, SSH and tmux still need interactive confirmation; CI PTYs are not represented as those manual tests.

- Add the experimental Linux parser module for authentication, auditd, journald JSON and HTTP common/combined exports, with per-ingestion time, bounded partial-event correlation and preserved source precision.

- Add the experimental syslog module: bounded RFC 5424/RFC 3164 and gzip parsing, explicit signed legacy-time context, detection and reproducible Parquet ingestion.

- Add an experimental declarative parser for bounded CSV, JSON/NDJSON and regex formats, with signed definition installation and recovery, pinned reconstruction, and a guarded ten-row preview in `/parsers`.

## 0.1.3 — Guided demo

- Guide the isolated synthetic demo through ten event-driven steps, from evidence exploration and signed approval to findings, custody verification and export.
- Keep one current instruction in the guide. Show completed ingestion as a fact, without competing command suggestions.
- Add command-specific help and optional empty-state hints, with a full tutorial PTY test on Linux, macOS and Windows.
- Record H5 as complete by analyst decision after a natural greeting with real DeepSeek and no unnecessary tool calls. Investigation citations, follow-up, streaming and verification remain pending analyst records; the real-connector validation remains pending.
- Refresh synthetic tutorial screenshots from the actual 0.1.3 binary.

## 0.1.2 — Demo ingest repair

- Show a persistent completion or actionable error after the demo's background ingestion, so the case never appears stuck after evidence is found.
- Use the same parser detection registry and signed `SourceManifestV2` path as ordinary case ingestion in the demo.
- Add experimental, auto-detected Elastic Common Schema NDJSON and OCSF JSON/Parquet parsers as optional Cargo modules compiled by default. Both normalize bounded records into signed local Parquet and preserve source provenance; ambiguous Parquet detection asks the analyst.
- Add experimental parsers for Velociraptor, Hayabusa, Chainsaw, Plaso, and common Eric Zimmerman CSV exports, with synthetic fixtures and parser detection.

## 0.1.1 — Community preview

- Offer a temporary `/demo` case with synthetic HuntEval data and a scripted model, without a configured key or network connection.
- Keep exact greetings conversational by withholding tools, while preserving the structured, signed agent conversation.
- Select the compiled parser from a bounded content sample. Sign its version, detection confidence, selection mode, and bounded rejected-record count in `SourceManifestV2`; existing V1 manifests remain verifiable.
- Provide user-level installers for Linux, macOS, and Windows, and a Linux aarch64 binary. The installers check release hashes and verify Sigstore and GitHub provenance when the tools are available.
- Publish SHA256SUMS, keyless Sigstore bundles, GitHub build attestations, and an SPDX SBOM. Tag builds smoke-test both installers in clean Linux and Windows runners.

Manual validation with a real model and a real connector remains pending. Use synthetic data only; this version is not suitable for real incidents or sensitive data.

## 0.1.0 — Pre-release (2026-10-31)

- Investigate a signed case from the terminal, with a guided first run, conversation, approvals, findings, and evidence views.
- Enforce case and organization scope before remote tool calls; require an analyst signature for external enrichment.
- Keep a signed chain of custody and source manifests; verify, seal, and export cases with an expected public-key fingerprint.
- Ingest approved local and cloud-exported logs into signed, partitioned Parquet; query bounded graph and timeline results directly with Arrow and Parquet, without DuckDB.
- Preserve case conversation and tool-call IDs across model rounds, answer ordinary questions without unnecessary investigation, and summarize work when a turn reaches its limit. Keep case context and evidence out of the trusted system role.
- Evaluate deterministic retrieval against the synthetic HuntEval corpus, including events hidden in 1 GB and 15 GB background corpora.
- Speed up Parquet graph queries with sorted entity rows, row-group pruning, and a signed co-observation artifact. Record the remaining disk and worst-case path work in the post-release issue.
- Add optional, fingerprinted custom CA certificates per connector while retaining TLS hostname verification.
- Configure model, connector, and keystore backends in the TUI. No model or connector is enabled by default.
- Build unsigned binaries for Linux, macOS, and Windows with SHA-256 checksums.

This pre-release is published without the manual H5 validation with DeepSeek or a connector test against a real test environment. Both remain pending and may lead to fixes in 0.1.x. Do not use this version for real incidents or sensitive data. The signed co-observation artifact's disk use, entity lookup latency, and worst-case three-hop path query are tracked in [issue #37](https://github.com/ns2switch/irmind/issues/37). Binaries are unsigned; verify the supplied SHA-256 checksums before use.
