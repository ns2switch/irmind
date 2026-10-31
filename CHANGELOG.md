# Changelog

This file records user-visible changes. IRMind 0.1.0 is a pre-release for evaluation with synthetic data.

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
