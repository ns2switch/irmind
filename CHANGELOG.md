# Changelog

This file records user-visible changes. The 0.1.0 entry is a draft until the MVP exit criteria in the [reference plan](docs/development/plan.md) are met and the release is tagged.

## 0.1.0 — Unreleased

- Investigate a signed case from the terminal, with a guided first run, conversation, approvals, findings, and evidence views.
- Enforce case and organization scope before remote tool calls; require an analyst signature for external enrichment.
- Keep a signed chain of custody and source manifests; verify, seal, and export cases with an expected public-key fingerprint.
- Ingest synthetic or approved local and cloud-exported logs into partitioned Parquet and query bounded results through DuckDB.
- Configure model, connector, and keystore backends in the TUI. No model or connector is enabled by default.
- Build unsigned binaries for Linux, macOS, and Windows with SHA-256 checksums.

The release is blocked on the documented manual DeepSeek and live test-connector validations. This draft must be checked against the final merged code before tagging.
