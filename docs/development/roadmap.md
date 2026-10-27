# Roadmap

This page is for contributors and evaluators planning around current limitations. It describes intended work without promising a release date. Start with the [security model](../security-model.md) before using any integration.

## Available for synthetic evaluation

- A case-centered TUI with signed case creation, evidence ingestion, investigation, approval, verification, sealing, and export.
- Incremental model text in the TUI, IOC/hypothesis/ATT&CK panels with analyst confirmation, and evidence excerpts beside matching approvals.
- Policy-gated reads and analyst-approved external enrichment, with a mandatory content guard.
- Local SQLite custody, a derived DuckDB graph, and Ed25519 signatures from an explicitly selected OS or encrypted-file backend.
- Explicitly selected LLM modules and optional Splunk, AWS, EDR, MISP, and VirusTotal connectors.
- Typed IOC, hypothesis, ATT&CK technique, and timeline proposals with analyst confirmation; reports cite confirmed evidence.
- Case scopes with projects and an optional TOML policy ceiling for remote reads.
- Automated contracts and synthetic end-to-end tests.

## Next work

1. Improve per-batch progress for long local tasks.
2. Stream CloudTrail and JSON parsing for larger inputs, add full-text graph search, and benchmark at least 1 GB of synthetic evidence.
3. Add SIEM alert retrieval and separate tracing from signed audit data.

The merge matrix covers Linux, macOS, Windows, and cross-platform export verification. Release binaries are built once daily on `main` after code changes.

## Later work

A local gateway may run watches and unattended agents. It must use a separate Agent key, allow only scoped reads without an analyst, and keep every approval analyst-signed. Containment remains outside the current scope.

Additional product connectors can follow shared ports after the structural and security work is reviewed. No provider should be enabled by default. Before any production use, the project also needs manual terminal testing, provider compliance approval, external trust anchoring for seals, and a decision on signed binary distribution.
