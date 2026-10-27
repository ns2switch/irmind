# Roadmap

[Español](../es/roadmap.md)

This page is for contributors and evaluators planning around current limitations. It describes intended work without promising a release date. Start with the [security model](../security-model.md) before using any integration.

## Available for synthetic evaluation

- A conversation-first TUI with a multiline prompt, scrollable signed activity cards, command completion, and an optional case sidebar. Case creation, evidence ingestion, investigation, approval, verification, sealing, and export remain in the same workspace.
- Incremental model text in the TUI, IOC/hypothesis/ATT&CK panels with analyst confirmation, and evidence excerpts beside matching approvals.
- Policy-gated reads and analyst-approved external enrichment, with a mandatory content guard.
- Local SQLite custody, a derived DuckDB graph, and Ed25519 signatures from an explicitly selected OS or encrypted-file backend.
- Explicitly selected LLM modules and optional Splunk, AWS, EDR, MISP, and VirusTotal connectors.
- Typed IOC, hypothesis, ATT&CK technique, and timeline proposals with analyst confirmation; reports cite confirmed evidence.
- Case scopes with projects and an optional TOML policy ceiling for remote reads.
- Automated contracts and synthetic end-to-end tests.

## MVP scope

The MVP has a fixed scope:

1. Stream CloudTrail and JSON ingestion, add full-text DuckDB graph search, and benchmark at least 1 GB of synthetic evidence.
2. Retrieve SIEM alerts and keep diagnostic tracing separate from signed custody events.
3. Replace free-form model-generated SIEM queries with structured fields, operators, time windows, and simple aggregations translated by the connector.
4. Finish recorded-response tests, shared contracts, and setup guides for the cloud, SIEM, EDR, and threat-intelligence modules already in the workspace.

Release `v0.1.0` only after every [reference-plan milestone](plan.md) passes, the model's manual test is documented, at least one connector is tested against a real test environment, and the tag includes a changelog and downloadable binaries. All current modules remain experimental until these checks pass. There is no release date yet.

The merge matrix covers Linux, macOS, Windows, and cross-platform export verification. Release binaries are built once daily on `main` after code changes.

## After the MVP

Chronicle, GCP, Azure, and other product connectors may follow the shared ports. External anchoring of case seals is also deferred. A local gateway may run watches and unattended agents; it must use a separate Agent key, allow only scoped reads without an analyst, and keep every approval analyst-signed. Containment remains outside the current scope.

No provider should be enabled by default. Before production use, the project also needs manual terminal testing, provider compliance approval, and a decision on signed binary distribution.
