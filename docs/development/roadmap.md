# Roadmap

[Español](../es/roadmap.md)

This page is for contributors and evaluators planning around current limitations. It describes intended work without promising a release date. Start with the [security model](../security-model.md) before using any integration.

## Available for synthetic evaluation

- A conversation-first TUI with a multiline prompt, scrollable signed activity cards, command completion, and an optional case sidebar. Case creation, evidence ingestion, investigation, approval, verification, sealing, and export remain in the same workspace.
- Incremental model text in the TUI, IOC/hypothesis/ATT&CK panels with analyst confirmation, and evidence excerpts beside matching approvals.
- Policy-gated reads and analyst-approved external enrichment, with a mandatory content guard.
- Local SQLite custody and a derived Parquet store queried directly with Arrow, with Ed25519 signatures from an explicitly selected OS or encrypted-file backend. Signed source manifests support large cases without an implicit copy of each original; a copy is an explicit option. The 1 GB and 15 GB synthetic benchmarks meet the local ingestion and query targets.
- Explicitly selected LLM modules and optional Splunk, AWS, EDR, MISP, and VirusTotal connectors; Splunk searches use structured fields and aggregations.
- Typed IOC, hypothesis, ATT&CK technique, and timeline proposals with analyst confirmation; reports cite confirmed evidence.
- Case scopes with projects and an optional TOML policy ceiling for remote reads.
- Automated contracts and synthetic end-to-end tests.

## MVP scope

The MVP has a fixed scope:

1. Ingest 15–500 GB cases through signed source manifests, optional original copies, and partitioned Parquet. Bounded Arrow scans query only signed Parquet produced by IRMind. Verify reports missing or changed originals; a sampled check reports its limited coverage. Benchmark 1 GB and 15 GB on a standard runner.
2. Retrieve SIEM alerts and keep diagnostic tracing separate from signed custody events.
3. Keep SIEM searches limited to structured fields, operators, time windows, and simple aggregations translated by the connector.
4. Parse exported CloudTrail, GCP Cloud Audit Logs, Azure Activity and Entra ID sign-in logs, and generic JSON in streaming mode. Migrate existing cases with verification before and after.
5. Read S3, GCS, and Azure Blob objects in streaming mode through explicitly enabled, read-only connectors. Signed case scope v3 names allowed buckets, containers, prefixes, and UTC windows. A complete signed listing precedes each version-bound read; transfer budgets and explicit confirmation limit cost. Test each backend against synthetic recordings.
6. Finish recorded-response tests, shared contracts, and setup guides for the existing cloud, SIEM, EDR, and threat-intelligence modules.

Release `v0.1.0` only after every [reference-plan milestone](plan.md) passes, the model's manual test is documented, at least one connector is tested against a real test environment, and the tag includes a changelog and downloadable binaries. All current modules remain experimental until these checks pass. There is no release date yet.

Every pull request and merge runs Linux checks. Pull requests touching platform code or CI workflows also run Windows and macOS; the full matrix and cross-platform export verification run nightly after main changes and on release tags. Release binaries are built only on tags and qualifying nightly runs.

## After the MVP

[Source-side queries](cloud-query-design.md) are the next step after the MVP: Athena, CloudTrail Lake, and Security Lake for AWS; BigQuery and Cloud Logging Log Analytics for GCP; and Azure Data Explorer and Log Analytics for Azure. Only structured queries are planned, with scan budgets and signed results. Remote re-verification of cloud originals after sealing, Chronicle and other product connectors, external anchoring of case seals, and the local gateway with watches remain deferred. The gateway must use a separate Agent key, allow only scoped reads without an analyst, and keep every approval analyst-signed. Containment remains outside the current scope.

No provider should be enabled by default. Before production use, the project also needs manual terminal testing, provider compliance approval, and a decision on signed binary distribution.
