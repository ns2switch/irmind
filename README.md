# IRMind

> [!WARNING]
> IRMind is under development. It is not ready for real incident investigations or sensitive data. All examples use fictional identities.

IRMind is a local Rust client for incident investigation with signed evidence and policy-controlled tool calls. This repository contains an initial working implementation of the local core.

## Getting started

Build and run `irmind` without a subcommand to open the analyst workspace. On first launch, the TUI asks you to select a signing backend and a credential backend: the OS keyring or an encrypted local file. The file backend works over SSH without a graphical session and asks for a passphrase without echo. Save the analyst public-key fingerprint outside this computer. Create and open cases from the home screen; ingestion, investigation, approvals, verification, reports, sealing, and export are available inside each case. No LLM is selected by default.

```bash
cargo build --release
./target/release/irmind
```

Use `--llm-module <module-id>` only after approving the provider and its data handling. The CLI subcommands remain available for automation and use the same application operations:

In the case workspace, press `Ctrl+K` for the command palette, use `/help` for case commands, and use `/pause` to cancel an active task. Sealing and export require an explicit confirmation showing the case, audit count, final hash, and analyst-key fingerprint. The home screen also verifies an exported package against an expected fingerprint.

```bash
./target/release/irmind case new "CloudTrail alert" --severity high --scope "account 123456789012; 2026-10-23"
./target/release/irmind case scope <CASE_ID> 'v1;sources=splunk-demo;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z'
./target/release/irmind ingest <CASE_ID> cloudtrail.json
./target/release/irmind ingest <CASE_ID> ./evidence-directory
./target/release/irmind timeline <CASE_ID>
./target/release/irmind graph <CASE_ID>
./target/release/irmind entity <CASE_ID> ip 203.0.113.8
./target/release/irmind neighbors <CASE_ID> ip 203.0.113.8 --limit 10
./target/release/irmind entity-timeline <CASE_ID> ip 203.0.113.8 --limit 10
./target/release/irmind graph-path <CASE_ID> ip 203.0.113.8 user alice
./target/release/irmind text-search <CASE_ID> AssumeRole --limit 10
./target/release/irmind raw-records <CASE_ID> <SHA256> 0
./target/release/irmind verify <CASE_ID>
./target/release/irmind verify-graph <CASE_ID>
./target/release/irmind graph-rebuild <CASE_ID>
./target/release/irmind approvals <CASE_ID>
./target/release/irmind approve <CASE_ID> <REQUEST_ID>
./target/release/irmind deny <CASE_ID> <REQUEST_ID> "out of scope"
./target/release/irmind edit-approval <CASE_ID> <REQUEST_ID> '{"ioc":"example.com"}'
./target/release/irmind --policy policy.toml --llm-module llm-openai-compatible ask <CASE_ID> "Investigate this alert"
./target/release/irmind add-finding <CASE_ID> ioc "203.0.113.8" <EVIDENCE_HASH>
./target/release/irmind confirm-finding <CASE_ID> <FINDING_ID>
./target/release/irmind dismiss-finding <CASE_ID> <FINDING_ID> "reason"
./target/release/irmind report <CASE_ID>
cargo build --release --features ti-virustotal
./target/release/irmind --enable-virustotal approve <CASE_ID> <REQUEST_ID>
cargo build --release --features siem-splunk
IRMIND_SPLUNK_URL=https://splunk.example:8089 IRMIND_SPLUNK_SOURCE_ID=splunk-demo IRMIND_SPLUNK_INDEX=cloudtrail IRMIND_SPLUNK_ACCOUNT_FIELD=recipientAccountId ./target/release/irmind --llm-module llm-openai-compatible --enable-splunk ask <CASE_ID> "Investigate this alert"
cargo build --release --features ti-misp
IRMIND_MISP_URL=https://misp.example/ IRMIND_MISP_SOURCE_ID=misp-internal ./target/release/irmind --llm-module llm-openai-compatible --enable-misp ask <CASE_ID> "Enrich this IOC internally"
cargo build --release --features cloud-aws
IRMIND_AWS_SOURCE_ID=aws-demo IRMIND_AWS_REGION=eu-west-1 IRMIND_AWS_ROLE_NAME=IRMindReadOnly ./target/release/irmind --llm-module llm-openai-compatible --enable-aws ask <CASE_ID> "Find AssumeRole events in CloudTrail"
cargo build --release --features edr-crowdstrike,edr-sentinelone
IRMIND_CROWDSTRIKE_URL=https://api.eu-1.crowdstrike.com IRMIND_CROWDSTRIKE_SOURCE_ID=falcon-demo ./target/release/irmind --llm-module llm-openai-compatible --enable-crowdstrike ask <CASE_ID> "Look up the host"
IRMIND_SENTINELONE_URL=https://console.example.com IRMIND_SENTINELONE_SOURCE_ID=s1-demo IRMIND_SENTINELONE_SITE_ID=123456789 ./target/release/irmind --llm-module llm-openai-compatible --enable-sentinelone ask <CASE_ID> "Look up the host"
```

The SQLite case and audit database, DuckDB graph files, seals, and evidence live in the operating system's standard local data directory. Each case has a graph at `graph/<CASE_ID>.duckdb` inside that directory; opening older data migrates graph tables from SQLite. Use `--home <path>` to change the data directory. The explicit `[keystore]` selection is saved in `keystore.toml` there. Both backends keep Analyst and Agent keys separate; the encrypted file is `keystore.enc`. If the selected backend is unavailable, IRMind stops instead of changing backends silently. Press `k` on the home screen to inspect the selected backends, enter credentials, change the file passphrase, or migrate explicitly. See [PLATFORMS.md](docs/PLATFORMS.md) for installation and artifact verification.

Non-secret settings (`IRMIND_*_URL`, source, region, and model) are read at the composition root. Credentials are read only from the selected secret backend by their manifest field name; enter them in the TUI's keystore view. The OS backend uses service `irmind-module` and that field name as the account. The binary fails closed when a required entry is missing and does not accept secrets from environment variables.

No LLM module is enabled by default. Select the OpenAI-compatible Chat Completions module explicitly with `--llm-module llm-openai-compatible` or `IRMIND_LLM_MODULE`. Set the non-secret `IRMIND_MODEL` variable, and store `OPENAI_API_KEY` or `IRMIND_LLM_API_KEY` in the selected secret backend under that field name. For another endpoint, set `IRMIND_LLM_BASE_URL` and store a separate `IRMIND_LLM_API_KEY` entry; the `OPENAI_API_KEY` credential is never reused for a different URL. Keyless HTTP is allowed only on loopback (`localhost`, `127.0.0.1`, `::1`); remote endpoints require HTTPS and their own key. The endpoint must support SSE streaming, tool calling, and a final `stream_options.include_usage` block; incomplete streams are rejected. Optional Anthropic, DeepSeek, and OpenRouter modules use independent keys and models. See [LLM modules](docs/llm-modules.md) to build, configure, or add a provider. The application builds a shared tool catalog and advertises only capabilities backed by active connectors. `irmind ask <CASE_ID> "<alert>"` runs one turn; `irmind tui <CASE_ID>` opens the interface. The TUI displays the full response when the turn ends. Review data classification and egress policy before sending a real alert to the configured endpoint.

```bash
./target/release/irmind seal <CASE_ID>
./target/release/irmind export <CASE_ID> case.irmind.json
./target/release/irmind verify-export case.irmind.json --expected-key <SHA256_FINGERPRINT>
```

`verify-export` does not need the local database. Keep the SHA-256 fingerprint of the analyst's public key through a trusted channel and pass it with `--expected-key`: a package rewritten and signed with another key could still be internally consistent. The local seal also cannot prove that the analyst did not rewrite the entire case with their own key; that requires external anchoring.

## Implemented

- Rust 2024 workspace with an I/O-independent domain, use cases, a mandatory guard, storage adapters, a JSON/CloudTrail parser, and a separate LLM adapter. Compiled products implement `Module`, publish a manifest of ports, tools, and configuration fields, and register at the composition root. The registry supports multiple LLM and EDR modules without changing the engine. Each investigation signs the fingerprints of active modules, the model identifier, and the selected endpoint hash.
- Typed case severity, SHA-256 ingestion of original evidence files or directories, a timeline with source-record references, a local DuckDB entity index for JSON/CloudTrail files and Splunk/CloudTrail JSON results, bounded search, a graph summary, a case-centered TUI, and verifiable export. The CLI traverses directories in a stable order, rejects symbolic links and excessive limits, and skips hashes that already have a signed `GraphIndexed` event.
- Local lookups for entities, co-observed neighbors, and explicit CloudTrail relations (`assumed_role`, role-issued session, source IP, and used or created access keys), with result limits and `hash#record` pointers. The agent accesses them as policy-controlled `Read` tools.
- Paths of up to three co-observation hops, literal search across all fields of indexed original JSON, and retrieval of an original JSON record by pointer. Queries are bounded and pass through policy, guard, and audit when proposed by the model.
- Audit with canonical binary serialization, SHA-256 hash chaining, Ed25519 signatures, append-only SQLite protection, and a final-state seal.
- The signed `GraphIndexed` event records the parser and DuckDB builder versions. The DuckDB file is a derived index: an export includes the original evidence and audit trail, not a copy of the index.
- `verify-graph` reparses signed evidence and compares records, text, observations, and nodes with DuckDB. `graph-rebuild` reconstructs the index from originals in one transaction, even for a sealed case, without adding audit events. Indexes created by older versions must be rebuilt to search all fields.
- Risk follows the tool type. Case evidence queries are read-only; external enrichment proposals remain pending and are not executed. Unknown arguments are rejected.
- Pending requests are recovered from the signed log with their exact tool and arguments. The analyst can list, approve, deny, or edit them in the CLI and the TUI's `Approvals` tab (`↑`/`↓` to select, `a` to approve, `d` to enter a reason, `e` to enter JSON arguments; also `/approvals`, `/approve <id>`, `/deny <id> <reason>`, and `/edit <id> <JSON>`). Editing validates the new call, signs a denial of the old request, and creates another pending request; it does not execute a tool. Approval and denial sign distinct challenges with the analyst key, and a request can be resolved only once. Cases with open requests cannot be sealed.
- `--policy` loads versioned TOML rules with a strict schema: denied tools, an authorized-call quota per case, and a maximum byte count for each result sent to the model. Each investigation logs the file's SHA-256 fingerprint. Without a file, the same restrictive built-in policy applies.
- Policy also limits model tokens per case. Commercial model responses supply usage counts, which are signed in the audit trail; the TUI displays the total. For a cost estimate, set both `IRMIND_INPUT_MICROUSD_PER_MILLION` and `IRMIND_OUTPUT_MICROUSD_PER_MILLION` to the current corporate rates for the model in use.
- Explicit remote scope uses `v1;sources=splunk-demo;accounts=123456789012;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z`. The domain validates source, target, and time window; free-text scopes from older cases remain local-only.
- `case scope <id> <scope>` and the TUI's `/scope <scope>` change scope in a SQLite transaction with a signed event. Verification and export replay these changes and detect tampering with stored scope. A SIEM query restricted by account is not automatically authorized when scope also requires a host.
- `siem_search` uses explicit scope to authorize unattended reads within the declared source, account, and time window. Out-of-scope queries await an analyst signature. The Splunk module builds SPL from a literal search term, fixes the index and account field, limits the window to 24 hours, and caps responses at 5 MB. It requires a read-only role token and valid HTTPS. JSON results are saved as evidence before being indexed as case events.
- `ti_lookup_internal` uses MISP when compiled and enabled and when its source ID is in scope. It submits an exact IOC search to `/attributes/restSearch` with a limit of 20, then stores and redacts the result like other tools. Use a read-only MISP key and valid TLS.
- `cloud_audit_events` uses AWS CloudTrail `LookupEvents` when compiled and enabled. Before searching for an exact event name, STS checks that the credential's actual account matches the scoped account and that the configured dedicated role is in use. The maximum window is 24 hours and the result limit is 20 events. `cloud_identity` queries a specific role or user through IAM `GetRole`/`GetUser` under the same controls. Configure the dedicated role and region. The composition root reads `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and, when needed, `AWS_SESSION_TOKEN` from the selected secret backend. The SDK receives those credentials explicitly and does not consult the ambient profile chain.
- The EDR port and `edr_host_info`, `edr_process_tree`, and `edr_detections` tools accept only `AuthorizedCall`. The domain checks source, host, and, for detections, the case time window; the engine denies sources without a connector or the requested capability. Optional CrowdStrike and SentinelOne modules are independent and may be active together. CrowdStrike provides inventory and alerts; SentinelOne adds descendant process events associated with a threat. Results are retained as evidence and indexed in DuckDB before a redacted copy is shown to the model. See [EDR modules](docs/edr-modules.md).
- `irmind-testkit` provides an in-memory fake EDR and a shared HTTP contract suite passed by CrowdStrike and SentinelOne. It checks host and time filters, ambiguous or out-of-scope responses, errors, limits, redirects, and declared capabilities. The application test checks the signed evidence hash and confirms that the model receives only a redacted copy.
- Local findings linked to an evidence hash: IOCs, hypotheses, ATT&CK techniques, impact, and recommendations. The model or agent can propose them through `case_add_finding`; only the analyst can confirm or dismiss them. The deterministic report includes only confirmed findings and the indexed timeline, with each point linked to evidence.
- The TUI shows findings in a tab and supports `/add <type> <hash> <value>`, `/confirm <id>`, `/dismiss <id> <reason>`, `/findings`, and `/report`.
- The TUI starts at a searchable case list with severity, state, and last activity. It creates signed cases, selects evidence paths, shows compiled and enabled modules, and keeps ingestion, graph rebuild, and verification on cancelable workers. Canceling a task adds a signed operational entry even when the case is sealed. A `ratatui::TestBackend` test completes a case with fake modules without invoking the CLI.
- The VirusTotal adapter is an optional feature requiring explicit enablement and a key in the selected secret backend. It accepts only hashes, ASCII domains, and certain public IPv4 addresses, blocking internal or ambiguous indicators. Signed approval precedes the HTTP request; the full result stays as evidence, and the next session receives a bounded, redacted copy. VirusTotal warns that queried IOCs may enter its data set; consider that effect before approving a lookup.
- Every signed entry has a typed `Actor` (`Analyst` or `Agent`) with event provenance stored separately. Policy receives `ExecutionMode`: unattended mode authorizes only local read queries. A `PendingApproval` binds case, sequence, and arguments, and resolving it requires verification of an analyst-key signature.
- Use cases have no global state and are `Send + Sync`. File locks coordinate each case across processes; SQLite uses WAL for cases and audit, and each case has its own DuckDB graph. Unattended execution and the local gateway are not exposed as commands yet.
- Redaction handles known patterns of secrets, email addresses, and phone numbers; Unicode normalization neutralizes several prompt-injection forms and terminal escape sequences. The original stays local. Startup runs an injection corpus covering logs, CSV, HTML, Unicode, base64, and terminal escapes; its fingerprint is included in the signed guard identifier.

## Current limitations

- Splunk is the only SIEM connector, AWS CloudTrail the only cloud connector, and MISP the only internal threat intelligence connector. LLM modules collect the stream before returning it to the TUI; incremental display is not connected yet. Local providers with different protocols and Qwen do not have dedicated modules yet.
- Remote scope applies to Splunk, AWS CloudTrail, MISP, and both EDR connectors; GCP and Azure are missing. CrowdStrike's general process tree is not implemented. Finding values cannot be edited from the TUI. Cost estimates do not account for cache discounts or provider surcharges.
- Without the VirusTotal feature and explicit enablement, `ti_lookup_external` is neither advertised nor dispatched. Unattended mode is not enabled in the binary. Requests predating the structured format are still recovered from their signed challenge.
- JSON parsing happens in memory. Relations for other products and an accelerated full-text index are missing. `text-search` performs a literal search over indexed JSON. Relations marked as co-observations in `neighbors` and `graph-path` do not establish causality. Indexes created by parsers older than `json-cloudtrail-v4` must be rebuilt with `graph-rebuild` to include new relations. Derived summaries are not original evidence.
- Pattern-based redaction cannot detect every piece of PII or every secret, and injection detection is incomplete. Cases with regulated data require further testing and review of egress policy before enabling a provider.
- Local signatures detect changes to the log and files that are present, but an entire chain can be replaced unless its trusted key is pinned outside the machine. External anchoring is not available yet.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --all-features --locked --test-threads 1
cargo deny check
cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml check
cargo audit --ignore RUSTSEC-2026-0370 --ignore RUSTSEC-2026-0371 --ignore RUSTSEC-2026-0372
```

CI runs these checks with all features enabled and Clippy set to `-D warnings`.

The end-to-end test uses a fake model that tries to send data to external threat intelligence. It checks that the call remains pending, the full data stays local, and tampering with evidence breaks verification.

The `bundled` feature links DuckDB into the binary. The first build compiles its C++ library and needs substantial time and disk space.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in IRMind by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions. See [CONTRIBUTING.md](CONTRIBUTING.md) for the required DCO sign-off.
