# CLI automation reference

This page is for scripts and reviewers who need a non-interactive operation. Analysts should use the [TUI getting-started guide](../getting-started.md). Running `irmind` without a subcommand opens the TUI.

## Global options

| Option | Meaning |
| --- | --- |
| `--home <PATH>` | Override the standard local data directory. |
| `--policy <PATH>` | Load versioned policy TOML. |
| `--llm-module <ID>` | Select a compiled model module explicitly. |
| `--passphrase-fd <FD>` | Read the selected file keystore's passphrase from an explicit descriptor; Windows supports `0` only. Omit it for a no-echo terminal prompt. |
| `--enable-splunk`, `--enable-aws`, `--enable-crowdstrike`, `--enable-sentinelone`, `--enable-misp`, `--enable-virustotal` | Enable a compiled connector for this run. |
| `--help`, `--version` | Display command help or version. |

The [configuration guide](../configuration.md) lists non-secret environment settings, keystore selection, and credential names. A connector switch requires its Cargo feature in the binary.

For automation, the scope argument uses `v2;sources=...;accounts=...;projects=...;hosts=...;from=...;to=...`. Comma-separated values and UTC timestamps are required for remote access. Example: `v2;sources=splunk-demo;accounts=000000000000;projects=;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z`. Existing signed v1 scopes remain valid. Flags override environment variables, which override `config.toml`, which overrides defaults. This encoding is internal to the CLI and case storage; use the TUI form for interactive work.

## Cases and evidence

| Command | Purpose |
| --- | --- |
| `irmind case new <TITLE> --scope <SCOPE> [--severity <LEVEL>]` | Create a signed case. |
| `irmind case list` | List cases. |
| `irmind case show <CASE_ID>` | Show case details. |
| `irmind case scope <CASE_ID> <SCOPE>` | Sign a new scope. |
| `irmind ingest <CASE_ID> <PATH>` | Add a bounded file or directory without following symlinks. |
| `irmind evidence <CASE_ID> <HASH> [--output <PATH>]` | Display or save original evidence. |
| `irmind findings <CASE_ID>` | List proposed and confirmed findings. |
| `irmind add-finding <CASE_ID> <KIND> <VALUE> <EVIDENCE_HASH>` | Propose a finding. |
| `irmind confirm-finding <CASE_ID> <FINDING_ID>` | Confirm it with the analyst key. |
| `irmind dismiss-finding <CASE_ID> <FINDING_ID> <REASON>` | Dismiss it. |
| `irmind report <CASE_ID>` | Generate a report from confirmed findings. |

## Investigation and approvals

| Command | Purpose |
| --- | --- |
| `irmind ask <CASE_ID> <ALERT>` | Run one model turn; requires explicit model selection. |
| `irmind approvals <CASE_ID>` | List pending calls. |
| `irmind approve <CASE_ID> <REQUEST_ID>` | Sign and execute one approved call. |
| `irmind deny <CASE_ID> <REQUEST_ID> <REASON>` | Sign a denial. |
| `irmind edit-approval <CASE_ID> <REQUEST_ID> <ARGS_JSON>` | Replace a pending request with validated arguments. |
| `irmind tui <CASE_ID>` | Open the TUI directly on one case. |

## Graph and timeline

| Command | Purpose |
| --- | --- |
| `irmind graph <CASE_ID>` | Show the case graph summary. |
| `irmind graph-rebuild <CASE_ID>` | Rebuild the derived graph from signed originals. |
| `irmind verify-graph <CASE_ID>` | Compare the graph with signed originals. |
| `irmind timeline <CASE_ID>` | List timeline events. |
| `irmind entity <CASE_ID> <KIND> <VALUE>` | Look up an entity. |
| `irmind neighbors <CASE_ID> <KIND> <VALUE> [--limit <N>]` | List bounded neighbors. |
| `irmind entity-timeline <CASE_ID> <KIND> <VALUE> [--limit <N>]` | Show activity for an entity. |
| `irmind graph-path <CASE_ID> <FROM_KIND> <FROM_VALUE> <TO_KIND> <TO_VALUE>` | Find a bounded path. |
| `irmind text-search <CASE_ID> <QUERY> [--limit <N>]` | Search indexed text. |
| `irmind raw-records <CASE_ID> <HASH> <INDEX>` | Read one source record. |

## Custody

| Command | Purpose |
| --- | --- |
| `irmind verify <CASE_ID>` | Verify audit signatures and evidence hashes. |
| `irmind seal <CASE_ID>` | Make a verified case read-only. |
| `irmind export <CASE_ID> <PATH>` | Verify and export a sealed case. |
| `irmind verify-export <PATH> --expected-key <FINGERPRINT>` | Verify a package without unlocking a local keystore. |

Use `irmind <COMMAND> --help` to check positional arguments for the installed binary. Keep the expected key fingerprint outside the exported package and obtain it through a trusted channel.
