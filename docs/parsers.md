# Log parsers

This page helps analysts choose a local log parser and test a custom format before ingestion. All current parsers are experimental and validated with synthetic data. See [modules](modules.md) for individual formats and [configuration](configuration.md) for the data directory.

## How a parser is selected

The registry passes at most the first 64 KiB to every compiled detector. A filename is a hint, never proof. One unique match at 80% confidence or higher selects the parser automatically. Low-confidence matches and ties require analyst confirmation. Unattended ingestion does not choose an ambiguous parser. The selected identity, version, confidence and selection mode enter the signed source manifest.

`/ingest` opens the file picker. Use `/ingest --parser <name> <path>` for an explicit choice; it is audited. In **Settings → Preferences**, inspect compiled parser names and versions. Compilation includes no automatic remote model selection.

| Parser | Input | Detection | Mapped fields | Status |
| --- | --- | --- | --- | --- |
| Windows EVTX | Binary EVTX: Security, System, PowerShell, Sysmon | Valid EVTX header and checksum; 95 | UTC time at 100 ns precision, host, user, process, IP/port and real record offsets | available; experimental |
| Linux | auth.log/secure, auditd, journald JSON, HTTP common/combined | Authentication tags, audit headers, journal fields or HTTP header; 95 | UTC time, host, user, process, command, IP/port, action/result; bounded audit correlation | experimental |
| Syslog | RFC 5424 / RFC 3164, plain or gzip | PRI and timestamp/header shape; 95 / 90 | UTC time, host, application, PID, facility, severity, message and raw data | experimental |
| JSON and exported cloud logs | JSON/NDJSON; AWS, GCP, Azure and HuntEval | Recognized record fields | Time, identities, accounts, resources and IPs | experimental |
| ECS | NDJSON | ECS version and timestamp/characteristic fields | Event, host, user, source, destination, process, file, URL | experimental |
| OCSF | JSON/NDJSON or local Parquet | Class, category and schema metadata; Parquet needs confirmation | Authentication, API, network, process, file and findings | experimental |
| DFIR tools | Velociraptor, Hayabusa, Chainsaw, plaso, EZTools | Format markers or exact CSV headers | Time, host, user, process, action and available entities | experimental |
| Declarative | CSV, JSON, NDJSON or bounded regex | Exact header, required JSON pointers or sample regex; at most 70% | Explicit mapping described below | experimental |

## Current readers and existing cases

New ingestion uses the current parser version recorded in its signed source manifest. JSON uses `json-stream-v3`. Historical parsing engines are not retained. Existing signed bytes can still be authenticated and exported; to regenerate records from an older reader, create a new case and ingest the verified originals. Reinstall declarative definitions after a reader-version update. See the [changelog](../CHANGELOG.md#known-issue-fixed).

## Windows coverage

Use processed exports to investigate these artifacts today. All listed modules are experimental and tested with synthetic data. IRMind ingests the exports; it does not run KAPE, EZTools, Velociraptor or plaso, or open their raw binary artifacts itself.

| Artifact | What it helps answer | Current ingestion route |
| --- | --- | --- |
| Windows event logs, including Sysmon | Which logons, process or service events were recorded, and how do they correlate? | Hayabusa CSV/JSONL → `parser-hayabusa`; EvtxECmd CSV → `parser-eztools`. Direct `.evtx` → `parser-evtx` with the isolated helper; Hayabusa and EvtxECmd exports remain alternatives. |
| Registry hives and related transaction logs | Which account, configuration or persistence-related keys and values were reported? | Process externally with RECmd batch; ingest its CSV with `parser-eztools`. |
| Prefetch (`.pf`) | Which executables, run counts and reported run times appear? | PECmd CSV → `parser-eztools`. |
| Amcache | Which application paths, hashes and inventory timestamps were recorded? | AmcacheParser CSV → `parser-eztools`. |
| AppCompatCache / ShimCache | Which paths and cache metadata were recorded? | AppCompatCacheParser CSV → `parser-eztools`. Cache presence alone is not an execution verdict. |
| `$MFT` | Which file paths and filesystem timestamps were reported? | MFTECmd CSV → `parser-eztools`. |
| LNK shortcuts | Which targets, working directories and shortcut timestamps were reported? | LECmd CSV → `parser-eztools`. |
| SRUM (`SRUDB.dat`) | Which applications and users have recorded resource or network-usage data? | SrumECmd CSV → `parser-eztools`. Usage totals alone do not establish exfiltration. |

For these artifacts, another supported route is a timestamped Velociraptor JSONL artifact result through `parser-velociraptor`, or a plaso `psort` `json_line` export through `parser-plaso`. Export schemas must match the [module contracts](modules.md#velociraptor-parser): arbitrary collector output is not automatically supported. EZTools detection requires the exact recognized column names and a usable timestamp; unmapped fields remain in the record. Start with event timelines, then correlate execution, persistence, lateral movement and possible exfiltration rather than treating one artifact as proof.

[KAPE targets and modules](https://github.com/EricZimmerman/KapeFiles), [EZTools](https://ericzimmerman.github.io/) and [Velociraptor artifacts](https://docs.velociraptor.app/docs/artifacts/) describe collection and external processing. Keep originals and select the processed export files for ingestion. Native registry and `$MFT` parsing remain demand-driven future work under the isolated-helper model used in the [roadmap](development/roadmap.md#v02-parsers-and-connectors). [A Volatility 3 JSON parser](https://github.com/ns2switch/irmind/issues/158) is planned; direct memory-image parsing is not available.

## A custom format without Rust

Open `/parsers`. Choose **Test definition** and enter a TOML file and a small sample file. The preview shows detection confidence and at most ten guarded rows. It does not ingest evidence, create a case or contact a model. `/parsers test <definition> <file>` opens the same form with paths filled in; use the form for paths containing spaces.

Start from one of the [examples](examples/parsers/README.md). A definition contains:

- `version = 1`, a lowercase name and a short description.
- `input.format`: `csv`, `json`, `ndjson` or `regex`. CSV declares its delimiter and header. Regex uses named captures and the linear-time Rust regex engine.
- `detect.header`, `detect.required_fields` or `detect.pattern`. Detection confidence is 1–70, below native high-confidence formats. For JSON, required fields are JSON pointers. The detector checks only the bounded sample.
- `mapping`: common output field to CSV column, JSON pointer or regex capture. `time` is mandatory. Optional fields are `host`, `user`, `process`, `command_line`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `action`, `outcome`, `account` and `region`. Other original data stays in the record.
- `timestamp.format`: `rfc3339`, `unix` in decimal seconds, or a chrono date/time pattern. `timestamp.default_timezone` is `UTC`, `Z` or an explicit fixed offset such as `+02:00`. A source offset takes precedence. Full source timestamp text is retained; the current graph index has second precision.
- Optional stricter `limits`: `record_bytes`, `depth`, `fields` and `records`. Definitions cannot raise the hard limits: 1 MiB per record, depth 32, 1,024 JSON fields and 10 million records. Each source is capped at 50 GiB.

Definitions are at most 64 KiB. Regex source is at most 4 KiB, with a 1 MiB compiled/DFA bound per regex. Preview input is at most 1 MiB. Malformed records are counted with at most three escaped, bounded excerpts; an unrecoverable framing or file-limit error stops that file. No input is executed.

## Install, change, deactivate and recover

Review the preview first. Choose **Install definition**, inspect its name and SHA-256, and confirm **Sign and apply**. The application signs the complete validated definition in its global operational chain, writes it atomically with private permissions, and restarts the session. No case is required. Install a revised file through the same flow; never edit active files to bypass approval.

Accepted files live in `parsers/active/` under the private data directory, with content-addressed copies in `parsers/archive/`. A missing, edited, invalid or unsigned file stays disabled and is visible in `/parsers`; it does not prevent startup. **Restore approved file** explicitly restores the signed snapshot. **Deactivate definition** signs the removal from future detection; historical signed versions remain available for reconstruction. Installation failure after signing leaves an unavailable definition, requiring explicit restoration, never silent acceptance.

The definition hash is part of the parser version in the existing source manifest. Rebuilding an old case resolves that exact signed version, even after replacement or deactivation. Exported manifests retain the pinned hash; reconstructing on another machine also requires the matching approved definition. Export verification itself does not execute definitions. Symlink definitions are rejected. Temporary writes stay within the private data directory and are removed after completion or error; startup cleans orphaned definition temporaries.

All mapped records retain taint and source/parser/offset provenance. The guard screens preview, evidence shown on screen and model context. A definition cannot grant a tool permission or alter organization policy. Keep expected answers from synthetic evaluation episodes outside the source directory you ingest.

### Legacy syslog time

RFC 3164 opens a time-context form before ingestion. Confirm the first record’s year and fixed UTC offset, whether December → January advances the year, and whether to apply the choice to one file or the whole ingestion. Fields start empty. Verified sources from the same host may suggest a year and offset; you must confirm them. IRMind never uses the machine clock or file modification time. Other backward month transitions count as invalid records. The choice is signed with the source. See the [syslog contract and limits](development/syslog-parser.md).

### Linux exports

Classic auth.log/secure uses the same per-ingestion time form as syslog. Journald keeps the original microsecond timestamp. Auditd groups bounded records with the same node, timestamp and serial; unfinished groups stay marked partial. Standard HTTP access formats provide no server-host field, so IRMind leaves it unknown. For custom log formats, adapt the [declarative HTTP export example](examples/parsers/nginx-apache-custom.toml). The [Linux contract](development/linux-parser.md) lists limits and mapping details.

### Windows EVTX

EVTX is available in source builds and signed candidate packages; older releases do not include its helper. The experimental `parser-evtx` module uses the separately installed `irmind-evtx` helper. It recognizes the EVTX header and checksum, not the file extension. The helper receives one read-only file handle; it cannot open the evidence by path. Both local files and downloaded, case-private object spools use that route.

Linux requires kernel 5.13 or newer, Landlock ABI 1 enabled, and unprivileged seccomp. No Bubblewrap installation is required. Windows requires the BFE and MpsSvc firewall services to remain active. It uses a capability-free AppContainer, an explicit standard-handle list and a kill-on-close Job Object. macOS uses a deny-default sandbox profile. A startup probe verifies denied foreign reads, denied networking and denied child creation. If the probe fails, Preferences reports why EVTX is unavailable; there is no unconfined mode.

Security, System, PowerShell and Sysmon events map to the common schema. Unmapped fields remain in the record. The original FILETIME timestamp retains its 100 ns resolution, and provenance records the actual file offset and record number. The [helper design](development/evtx-helper-design.md) documents limits, mappings and the platform test requirements. Use the matching helper from the same verified release beside the main executable.

Tested native environments: Ubuntu 22.04 and 24.04, Debian 12 (kernel 6.1), macOS 26.6.2 arm64 and Windows Server 2025. Fedora 44 was tested as container userspace only. Windows 10/11 clients remain experimental and unconfirmed; see the [Windows 11 validation issue](https://github.com/ns2switch/irmind/issues/189) and the [exact platform evidence](development/evtx-helper-validation.md). Runtime isolation checks must pass on each installation.
