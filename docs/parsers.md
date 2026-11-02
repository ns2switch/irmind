# Log parsers

This page helps analysts choose a local log parser and test a custom format before ingestion. All current parsers are experimental and validated with synthetic data. See [modules](modules.md) for individual formats and [configuration](configuration.md) for the data directory.

## How a parser is selected

The registry passes at most the first 64 KiB to every compiled detector. A filename is a hint, never proof. One unique match at 80% confidence or higher selects the parser automatically. Low-confidence matches and ties require analyst confirmation. Unattended ingestion does not choose an ambiguous parser. The selected identity, version, confidence and selection mode enter the signed source manifest.

`/ingest` opens the file picker. Use `/ingest --parser <name> <path>` for an explicit choice; it is audited. In **Settings → Preferences**, inspect compiled parser names and versions. Compilation includes no automatic remote model selection.

| Parser | Input | Detection | Mapped fields | Status |
| --- | --- | --- | --- | --- |
| Syslog | RFC 5424 / RFC 3164, plain or gzip | PRI and timestamp/header shape; 95 / 90 | UTC time, host, application, PID, facility, severity, message and raw data | experimental |
| JSON and exported cloud logs | JSON/NDJSON; AWS, GCP, Azure and HuntEval | Recognized record fields | Time, identities, accounts, resources and IPs | experimental |
| ECS | NDJSON | ECS version and timestamp/characteristic fields | Event, host, user, source, destination, process, file, URL | experimental |
| OCSF | JSON/NDJSON or local Parquet | Class, category and schema metadata; Parquet needs confirmation | Authentication, API, network, process, file and findings | experimental |
| DFIR tools | Velociraptor, Hayabusa, Chainsaw, plaso, EZTools | Format markers or exact CSV headers | Time, host, user, process, action and available entities | experimental |
| Declarative | CSV, JSON, NDJSON or bounded regex | Exact header, required JSON pointers or sample regex; at most 70% | Explicit mapping described below | experimental |

## A custom format without Rust

Open `/parsers`. Choose **Test definition** and enter a TOML file and a small sample file. The preview shows detection confidence and at most ten guarded rows. It does not ingest evidence, create a case or contact a model. `/parsers test <definition> <file>` opens the same form with paths filled in; use the form for paths containing spaces.

Start from one of the [three examples](examples/parsers/README.md). A definition contains:

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

RFC 3164 needs a year and UTC offset supplied by the analyst. IRMind records the inference and never fills these from the machine clock. See the [syslog configuration and limits](development/syslog-parser.md).
