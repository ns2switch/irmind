# EVTX parser: dependency review and implementation gate

This document is for maintainers deciding how to add the next experimental parser. **No EVTX dependency or runtime parser is added by this PR.** The analyst required dependency approval before adding `evtx`; the review found a feature-unification conflict that must be resolved first. Syslog and Linux are also not integrated; an old, uncommitted syslog prototype exists separately and is not evidence of a delivered module.

## Candidate and evidence

The candidate is the published `evtx` **0.15.1**, with `default-features = false`, pinned for review. [Its release metadata](https://crates.io/crates/evtx/0.15.1) reports MIT/Apache-2.0 licensing and a non-yanked release. The archive SHA-256 is `1f43baa96df69a1b45b7738edb91168028915e0f33aca91f194c39357f432a52`; the review verified those bytes before reading its manifest and Rust sources. [Upstream](https://github.com/omerbenamram/evtx) has recent releases and upstream fuzz targets. This is maintenance evidence, not a complete security audit or a promise of safe behavior on malicious files.

| Area | Finding | Required treatment |
| --- | --- | --- |
| License | Published metadata uses the legacy `MIT/Apache-2.0` spelling; the project offers either license. | Check the resolved dependency licenses with cargo-deny before adoption and add attribution. |
| Library unsafe | The reviewed library root has `#![forbid(unsafe_code)]`; no unsafe block was found in its library sources by a token scan. The optional CLI has a Windows unsafe extern declaration. | Compile the library only, with default features disabled. Keep `#![forbid(unsafe_code)]` in IRMind. |
| Transitive unsafe | Required `utf16-simd` and `sonic-rs` contain unsafe/SIMD code. A scan found 67 and 246 unsafe-token sites respectively, including cfg/test sites; these are not reachable-site counts or validated vulnerabilities. | Explicitly review and approve this additional attack surface; fuzz the complete selected build. Do not describe the dependency closure as unsafe-free. |
| Optional features | Defaults include multithreading and the CLI; the CLI also enables provider-template/PE extraction. Optional allocators are separate. | Disable CLI, Rayon, PE extraction and allocator replacement. No provider binary is executed or loaded. Parallelize files through the existing bounded application pipeline. |
| Mandatory dependencies | The minimal library still uses the JSON/SIMD renderer, jiff, bumpalo and winstructs. A scratch metadata resolution was inspected outside the repository. | Review the actual workspace lockfile delta before adoption. Scratch latest versions are not a forecast of that delta; retain existing pins where compatible. |
| JSON feature conflict | Even with defaults disabled, the published manifest requires `serde_json/preserve_order`. Current IRMind enables default/raw_value/std but not preserve_order. | Do not enable it silently: changing map iteration/serialization can change normalized record text and break reconstruction of previously signed Parquet. |

The same preserve-order requirement is present in the reviewed 0.12.3 manifest; downgrading to that release does not solve it. No old release is selected solely to avoid reviewing current dependencies.

Sources: the [published manifest](https://docs.rs/crate/evtx/0.15.1/source/Cargo.toml.orig), [library root](https://docs.rs/crate/evtx/0.15.1/source/src/lib.rs), [utf16-simd source](https://docs.rs/crate/utf16-simd/0.2.0/source/src/lib.rs) and [sonic-rs documentation](https://docs.rs/sonic-rs/0.5.10/sonic_rs/). The direct source scan was bounded and read archive members without extracting paths; review archives and scratch manifests were deleted.

## Decision requested before adding the dependency

Preferred EVTX route: review a minimal, pinned patch that makes preserve_order optional and leaves it disabled in IRMind. Keep the parser logic and its license unchanged, document and checksum the patch, seek the change upstream, and prove with synthetic binary EVTX fixtures that JSON/XML record meaning is unchanged. This is a proposal; the patch has not been applied. Merely switching to XML output cannot disable a mandatory Cargo feature.

Tests must prove that every existing parser produces identical normalized rows and reproducible Parquet when the new module is compiled, and that historical cases still pass verify_graph. Preserve-order must remain absent in the production feature tree. If upstream genuinely requires insertion-ordered maps for correctness, stop and review another approach rather than removing the feature or changing signed behavior to make tests pass. A process-isolated helper would be a separate architectural proposal, not an implicit fallback.

Alternative: continue with syslog first while EVTX remains blocked. Do not silently choose an older dependency or globally change JSON semantics. The analyst must approve the dependency/patch route and the transitive unsafe exposure before the production dependency is added; the normal pre-merge dependency gate still applies.

## Module boundary and custody

The implementation will be `crates/modules/parser-evtx`, feature `parser-evtx`, compiled by default and removable with a minimal build. It implements the existing EventParser/StreamingEventParser/LogParser ports and the common module manifest. Detection is pure, bounded to the existing 64 KiB sample and based on EVTX header structure/magic, not extension alone. It joins the existing detection matrix; an ambiguous candidate asks the analyst.

Use the existing local random-access parser path. Local files are read directly, never copied into the system temporary directory. Cloud streams already use the case-private spool, with the existing free-space, permissions, cancellation and cleanup checks. The module must not obtain credentials, access the network, open provider DLLs or bypass signed manifest selection. No new parser port is proposed here.

Keep exact source hashes and byte/record provenance. Emit Tainted records; guard and redaction remain at display/model boundaries. Preserve the complete original timestamp and record. Until the [artifact-v2 proposal](https://github.com/ns2switch/irmind/pull/150) is approved for implementation, the derived index remains visibly second precision; never claim microsecond ordering. Do not change the current signed manifest, artifact, seal or export format to add this parser.

## Initial mapping contract

Use typed fields for System, provider/channel, EventID, TimeCreated and the known EventData entries. Preserve unknown fields as bounded original record data. Never run a command line, expand a path, evaluate PowerShell, contact an IP or interpret embedded instructions. Duplicate fields and conflicting timestamp representations need a documented, tested treatment; do not discard them silently.

| Channel / provider | Required initial event IDs | Common output and preserved details |
| --- | --- | --- |
| Security | 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 4768, 4769, 4776, 1102 | UTC time, computer, subject/target user and SID, logon ID/type, process/parent and command line, client IP/port, action and outcome where present. Preserve ticket, service, task and group fields. |
| System / Service Control Manager | 7045 | Computer, service name, binary path, service account and original service metadata. |
| PowerShell | 4103, 4104 | Computer, user, process, script-block ID/part numbers and payload. Script text is untrusted evidence, never executable instructions or an automatically confirmed finding. |
| Sysmon | 1, 3, 7, 8, 10, 11, 12, 13, 22, 23 | Process GUIDs/IDs and parent, image/command line/user, source/destination IP/ports, files/hashes, registry keys and DNS names when present. Preserve unmapped fields. |

Bind mappings to both provider/channel and event ID; numeric IDs alone are not globally unique. [Microsoft's 4624 schema](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624), [4688 schema](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688), [Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) and [PowerShell logging reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) are the field references. Validate the remaining per-event field/version variants against official schemas before claiming coverage; the table is required scope, not implemented coverage.

## Required validation before merge

- Synthetic binary EVTX builder/fixtures for every mapped ID and channel/version variant, plus malformed headers/chunks, corrupt lengths/CRC, duplicate IDs/fields and invalid Unicode. Do not copy real upstream Security logs as fixtures.
- Hard file/record/output, nesting, field and record-count limits around the selected API, checked before allocation where feasible. Unsupported structures must fail with a bounded reason; count recoverable bad records and retain only the standard bounded untrusted samples. Never hide parser errors or enable carving/recovery silently.
- Cancellation between chunks and records; no system spool and no partial signed artifacts after an error. If the library cannot bound rendering before allocation, resolve that gap before enabling the module.
- Shared streaming contract, full parser detection matrix, direct-file/spool tests on Linux/macOS/Windows, and reproducible signed ingestion/rebuild/export with existing cases.
- Fuzz detect and binary parse under nightly/ASAN for at least ten minutes locally; add the target to weekly fuzzing. Use bounded disposable corpora and delete them after the run.
- Synthetic HuntEval-style lateral-movement episode: network logon (4624 type 3), service installation and process launch. Expected events/entities/techniques are evaluator-only and never ingested or sent to a model.
- Measure 1 GiB ingestion throughput and binary-size delta on the same machine. Keep the full source precision for later artifact-v2 migration. Document in English and Spanish as experimental and synthetic-only; do not mark the parser delivered until these checks pass.
