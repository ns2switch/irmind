# Declarative parser integration proposal

This document is for maintainers implementing the user-defined parser block ([issue #80](https://github.com/ns2switch/irmind/issues/80)). It records the integration needed before a definition can produce signed evidence. The parser port extension is awaiting analyst approval; this document does not authorize a signed-format change.

## Module and identity

One feature-gated crate, `irmind-mod-parser-declarative`, implements the existing parser contracts. It is compiled by default and can be excluded. Its code performs no filesystem or network access. The composition root supplies validated definition contents.

Each accepted definition becomes a detector/parser instance in the common catalog. Its stable catalog ID is `parser-declarative-<name>`; restrict names so the complete ID fits SourceManifestV2's current 64-byte bound. Its content-dependent version is `declarative-v1:sha256=<64 lowercase hex digits>`, within the existing 128-byte version bound. The hash covers the exact accepted UTF-8 definition bytes. The signed operation also stores those bytes, so harmless edits produce an explicit new version instead of changing the meaning of an old hash.

The current `&'static str` parser names and versions cannot represent these identities safely. Add borrowed/owned identity accessors with defaults for native parsers and use owned catalog keys. Keep existing native implementations working. Rebuild routing must resolve the exact signed definition hash, not today's active definition with the same name. Never use `Box::leak` or global mutable identity tables.

This uses SourceManifestV2's existing parser ID and version fields. It does not add a manifest field, tag or decoder rule. Artifact versions must use the same exact parser-version string, and existing source/artifact link validation remains mandatory.

## Definition syntax and limits

Definitions are strict TOML with unknown fields rejected. They declare a bounded name, description, input mode, detector, field mappings and timestamp context. Inputs are CSV with an explicit delimiter/header, JSON or NDJSON with JSON Pointer field paths, or line-oriented regex with named captures. No template, shell, script, network fetch or arbitrary expression is supported.

Proposed fixed ceilings:

| Item | Ceiling |
| --- | --- |
| Definition UTF-8 bytes | 64 KiB |
| Active definitions | 64 |
| Detector sample | 64 KiB, at most 16 lines |
| Declarative confidence | 70, always below a native high-confidence match |
| Regex source | 4 KiB |
| Compiled regex/DFA size | 1 MiB each |
| Record or CSV logical row | 1 MiB |
| JSON depth / field count | 32 / 1,024 |
| Mapping count | 64 |
| Field path or capture name | 256 bytes |
| Records per input | 10,000,000 |

The application input/source limits still apply; a definition can lower a limit but cannot raise a fixed ceiling. Use the existing Rust `regex` crate's linear-time engine with compilation and input bounds; unsupported regex syntax is a clear definition error. Do not add a backtracking engine.

JSON parsing extracts selected scalar fields through a bounded visitor rather than constructing an unrestricted `serde_json::Value` tree. Validate depth and field count while walking. Preserve the bounded original record as untrusted text. CSV uses the existing `csv` crate with bounded logical records, including quoted newlines. Regex reads bounded lines. A malformed record increments the rejected count and retains at most the existing three 256-byte untrusted samples; it does not discard the rest of the source. Cancellation is checked between records/batches.

## Time and common fields

Map event time, host, user, process, command line, source/destination IP and ports, action and outcome into the common normalized event. Extract the matching typed entity kinds and preserve unmapped original content. Validate numeric ports and IPs; missing optional fields are not invented.

Support RFC 3339, declared chrono formats and decimal Unix epochs without floating-point conversion. A default timezone may be UTC or an explicit numeric offset. IANA zones needing daylight-saving data are unsupported unless separately approved with a timezone dependency. A source offset takes precedence over a default, and inferred timezone context is recorded explicitly.

Preserve the source timestamp's complete precision in record text. Until the artifact-V2 proposal is approved and implemented, the derived graph still has second resolution; the module must not claim subsecond index ordering.

## Detection and choice

Run this module through the common detection registry. A declaration matches only if its exact expected header, required fields or bounded sample regex matches. Filename extensions are never sufficient. Confidence stays below native high confidence, so native formats win. Ambiguous or low-confidence candidates ask the analyst; unattended ingestion records why it did not ingest. A forced ID is audited through the existing selection mode.

All parsed values keep `Tainted<GraphRecord>` and source/definition/record provenance. The guard applies before display or model context. Definitions and their examples never enter the trusted system role.

## Signed management and recovery

The root owns a private `parsers/` directory beneath the data directory. Archive accepted definitions by content hash and retain old versions for reconstruction even after deactivation. Never follow symlinks or use a definition name as an unchecked filesystem path.

Add, replace and remove are explicit analyst operations. Validate first, show the definition identity and hash, sign a bounded global operational snapshot, then write the accepted bytes atomically with private permissions. Removal signs deactivation; it does not erase a definition still needed by signed cases. Keep the existing operational envelope and signature domain, with a versioned payload for definition management.

On startup verify the global operation chain. Enable only a valid definition matching its last accepted snapshot. An invalid, unknown or unsigned edited definition is disabled with a safe warning; it does not prevent IRMind from starting. Never silently sign or accept it. Offer explicit review/restore using the signed archived contents. Missing historic definitions make reconstruction unavailable with a clear reason, without weakening case-chain verification.

## User interaction

`/parsers` lists native and declarative parsers, versions, definition hashes and experimental status. `/parsers test <definition> <file>` runs bounded detection and mapping without ingestion, signing evidence or invoking an LLM. It displays the confidence and first ten guarded rows, with rejected counts and safe errors. Destructive or installing actions require explicit confirmation and an unlocked analyst signer.

Preferences lists compiled parsers as today, including this module and its active definitions. Existing parser choices and the TUI ingestion command's explicit parser override remain the only ingestion dispatch path.

## Acceptance evidence

- Exact-header CSV, nested NDJSON and named-capture regex examples, with synthetic source fixtures and isolated expected answers.
- Malformed definitions, unknown fields, excessive limits, invalid timestamps, multiline CSV, depth/field limits, invalid regex and cancellation fail safely.
- Detection matrix includes every existing fixture and confirms no declarative detector wins over a native high-confidence format.
- Add/change/remove, manual edit, crash-before-file-write, archived rebuild and unavailable-definition tests exercise signed management.
- `/parsers test` does not add case evidence, read hidden answers or send anything to a model. Its output is guarded.
- Feature-minimal and default builds, dependency direction and shared parser contracts pass. Production dependencies reuse the existing `csv`, `serde_json`, `regex`, `toml`, `serde` and `chrono` packages; no new lockfile package is needed.
- Fuzz detection and parsing for at least ten minutes locally and include the target in the weekly workflow. Measure a synthetic 1 GiB input and binary size before/after, with no unmeasured throughput claim.

The three proposed definitions in [docs/examples/parsers](../examples/parsers/README.md) illustrate the intended syntax. They are specifications until the parser implementation is complete and tested.

## Draft implementation evidence

The core library now validates the three example definitions and decodes bounded CSV, JSON/NDJSON and regex records. It keeps source offsets, full timestamp text, rejected-record samples and taint provenance. It extracts selected JSON scalars without building a `serde_json::Value` tree. Regex matching uses bounded linear-time compilation and copies only mapped captures.

| Local check | Observed result |
| --- | --- |
| Core unit tests | 9 passed, including cancellation, malformed neighboring records, depth/field limits, duplicate keys, quoted CSV newlines and exact fractional epoch time |
| Workspace fmt and clippy with warnings denied | Passed |
| Nightly AddressSanitizer fuzzing | 10 minutes, 1,042,080 inputs, no failures; peak RSS 385 MiB under a 512 MiB limit |
| Default-feature fuzz targets | All built successfully after the explicit-reader correction |
| Fuzz corpus and artifacts | Disposable local corpus removed after the run; versioned synthetic seeds retained |
| Production dependency resolution | Existing third-party package versions reused; the lockfile adds only the new IRMind parser crate |

The application does not register this core yet. Remaining work is the reviewed identity/catalog extension, the module's common-port implementation and default feature, signed definition storage/recovery, parser preview and preference views, shared contracts/detection matrix, synthetic episode, user documentation in both languages, and the 1 GiB ingestion/binary-size measurements. No throughput or full-ingestion claim is made by these core-only tests.
