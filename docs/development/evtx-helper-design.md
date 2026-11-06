# Isolated EVTX decoding

This design is for maintainers implementing the experimental Windows event-log module. It defines the decoder boundary, platform containment and distribution checks before any EVTX data reaches the main engine.

## Cargo and module boundaries

- Add `crates/modules/parser-evtx` behind a default `parser-evtx` feature. It implements the existing `LogParser` and indexed streaming capabilities, registers with the parser catalog and emits the existing source/artifact manifests.
- Put `irmind-evtx` in its own Cargo workspace under `helpers/evtx`, with a separate lockfile. Neither the decoder nor its dependencies belong to the main Cargo feature graph.
- Use official, unmodified [`evtx` 0.15.1](https://crates.io/crates/evtx/0.15.1), pinned exactly, with default features disabled. The published archive SHA-256 is `1f43baa96df69a1b45b7738edb91168028915e0f33aca91f194c39357f432a52`; its declared license is MIT/Apache-2.0.
- The published decoder manifest enables `serde_json/preserve_order` unconditionally. The separate workspace is necessary even with default features disabled. Keep the main release feature-isolation check.
- Disable upstream CLI, WEVT/PE template loading, custom allocators, carving and multithreading. Do not read neighboring DLLs, templates or files. Retain upstream chunk checksum validation.
- Record the exact decoder/protocol identity in the parser version. Parent normalization uses explicit canonical field ordering; never rely on the helper's JSON object order.

The published package has no build script. Its core dependencies include `sonic-rs`, `utf16-simd`, `winstructs` and `jiff`; a complete helper lockfile, license/advisory review and transitive unsafe report are implementation evidence, not implied by the upstream package description.

## Input and process contract

Locate the helper adjacent to the running IRMind executable, never through a model argument or executable search path. Pass fixed protocol arguments and an already-opened, read-only regular-file handle as stdin. Do not invoke a shell. The helper duplicates that handle using safe standard-library APIs and uses seekable decoding; it never opens an analyst-supplied path.

Local evidence is read without copying. Object-storage sources use the existing private case spool and random-access parser route. The application authenticates the complete source before publication, retaining version/ETag checks and normal source re-verification. No evidence is written to the system temporary directory.

The initial bounds are explicit and testable: 4 GiB source, 4 MiB output record, 1,000,000 records, and 600 seconds wall time per helper invocation. Total output is bounded by the lesser of 8 GiB and 32 times the input size plus 1 MiB. Parent queues are byte-bounded; stderr is capped and never displayed verbatim. The process limit is independent of tool-query deadlines. Limits must be documented rather than silently truncating a file.

Crash, timeout, cancellation, unavailable containment or malformed output rejects the complete file. Provisional events never enter a signed batch before an authenticated source, complete protocol trailer and successful child exit. Kill, wait and join pipe readers on every path. Existing whole-batch rollback removes provisional Parquet files.

## Network and filesystem containment

The decoder's lack of HTTP dependencies is not a network boundary. A platform must prove operating-system containment before reporting EVTX as available. There is no unsandboxed fallback.

| Platform | Intended boundary | Availability and tests |
| --- | --- | --- |
| Linux | Fixed Bubblewrap invocation with a private network/PID namespace, no inherited environment or unrelated file descriptors, read-only helper/runtime bindings, and parent-death termination. Evidence is inherited only through its read-only handle. | Probe namespace availability. Missing Bubblewrap or denied user namespaces makes EVTX unavailable, with an actionable status. Test outbound network, unrelated-file reads, child cleanup and cancellation. |
| macOS | Fixed `sandbox-exec` profile denying network and process forks, allowing only helper execution, required runtime reads and inherited IO. | Probe the system facility and exact profile. It is deprecated; its presence is not assumed. If the profile cannot enforce the boundary, mark EVTX unavailable. Test on native macOS CI. |
| Windows | AppContainer with no network capabilities, an explicit inherited-handle list, suspended startup and a kill-on-close Job Object with one active process. Bind executable read/execute permissions to the sandbox identity without granting it access to evidence paths, user configuration or keys. | Use official Microsoft APIs. Test handle inheritance, executable ACLs, blocked network, blocked unrelated reads, process-tree termination and startup rollback on native Windows CI. |

The Windows launcher needs native process/security calls that are unsafe Rust APIs. The proposed implementation puts only those calls in a dedicated common process-containment crate, using the already-reviewed official `windows-sys` family. Its public Rust API is safe; domain, application, TUI, main binary and parser remain `forbid(unsafe_code)`. Do not put process launching into `irmind-fs` or an adapter-to-adapter dependency. A narrowly documented exception to the current unsafe-code policy is a prerequisite for implementing that boundary; no broad lint allowance is acceptable.

If a maintained safe abstraction can provide every listed guarantee, compare its dependency/unsafe surface before choosing it. Do not substitute environment clearing, a low-integrity label, a timeout, or an ordinary restricted token for network isolation.

## Bounded NDJSON protocol

Use a helper-protocol label independent of signed custody formats. Frames are a version handshake, zero or more record/rejection frames, and exactly one completion frame. Reject unknown fields, duplicate keys, unexpected frame order, invalid UTF-8, excessive nesting/fields, overlong lines, trailing bytes and count mismatches. EOF without completion is an error even if the child exits successfully.

A record carries the event record number, an actual physical byte offset when available, the original timestamp and its event object. Preserve 100 ns timestamps without rounding. The upstream serialized-record type does not expose a physical offset: obtain one through a checked chunk/frame traversal, or leave it explicitly unavailable. Never fabricate an offset from record number or iteration position. Validate every supplied offset against source bounds.

The parent independently validates the record shape and performs domain normalization. Every result is `Tainted` with source hash, parser identity and record/offset provenance. All display and model paths retain `ContentGuard`; no decoded data becomes a system message.

Bounded per-record decoder errors are counted with safe samples under the existing ParseReport rules. An invalid protocol, process failure or resource limit is a file-level failure, not a successful partial extraction. Panic/error output must not expose record contents or local paths.

## Event mapping

Normalize UTC instant, host, user, process, command line, IP/ports, action and outcome. Preserve unmapped event fields as untrusted record attributes. Use the endpoint-host partition profile and approved V2 cardinality/overflow rules.

Required synthetic mapping fixtures cover:

- Security: 4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 4768, 4769, 4776 and 1102.
- System: 7045.
- PowerShell: 4103 and 4104.
- Sysmon: 1, 3, 7, 8, 10, 11, 12, 13, 22 and 23.

Detection requires the bounded EVTX signature/header, not the extension alone. Directories use the existing enumerator and parser-selection rules. Missing helper or failed containment stays visible in settings and cannot win automatic selection.

## Validation and distribution gates

1. Synthetic-only decoder, detector and mapping fixtures; no upstream incident samples.
2. Protocol tests for process crash, timeout, broken/truncated/oversized frames, wrong counts, invalid offsets, missing completion and cancellation. Check no signed partial ingestion and no temporary leftovers.
3. Native Linux, macOS and Windows containment tests, including denied outbound connections and unrelated-file reads. A missing test facility must be reported rather than treated as evidence of containment.
4. Source/derived reconstruction and mixed V1/V2 verification through the existing application ports. Keep historical signed goldens unchanged.
5. At least one hour of malformed-input fuzzing before integration, with the same target in the nightly workflow. Publish duration, crashes and coverage limitations; a lexical search for `unsafe` is not a cargo-geiger report.
6. Separate lockfile, full license/advisory checks, helper SBOM and a cargo-geiger or equivalent unsafe report. No unapproved main-workspace feature unification.
7. Include the helper in every supported signed release package, SHA256SUMS, Sigstore bundles, GitHub provenance attestations and verified installers. A helper mismatch or missing asset fails installation; no tag is created during implementation.
8. Request dependency and new-binary distribution review before merging. Elastic and Chronicle follow this work; they do not introduce credentials or JWT dependencies in the EVTX change.

Related: [approved work order](plan.md#approved-parser-and-precision-work-order), [precise artifact design](parquet-artifact-v2-design.md), [Windows coverage](../parsers.md#windows-coverage), and [EVTX tracking issue](https://github.com/ns2switch/irmind/issues/47).
