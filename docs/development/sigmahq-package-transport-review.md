# Transport for pinned SigmaHQ rules

The approved catalog can use any of these three transport designs. The resulting
case manifest still pins each admitted rule by path, size and SHA-256.
This review adds no package dependency.

## Measured dependency and size cost

I built a standalone Linux x86_64 size probe with Rust 1.97.1, ThinLTO, one
codegen unit and stripping. Each variant opens a file and copies at most
65,537 bytes to a sink. The ZIP variants also exercise strict header validation.
These are linked probe sizes. Incremental size in the complete IRMind binary
may differ because it already links several of these crates.

| Option | Production dependency implications | Probe |
| --- | --- | ---: |
| `zip =9.8.2`, `default-features = false`, feature `deflate` | 23 distinct normal packages in the Linux probe, including the compression backend and writer support. Five names are absent from the current root lockfile: `zip`, `typed-path`, `constant_time_eq`, `zlib-rs`, `zopfli`. No AES or other compression features selected. | 579,392 B (+228,136 B) |
| `zip`, deflate through the existing `flate2`/miniz backend | The narrower `deflate-flate2` feature and existing `flate2 =1.1.10` with `miniz_oxide` select 21 normal packages. Three names are absent from the root lockfile: `zip`, `typed-path`, `constant_time_eq`. This drops the extra zlib backend and Zopfli writer. | 547,520 B (+196,264 B) |
| Minimal reader on `flate2` | Direct reuse of `flate2` and an existing CRC32 implementation for ZIP CRC validation. The decoder probe has six normal packages, all already represented by name: `flate2`, `miniz_oxide`, `crc32fast`, `adler2`, `simd-adler32`, `cfg-if`. The size excludes the unimplemented structural reader. | 374,736 B (+23,480 B for inflater) |
| Individual pinned Git files | Reuse the authenticated index, client, streaming hash and bounded local rule admission. Zero new packages or features. No ZIP code is linked. The existing HTTP path remains required. | 351,256 B (probe baseline) |

These are independently solved Linux closures. An implementation PR needs
a locked workspace closure on all supported targets, license and advisory
checks, and a full CLI size measurement before adding the dependency.
[Feature definitions](https://docs.rs/crate/zip/9.8.2/features) ·
[Archive API](https://docs.rs/zip/9.8.2/zip/read/struct.ZipArchive.html).

## Admission controls by option

| Concern | Maintained `zip` reader | Minimal reader on `flate2` | Pinned Git files |
| --- | --- | --- | --- |
| Compressed input | Hash approved transport before opening. Bound file and central directory before library allocation. Require stored or deflate, reject encryption and use no decrypt API. Cap actual output per rule and across the archive before retaining bytes. Verify length, CRC and SHA-256 to EOF. | Same bounds. Read only single-disk ZIP32 with defined flags. Cap offsets and input to the decoder. Check exact decompressor consumption and output, CRC and SHA-256. | Request identity encoding and reject unexpected content encoding. Cap each response by the signed byte count and existing rule cap. Enforce a total quota, overall deadline and bounded fan-out. |
| Paths | Reject unsafe or ambiguous raw names, duplicate normalized aliases and nonregular entries. Apply strict constraints to selected paths. Do not extract. | Same restrictions, with explicit UTF-8/ASCII path decoding and validation under the wrapper. Do not extract. | Use the pinned repository and commit with validated, segment-encoded paths and a fixed host. Reject mutable refs, ambiguous encodings and redirects outside the permitted endpoints. Keep rules in the content-addressed store. |
| Duplicate entries | Check `has_duplicate_names` and reject aliases after normalized validation. The crate's name lookup alone collapses duplicate raw names. | Track each path and byte range in bounded sets. Reject repeats, overlaps, count mismatches and entries absent from the directory. | Reject duplicated/colliding signed paths and unexpected bodies. Match each downloaded file to exactly one manifest slot. |
| Central versus local records | Use `validate_header_consistency` before opening entries. Add the restricted-profile checks for offsets, flags and methods, no encryption, no ZIP64 or split volumes. The crate's strict method checks duplicate names, mismatches, overlaps and unlisted local headers. | Implement all these checks in IRMind, including exact local versus central sizes, names, flags, CRC and methods. Limit any optional records and fail on ambiguous layouts. | No archive headers. A fetched body must match its commit-pinned path, byte count and SHA-256 before parser admission. |
| Fuzzing | AddressSanitizer against the full wrapper, including index-selected paths, duplicate and cross-header cases, limits, cancellation and streams. Keep supported archive fixtures and an end-to-end proof test. | Same wrapper campaign plus independent structural decoder fuzzing with offsets, truncated data and directories. Differential checks on accepted fixtures against the reference crate. | Fuzz index/manifest paths and bounded HTTP body handling. Simulate missing/swapped/truncated responses, throttling, redirect and encoding changes, cancellation, and atomic publication when a partial download fails. |

The pinned `r2026-07-01` asset measures 3,172,748 bytes compressed and
5,039,590 bytes declared decoded. It contains 3,303 entries, including the
version metadata and 3,302 YAML files. All use deflate with no extra fields
or flags. The largest entry is 295,078 bytes. The per-rule admission limit
still applies to the explicit reviewed selection, so over-limit candidates
remain out. The strict library probe accepted the archive structure.
[Official asset](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01) ·
[ZIP structure specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT).

Downloading individual files removes compressed-container parsing from the
runtime. It needs one bounded request per selected rule. A large selection
can require thousands of requests and makes catalog installation sensitive
to throttling and partial failure. Offline use also needs the selected files
rather than one original artifact. Commit-permalink selection and per-file
hashes still authenticate the exact downloaded bytes. The contract would
change the SigmaHQ index source variant from archive pin to commit/path
pins and regenerate that variant's vectors if chosen.
[GitHub commit permalinks](https://docs.github.com/en/repositories/working-with-files/using-files/getting-permanent-links-to-files).

**Recommendation:** use the maintained `zip` reader with the narrower
`deflate-flate2` configuration and the existing miniz backend. That gives
one portable archive to download, a complete header consistency check and
a small additional dependency closure. Keep the IRMind wrapper for all
read, size, path and manifest controls. The custom reader moves structural
parsing and discrepancy checks into IRMind. Individual pinned files are
viable for small curated sets. This recommendation needs approval before
changing the workspace.

## Linked IRMind measurement

Two Linux x86_64 IRMind release builds used Rust 1.97.1, ThinLTO,
one codegen unit, default shipping features and stripped symbols.
Both used the candidate lockfile. The baseline omits all calls to
the reader. The second uses a temporary entry point that invokes the
reader on a synthetic archive and its pinned rule selection. The
entry point was removed after measurement.

| Build | Bytes |
| --- | ---: |
| Baseline | 47,265,392 |
| With the ZIP reader linked | 47,407,984 |
| Difference | 142,592 |

The workspace lock adds four packages for the approved reader.
Linux uses `zip`, `typed-path` and `constant_time_eq`.
The macOS dependency graph adds `nix 0.31.3` through ZIP.
The only enabled ZIP feature is `deflate-flate2`, with its internal
`_deflate-any` switch. Cargo-deny accepts the workspace and fuzz
lockfiles. See [the dependency notices](../../THIRD_PARTY_NOTICES.md#sigmahq-zip-reader).

The reader authenticated all 3,303 members of the pinned SigmaHQ
archive. It independently checks CRC and deflate stream completion,
including the exact length consumed. It rejects gaps in the ZIP
layout and retains only the explicitly selected, hash-pinned rules.

Eight synthetic regression tests passed, including ZIP32 truncation,
header mismatches, overlapping offsets, gaps, CRC mismatch and excess
output. The full reader ran under AddressSanitizer with these seeds
for 601 seconds and completed 13,429,713 inputs without a crash.
