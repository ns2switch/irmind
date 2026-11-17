# Removing unmaintained date dependencies

The replacement route removes `chrono` and `humantime` from all four locked
build/test/fuzz graphs. Advisory enforcement stays unchanged; there is no ignore
entry or global advisory-policy change. Date calculations use the existing
validated IRMind UTC types where sufficient and a maintained date implementation
where general calendar/format support is required.

## First implemented slice

- TUI UTC labels, the new-case time validator, AWS, Splunk, CrowdStrike and
  SentinelOne reuse the domain's checked UTC timestamps. Five direct `chrono`
  dependency edges are removed, without adding a replacement crate. EDR response
  filtering compares exact instants, including nanoseconds and explicit offsets;
  unknown offsets and leap-second values are rejected.
- The official `evtx 0.15.1` source imports only `winstructs::guid::Guid`.
  A GUID-only source patch retains the original GUID/error code and license
  byte for byte, while omitting unused timestamp, NTFS and security modules.
  The verified archive checksum and file hashes are in the
  [source manifest](../../helpers/evtx/vendor/winstructs/UPSTREAM.json).
  EVTX decoding, timestamps, protocol and containment are unchanged.
- The helper's fuzz lockfile no longer contains either retired dependency.
  The helper's development graph still reaches `chrono` through Parquet/Arrow;
  removing that path remains part of the work below.

Validation so far: 159 TUI/connector tests, two additional exact-boundary tests,
14 native Linux EVTX protocol/containment/custody tests and the retained GUID
short-read contract pass. The selected TUI/connector Clippy check passes with
warnings denied. Current signed-format and UI golden files are unchanged.
This is not a completed dependency replacement or a green release matrix.

## Why an upstream version bump is insufficient

| Dependency | Current notice | Existing runtime paths |
| --- | --- | --- |
| `chrono 0.4.45` | [RUSTSEC-2026-0543](https://github.com/RustSec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md) | IRMind parsers, Arrow/Parquet, storage, and the original helper's unused winstructs timestamp module. |
| `humantime 2.4.0` | [RUSTSEC-2026-0542](https://github.com/RustSec/advisory-db/blob/main/crates/humantime/RUSTSEC-2026-0542.md) | The vendored `object_store` runtime. |

Both database entries are `informational = "unmaintained"` with no patched
version listed. Published Arrow/Parquet 60.1.0 still require `chrono` normally;
`object_store 0.14.2` still requires both packages. Updating those versions alone
cannot satisfy the removal target. The existing physical-format versions can
therefore stay pinned while their date dependencies are replaced explicitly.

## Concrete remaining source/dependency proposal

1. Use **`time = 0.3.55`** directly for the remaining general date consumers.
   It is already present in the main lockfile through AWS and supports strftime
   parsing/formatting. Proposed features are `std`, `parsing`, `formatting`,
   `serde` and `large-dates`, with no host-local-offset feature or timezone DB.
   IRMind's existing supported instant range and validation remain authoritative.
2. Replace the unused Arrow umbrella dependency with the already locked direct
   `arrow-array`, `arrow-schema`, `arrow-select` and `arrow-ord` **59.3.2** crates.
   Keep the same record batches, arrays, filtering, ordering and take kernels.
   This drops unrelated arithmetic/string kernels without removing a product tool.
3. Vendor the published **`arrow-array 59.3.2`**, **`arrow-cast 59.3.2`** and
   **`parquet 59.3.0`** sources and replace only their date implementation with
   `time`. Their current Rust source totals **218 files / 6,796,051 bytes**,
   before manifests/licenses. Package checksums are fixed in
   [date-dependency-sources.json](date-dependency-sources.json).
   Retain Apache notices, record every changed file, keep new code safe, and
   preserve existing upstream unsafe blocks unchanged. This is a maintained local
   source patch, not an upstream chrono-free Arrow release.
4. Extend the existing **`object_store 0.13.2`** source patch to use `time` for
   dates and **`jiff = 0.2.39`** (`std` only) for duration parsing/formatting,
   removing `humantime`. Jiff and its **`jiff-core 0.1.2`** dependency already
   ship in the helper graph. Preserve supported configuration-duration units and
   overflow rejection without calendar or host-timezone inference. Preserve the
   pre-parse 8 MiB HTTP response bound, streaming
   object-body path, explicit credentials, full TLS and canonical request signing.
5. Apply the same source selections to the main, main-fuzz, helper and helper-fuzz
   workspaces. The GUID-only **`winstructs 0.3.2`** patch above remains separate
   from the official EVTX decoder; no EVTX fork or isolation change is proposed.

The new direct dependency declarations and local third-party source patches are
an additional supply-chain choice. They are proposed here; the `time` and Arrow
changes are not implemented in this slice. None grants permissions or introduces
credentials, and no IRMind domain/application port change is proposed.

## Completion gates

- All four locked graphs and all four lockfiles contain neither retired package;
  `cargo deny` passes with the existing policy and no advisory suppression.
- Differential date fixtures cover offsets, leap years, fractions through
  nanoseconds, pre-epoch times, date boundaries, invalid/unknown zones and declared
  formats. Preserve existing supported inputs and reject unsupported instants
  explicitly; never clip precision or silently substitute UTC.
- Existing canonical frames, Parquet physical hashes, signed commitments, source
  provenance, hash verification, rollback, scope and export vectors stay unchanged.
  A byte mismatch is investigated, not accepted by regenerating a signed golden.
- Repeat native Linux/macOS/Windows tests, preserve_order tests, EVTX byte/worker
  equivalence and containment. Verify the retained third-party source hashes.
- Reintegrate cache accounting only after dependency removal, repeat its three
  release-mode scripted measurements, then run the normal signed distribution and
  clean-install checks before publishing v0.5.3.
