# Compact ordering for Azure flow logs

**Status.** Proposed for v0.6.2. [Performance issue](https://github.com/ns2switch/irmind/issues/360).

The current direct writer speculates on source order. When an Azure source
arrives out of order, replay stages expanded, mapped rows and sorts copies of
those rows. The proposed disordered-source path orders compact locators first.
It produces the existing decoded records, mappings and Parquet bytes.

## Decoder boundary

Add an optional `SourceDecoder::compact_ordering()` accessor, returning a
bounded format-specific iterator/replay adapter or `None` by default. The
first implementation is restricted to `parser-azure-flow/azure-flow-source-v1`.
It reads the already-open evidence handle with the existing Azure frame
decoder. It exposes the physical enclosing frame span and the ordinal of a
tuple inside that frame. The span is private scheduling data. A nested tuple
still has no claimed byte offset in the signed evidence. A format that cannot
provide a safe replay locator uses the existing sorted-row path for the whole
source. Unknown and empty Azure payloads retain their current one-record
behavior, including the enclosing frame offset where already defined.

A key contains the checked instant (including precision), the existing
logical record ordinal, and the existing optional signed offset. The caller
compares keys using `compare_record_keys`, in a single source's scope. Record
ordinals count rejected tuples the same way as the current `SourceFrameEmitter`.
The locator contains a checked source frame span and tuple ordinal. For replay,
verify the frame commitment and bounds, then use the existing validated
record constructor and mapping. Compare the final row's key with the staged
key before it can reach Parquet. Check the source SHA-256 and size against the
opened handle before and after replay. Object downloads use their existing
verified case-local spool and acquisition checks.

## Scratch and custody

Sort fixed-size entries with the existing fan-in and source-worker caps.
Stage only locators and compact receipts in private case files. A bounded frame
cache may eliminate nearby rereads; a cache miss reopens the same validated
span. Check each compact run's size, count, SHA-256 and ordering at consumption.
Cancellation, corruption, a changed original or a write failure rolls back the
unsigned group and releases its scratch. Avoid an expanded sorted-row spool.

Replay the locators in order and construct the expanded source record and
projection only for the selected tuple. The commitment is still a digest of
source-order records. Stage each existing commitment tuple in its ordinal slot
and fold the occupied slots in original order through the existing commitment
code. Validate ordinal uniqueness and coverage, offsets, provenance, precise
keys and report counts. Obtain bounded rejection samples in their original
order. Mapping diagnostic counters and the set of selected formats are
computed from the same validated projections. Retain the existing grouping,
Parquet writer and signed manifests. The compact runs, frame hashes and
receipt slots are private temporary state.

Ordered sources keep their existing direct path. For disordered sources, keep
the normalization allowance, disk admission formula, margins, sort-worker
caps, and existing row and queue limits. Continue charging the same logical
normalized bytes while streaming rows into the writer. Bound live compact
scratch within the existing per-source allowance and current preflight
reservation. If the compact recipe cannot do so, use the existing route.
A lower reservation can be evaluated separately after measuring this release.

## Evidence and release measurements

Use the actual v0.6.1 build as the reference and identical deterministic
synthetic VNet and NSG corpora. Measure ordered and alternating-timestamp
sources of 1 GiB on the same release runner. Report wall time, scratch peak,
total logical writes, merge depth, rereads, and peak worker memory and open
handles. Report any additional frame spool separately. The estimates in
[#360](https://github.com/ns2switch/irmind/issues/360) exclude that cost.

Compare the stable sequence, decoder commitment, mapping receipt, artifact
bytes and deterministic signed case entries against the current path on the
same source. Run with one and multiple workers and `serde_json/preserve_order`.
Include nested groups, VNet and NSG supported versions, invalid and missing
instants, tied keys, unknown payloads, gzip/path eligibility as applicable,
bad or duplicate locators, mutated frames, cancellation, and disk denial
before ingestion. Run full reconstruction and export verification. Leave
the file quota and reservation unchanged for v0.6.2.
