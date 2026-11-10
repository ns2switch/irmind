# Bounded parallel decoding within a source

This proposal is for maintainers implementing local ingest parallelism. It describes how to schedule independent records while keeping the source decoder responsible for framing and validation.

## Decoder contract

Add one optional method to `SourceDecoder`:

```rust
fn decode_with_budget(
    &self,
    input: DecodeInput<'_>,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError>
```

`DecodeInput` holds either the existing `SourceInput` or `SourceFileInput`. The default method delegates to the corresponding existing method. `DecodeBudget` is a nonzero worker allowance and a bounded allowance for in-flight decoded data. It conveys no capability. The caller divides its operation budget among active source workers; the allowance includes the source worker itself. A decoder may use fewer workers. Reconstruction may use one worker, with the same bytes and commitments.

A decoder first identifies complete records using its current framing and limits. It dispatches bounded groups of complete frames to workers. The coordinator consumes worker results in input order and assigns accepted-record ordinals in exactly the same place as the sequential decoder. A malformed frame still contributes to the same report counters and samples. No worker invents an offset or changes the hash in provenance. The coordinator applies the existing source limits to the entire stream, even when individual worker queues contain fewer records.

- NDJSON and independent text lines use existing bounded line readers. The coordinator records the true byte position before assigning a group of lines.
- JSON arrays and single documents use the existing incremental frame reader where it can separate complete records. An oversized first line cannot bypass framing or consume the opening bytes.
- CSV uses its existing record reader to find boundaries. A quoted newline is part of the record, not a split point. Header detection and schema validation occur once.
- Stateful formats use ordered finalization for state that can be carried through the coordinator. RFC 3164 rollover is one example. Formats that cannot yet separate work safely, such as interleaved auditd event grouping, retain the sequential decoder.

Worker output is an owned, validated candidate, not a trusted record. Only the coordinator emits the record with its original taint and provenance. Backpressure limits queued input and output. On cancellation or terminal failure, the coordinator stops dispatching, closes queues, joins workers and returns through the existing rollback path. It does not open another pathname after hashing; all framing uses the opened source.

## EVTX helper

The pinned `evtx` 0.15.1 crate decodes chunks in parallel only with its optional `multithreading` feature, which adds Rayon and its transitive dependencies to the helper workspace. Its `num_threads` setting bounds in-flight chunk work; the actual Rayon pool must also be capped. Neither feature nor dependency is enabled by this proposal.

The current Linux seccomp policy does not permit the helper to create threads after applying isolation. Keep Linux serial under that policy. Do not start an unrestricted thread pool before installing the sandbox. On macOS and Windows, consider the feature only if the bounded pool can be started inside the existing isolation boundary and native isolation tests pass. The broker still starts at most one Windows helper at a time and retains the one verified network witness per session. No shell, handle expansion, or protocol change is proposed.

## Measurements and acceptance

Compare release builds on the same runner at one, four, and all available worker slots, subject to the memory reservation. Use an ordered multi-file 1 GiB corpus, one 4 GiB NDJSON file, and one 1 GiB EVTX file. Report effective worker counts, ingest wall time, speedup, peak process RSS, and helper RSS separately for EVTX. A single 4 GiB source currently needs more than 128 GiB of free case storage at preflight. Use a runner with that capacity or report the preflight failure. Do not bypass the guard to get a benchmark number.

Compare one, two, four, and the effective maximum worker count using the same sources, initial signed case and clock. Compare Parquet bytes, source and mapping commitments, and every signed audit hash. Cover CRLF, quoted CSV newlines, broken and oversized records, cancellation under backpressure, record offsets and time rollover. Retain existing limits, historical physical goldens and native helper isolation tests.
