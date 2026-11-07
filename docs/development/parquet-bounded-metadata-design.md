# Bounded Parquet metadata for dense sources

This design is for storage maintainers. It proposes a fixed memory envelope for sources with millions of events, while retaining reproducible reconstruction of existing artifact generations.

## Evidence and scope

The EVTX release benchmark streams decoded records and writes bounded batches. The decoder's observed resident high-water memory remains approximately 3 MiB. The complete ingestion host uses more memory as source record count grows, even with one host and one date partition:

| Synthetic records | Source bytes | Host peak MiB | Decoder peak MiB |
| ---: | ---: | ---: | ---: |
| 204,800 | 104,861,696 | 89.62 | 3.11 |
| 2,097,152 | 1,073,745,920 | 245.00 | 3.06 |
| 8,000,000 | 4,096,004,096 | 621.36 | 3.05 |

These are separate local release measurements of source `341c7184cb525d87ecc6c90e089cd0d796d1a681`, using the compact Security stress corpus. They are not hosted-runner figures or evidence of constant host memory. The host includes Parquet writing, publication and final chain/artifact verification; it excludes a TUI, model and real keystore. [Raw measurements](benchmarks/evtx-streaming-local.json) record the sampling method and scope.

Parquet writers retain row-group metadata until file finalization. Readers also load footer metadata. The current builder consolidates each source/bucket/family to one artifact, so metadata per file grows with its row-group count. This is a candidate contributor; a phase/allocation profile must establish its actual share before attributing the measured peak to it. Streaming records alone does not establish constant memory for the complete pipeline.

## Proposed builder contract

- Introduce a new builder identity for newly written artifacts. Keep the current builder and its reconstruction behavior unchanged for signed generations.
- Rotate a source's open artifact set at a deterministic bound on emitted row groups, with a fixed maximum of open writers. Select and document the row-group bound from the profile; begin evaluation at 64 groups per writer.
- Keep family segments aligned and number them deterministically. Do not merge all bounded segments back into a single unbounded artifact at publication.
- Retain the existing schema, scope normalization, cardinality/overflow policy, record ordering, compression, row-group sizes, hash checks, cancellation, whole-source rejection and source links.
- Keep all current file, artifact-count, disk and time limits. Count extra segments against the existing artifact ceiling; do not raise it implicitly.
- Verify old generations through their recorded builder, and new generations through the new builder. Opening a case performs no migration. Any conversion is explicit and preserves the old generation.

## Qualification

Measure peak host/decoder memory at 204,800, 2,097,152 and 8,000,000 compact events with date/host cardinality held constant. Separately measure the richer near-4 GiB Security corpus and its multiple dates. Separate parsing/writing, publication and verification peaks before selecting the cap.

Exercise cancellation and failure at a segment boundary, deterministic bytes across worker schedules, old-builder golden reconstruction, mixed-generation queries, complete artifact-set verification and export. Repeat the one-request Windows batch, single-file 1 GiB and near-4 GiB Linux tests under the unchanged 600-second invocation deadline. Report memory, throughput, artifact count and disk overhead, including any existing limit reached.

This is a design only. It changes no builder identity, artifact bytes, signed format or migration implementation.
