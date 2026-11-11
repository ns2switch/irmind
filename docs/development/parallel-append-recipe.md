# Parallel Parquet append recipe

This proposal is for maintainers changing how the direct mapped writer encodes partitions. It describes a physical writer recipe that can overlap appends while preserving custody and the signed wire formats.

## Why the current writer has an ordered append

The current writer chooses which sink to close from the live memory and row-group state after each append. The next append can depend on that eviction. Completing independent sinks whose cuts have already been selected can run in parallel, as in [the partition finalization change](https://github.com/ns2switch/irmind/pull/238). Dispatching the current append loop concurrently and evicting by completion order would change physical file boundaries.

## Proposed recipe

Use a new value, `parquet-builder-common-event-partition-workers-v1`, in the existing signed constructor field. Keep `parquet-builder-common-event-direct-v1` for reconstruction of its existing artifacts. The ParquetArtifactV3 envelope, source records, mapping receipts, inventories, seals, export V6 and their canonical encodings do not change. New artifacts may have different physical file boundaries and hashes from the previous recipe.

The coordinator keeps the canonical source order, partition allocation, source bindings, and per-partition row order. It builds deterministic work windows from the existing row and byte limits. A window contains at most one append batch per active partition. It assigns each writer a fixed logical memory reservation before dispatch. The reservation and logical writer set depend on the canonical input and the writer policy, not on the CPU count. Each partition's worker owns that partition's schema sinks and their Arrow encoder state.

Appends for distinct partitions can run together. At each window barrier, the coordinator collects results in partition order and applies deterministic close decisions before starting the next window. The one-worker setting executes the same logical windows serially. No memory or file boundary decision depends on worker completion time. Large records that fit the existing limits can use an exclusive window, with the existing checks.

The operation budget counts decoders, input queues and writers together. It never grants every decoder and every writer the full worker cap simultaneously. The writer keeps the existing 128 MiB bound for retained writer state, the file-handle cap, and the existing maximum sizes and frame counts. The implementation must demonstrate a conservative reservation before concurrent work. If it cannot reserve a window, it takes a deterministic smaller window or uses the exclusive path. A resource failure does not exclude a source or produce a partially committed group.

An ordered source still uses the bounded decoder-to-writer queue. Only proven disordered sources use a normalized record spool. All results are provisional until the original hashes, artifact hashes, mapping commitments and audit transaction succeed. On cancellation or failure the coordinator closes the queues, joins the workers and discards the group.

## Review and measurement

- Keep the current physical goldens byte for byte and add a golden for the new recipe. Verify that reconstruction chooses the signed recipe and that both recipes verify through export V6.
- Compare every Parquet digest, mapping commitment and signed audit hash at one, two, four and the effective maximum workers from the same initial case and clock.
- Exercise ordered and disordered groups, many partitions, a large row, source failures, write failures and cancellation with full queues.
- Compare the same release runner and sources with the current recipe. Record peak memory, active disk, staged disk, ingest wall time, and query p95. Check the nine 15 GB scenarios before changing the default. No threshold change is proposed.
