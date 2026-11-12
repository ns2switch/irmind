# Bounded parallel mapping preparation

This note is for contributors reducing the serial work in single-source ingestion.
The [release profile](benchmarks.md#current-mapped-single-file-worker-profile)
shows mapping and checked row preparation on the producer's critical path.

## Execution

Split the existing per-source worker allowance between format decoding and pure
mapping preparation. Each mapping lane has at most one outstanding input batch and
bounded channels. Reserve 128 MiB per lane from the existing queue allowance.
Input batches stop at 256 records or an 8 MiB conservative retained-size charge;
a larger valid single record is processed alone. Output frames stop at a 4 MiB
charge, or one valid larger output. The worker waits for an acknowledgement
after each frame is committed, preventing accumulation of oversized results.
The domain caches the source scheduling charge during its existing tree
validation; this derived integer is absent from canonical encoding.
Small budgets keep the sequential path. Writer completion remains parallel as
before; partition allocation and canonical append remain sequential.

Mapping lanes perform identified catalog selection, mapping, canonical source
hash preparation and checked row projection. They receive no storage, audit,
signer, clock, secret or remote tool port. Outputs return in original record
order, regardless of completion order. Source hashes are still verified before
any group is published or signed.

## Checked preparation

An opaque prepared record binds its original tainted source and provenance to
the exact frozen mapping catalog. Only the application can construct it. At
ordered commit, the existing accumulator checks source/decoder identity,
provenance, record order, offsets, count and format limits, then appends the
same canonical tuple and updates the same mapping counts. A preparation from a
different catalog or source cannot be committed. No method releases tainted
content for an authorized tool call.

Format decoders and source mappers keep their existing port signatures. New
helpers are concrete application utilities, not alternate ingestion ports.
Current envelopes, builder recipe, physical row groups, seals, export frames
and golden bytes remain unchanged.

## Completion and failure

Finish pending canonical results before classifying a later decoder error, so
an earlier callback failure retains precedence. Successful decoding still
drains and authenticates the source reader. Cancellation is checked while
waiting. Errors close job and result channels before joining workers; provisional
groups still roll back completely. No parent cancellation token is reused as an
internal stop flag.

## Validation

Compare artifacts, commitments and complete signed chains at 1, 2, 4 and the
machine's bounded maximum. Test changed sources, cross-catalog preparation,
reordered or repeated records, callback failure, cancellation and rollback.
Run current physical and export golden fixtures unchanged. Measure three paired
1 GiB repetitions, the 4 GiB NDJSON source and contained EVTX on native runners,
then the full current 15 GB matrix with the same absolute query/ingestion gates.
