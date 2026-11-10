# Production source-pipeline profiling

For contributors measuring ingestion overhead, this harness runs the real local
case ingestion, validates row counts and zero rejections, and verifies the signed
chain. Sources are synthetic EVTX, ECS, CloudTrail and Linux journald. It does not
use a model, cloud credentials or a remote data source.

The manual graph-benchmark workflow accepts `pipeline_profile=true` and
`profile_base=<40-character commit>`. The baseline must contain this harness.
It builds both revisions in release mode on one Ubuntu 24.04 runner and measures
three V2/V3 pairs of at least 1 GiB per source for each revision. The same helper
and generated EVTX file serve both revisions. Every ingestion prints its source
SHA-256, accepted count and rejected count. The run records the compiler profile,
runner label and development profiler version.

## Timing intervals

Normal timing runs do not run under Heaptrack. Decoder wrappers subtract time
spent inside the writer callback. Mapper wrappers time the selected mapping.
The production adapter supplies its existing validation/mapping, projection,
commitment-finalization, row, Parquet and partition counters. Subtracting mapper
time from validation/mapping exposes the remaining selection, validation and
commit-spool work. Hashing and custody signing/append intervals are also printed. Active artifact
bytes are reported by schema so physical storage cost stays visible.

Partition, conversion and callback intervals can contain child phases. They are
explicitly labeled inclusive and must not be added to those child intervals or
treated as a disjoint wall-clock total. The top-level elapsed ingestion interval
is the throughput measurement; verification after ingestion is outside it.

## Allocation calls

Full debug symbols, unshortened Rust trait frames and GNU demangling retain the
function names needed for allocation attribution. Missing production-phase symbols
fail the measurement instead of being reported as zero work.

A separate V3 ingestion for each revision and source runs under the distro's
Heaptrack development tool. Its allocation-call stacks are aggregated by
`scripts/profile_pipeline_allocations.py`. Each call belongs to its deepest
recognized production frame, or to an explicit outside/unattributed bucket.
The sum of all buckets must equal the observed call count. This measures calls
to allocation functions; it is not a count of simultaneously live Rust objects.
The isolated EVTX helper is a separate process and is not included in the main
process allocation counts.

The workflow uploads only timing records, metadata and aggregated JSON counters.
It deletes raw traces after aggregation and never publishes their paths or stack
contents. Heaptrack's instrumented elapsed time is not a performance result.
The tool adds no production dependency, allocator override or first-party unsafe
code. The [Heaptrack printer](https://github.com/KDE/heaptrack/blob/master/src/analyze/print/heaptrack_print.cpp)
defines the allocation-call metric used by its collapsed stacks.

## Checks

`test_profile_pipeline_allocations.py` checks exclusive attribution, totals and
invalid profiles. Existing format golden tests remain the byte-level control.
The benchmark asserts a complete source count and a valid signed chain for every
variant. A developer can reduce `IRMIND_PIPELINE_BYTES` for a local smoke only;
published release comparisons leave it unset and use at least 1 GiB.
