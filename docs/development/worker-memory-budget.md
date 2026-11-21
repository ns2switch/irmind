# Worker memory budget

**Status.** Measurement and proposal for a later change.

The scheduler reserves 512 MiB for the coordinator and 512 MiB per source or
query worker. With the existing 4 GiB per-operation budget, the memory ceiling
is seven workers. By default the CPU ceiling leaves one logical CPU free.
A worker preference can lower the effective limit. [Scheduler](../../crates/infra/src/parquet_store/workers.rs).

## Proposed setting

Keep 4 GiB as the default. If workloads on dedicated machines benefit from a
higher cap, add a signed per-installation preference in `/settings`, bounded
to at most 8 GiB. Apply the lower of the validated memory ceiling, the CPU
ceiling and the worker preference. Keep the existing coordinator and worker
reservations and the independent per-source, queue and writer bounds.

An explicit setting is portable across OS and container configurations.
Automatic detection would need to account for container or job limits,
headroom and concurrent operations. Available-memory telemetry alone cannot
reserve memory for the operation. A future shared reservation pool would
also need to cover simultaneous ingestion and scans before raising the cap.

## Release measurements

The paired runs use the same 1,077,079,150-byte synthetic CloudTrail-shaped
corpus in 1,030 files. CPU affinity exposes four or sixteen logical CPUs on
one Linux machine. The comparison changes only the budget constant in an
isolated benchmark build. Peak RSS covers the full benchmark process,
including its queries and verification. The table records median ingestion
wall time and peak RSS across three repetitions.

| Logical CPUs | Budget | Workers | Ingest seconds (median) | Peak RSS MiB (median) |
| ---: | ---: | ---: | ---: | ---: |
| 4 | 4 GiB | 3 | 35.815 | 116.2 |
| 4 | 8 GiB | 3 | 35.622 | 116.2 |
| 16 | 4 GiB | 7 | 26.985 | 200.6 |
| 16 | 8 GiB | 15 | 30.556 | 343.9 |

The 16-CPU prototype raised median ingestion time by 13.2% and peak RSS by
71.4%. Both budgets wrote 259,162,335 bytes of Parquet in every run. Keep the
shipping budget at 4 GiB. Before adding a configurable cap, measure larger
corpora and concurrent queries on a dedicated machine.

The [worker benchmark](../../crates/infra/src/tests/parquet_benchmark.rs) uses
the `parquet_worker_benchmark_1gib` release test with
`IRMIND_BENCH_SCENARIO=cloud`. The paired measurement changed the constant
in a disposable benchmark build and used the default worker preference.
