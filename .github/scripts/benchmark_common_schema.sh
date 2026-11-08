#!/usr/bin/env bash
# Paired release measurements; no model, credentials or remote evidence.
set -euo pipefail
[[ "$BASE_REF" =~ ^[0-9a-f]{40}$ ]]
candidate=$(git rev-parse HEAD)
git merge-base --is-ancestor "$BASE_REF" "$candidate"
cleanup() {
  if [[ "${stage:-}" == baseline ]]; then
    git restore --source="$BASE_REF" -- crates/infra/src/tests/parquet_benchmark.rs crates/infra/src/tests/hunteval_eval.rs
  fi
  git checkout --detach "$candidate" >/dev/null
}
trap cleanup EXIT
failed=0
for stage in baseline candidate; do
  revision=$candidate
  unset IRMIND_BENCH_COMMON_EVENT
  if [[ "$stage" == baseline ]]; then
    revision=$BASE_REF
  elif [[ "${MAPPED_CANDIDATE:-true}" == true ]]; then
    export IRMIND_BENCH_COMMON_EVENT=1
  fi
  git checkout --detach "$revision"
  output="common-schema-$stage.txt"
  echo "PAIRED_REVISION stage=$stage commit=$revision scenario=$IRMIND_BENCH_SCENARIO" | tee "$output"
  cargo test -p irmind-infra --release --locked --no-run
  # Exercise the new metadata and scoped-identity compaction paths before
  # spending time on large corpora. A functional rejection is not a latency.
  if [[ "$stage" == candidate ]]; then
    cargo test -p irmind-infra --lib parquet_store::tests::common --release --locked -- --test-threads 1 2>&1 | tee -a "$output"
    cargo test -p irmind-infra --lib tests::mapped_ --release --locked -- --test-threads 1 2>&1 | tee -a "$output"
  fi
  # Add only the larger test harness to older baselines. Production source,
  # parsing, schemas, queries and limits remain those of the pinned commit.
  if [[ "$stage" == baseline ]]; then
    python3 - <<'PY_SMOKE'
from pathlib import Path
path = Path("crates/infra/src/tests/parquet_benchmark.rs")
source = path.read_text()
if "fn common_schema_smoke_1gib()" not in source:
    assert "fn benchmark(files: usize, multiplier: usize, label: &str)" in source
    source += '\n#[test]\n#[ignore = "paired release measurement: 1 GiB"]\nfn common_schema_smoke_1gib() { benchmark(1030, 1, "1gib"); }\n'
marker = '    let bundles = ingest\n        .compact_case'
assert marker in source
source = source.replace(marker, '    let layout_started = Instant::now();\n' + marker, 1)
marker = '    println!("PARQUET_COMPACTION bundles={bundles}");'
assert marker in source
source = source.replace(marker, marker + '\n    println!("PARQUET_LAYOUT_TIME seconds={:.6}", layout_started.elapsed().as_secs_f64());', 1)
path.write_text(source)
path = Path("crates/infra/src/tests/hunteval_eval.rs")
source = path.read_text()
old = """pub(super) fn stage_sources(root: &Path, episodes: &[Episode]) -> Vec<String> {
    episodes
        .iter()"""
new = """pub(super) fn stage_sources(root: &Path, episodes: &[Episode]) -> Vec<String> {
    let mut hashes = std::collections::BTreeSet::new();
    episodes
        .iter()
        .filter(|episode| hashes.insert(episode.hash.clone()))"""
assert old in source
path.write_text(source.replace(old, new, 1))
PY_SMOKE
    echo 'PAIRED_HARNESS smoke_files=1030 production_unchanged=true unique_public_sources=true' | tee -a "$output"
  fi
  # Both sides run three >=1 GiB repetitions per representative source.
  if [[ "$IRMIND_BENCH_SCENARIO" == cloud-v2 || "$IRMIND_BENCH_SCENARIO" == endpoint-v2-64-chronological ]]; then
    smoke=common_schema_smoke_1gib
    for repetition in 1 2 3; do
      echo "SMOKE_REPETITION=$repetition" | tee -a "$output"
      if ! cargo test -p irmind-infra "$smoke" --release --locked -- --ignored --nocapture --test-threads 1 2>&1 | tee -a "$output"; then failed=1; fi
    done
  fi
  if ! cargo test -p irmind-infra parquet_benchmark_15gb --release --locked -- --ignored --nocapture --test-threads 1 2>&1 | tee -a "$output"; then failed=1; fi
  if [[ "$stage" == baseline ]]; then
    git restore --source="$BASE_REF" -- crates/infra/src/tests/parquet_benchmark.rs crates/infra/src/tests/hunteval_eval.rs
  fi
done
exit "$failed"
