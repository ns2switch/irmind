#!/usr/bin/env bash
# Paired release measurements; no model, credentials or remote evidence.
set -euo pipefail
[[ "$BASE_REF" =~ ^[0-9a-f]{40}$ ]]
candidate=$(git rev-parse HEAD)
harness_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/irmind-benchmark-harness.XXXXXXXX")
restore_harness() {
  git restore --source="$BASE_REF" -- crates/infra/src/tests/parquet_benchmark.rs crates/infra/src/tests/parquet_benchmark/measurements.rs crates/infra/src/tests/hunteval_eval.rs
  local probe=crates/infra/src/tests/parquet_benchmark/staging_probe.rs
  if git cat-file -e "$BASE_REF:$probe" 2>/dev/null; then
    git restore --source="$BASE_REF" -- "$probe"
  else
    rm -f -- "$probe"
  fi
}
cleanup() {
  if [[ "${stage:-}" == baseline || "${stage:-}" == reference ]]; then
    restore_harness
  fi
  git checkout --detach "$candidate" >/dev/null
  rm -rf -- "$harness_dir"
}
trap cleanup EXIT
cp crates/infra/src/tests/parquet_benchmark/staging_probe.rs "$harness_dir/staging_probe.rs"
git merge-base --is-ancestor "$BASE_REF" "$candidate"
failed=0
stages=(baseline candidate)
if [[ "${DIRECT_WRITE:-false}" == true ]]; then stages=(reference baseline candidate); fi
for stage in "${stages[@]}"; do
  revision=$candidate
  unset IRMIND_BENCH_COMMON_EVENT
  if [[ "$stage" == baseline || "$stage" == reference ]]; then
    revision=$BASE_REF
    if [[ "$stage" == baseline && "${DIRECT_WRITE:-false}" == true ]]; then export IRMIND_BENCH_COMMON_EVENT=1; fi
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
  if [[ "$stage" == baseline || "$stage" == reference ]]; then
    cp "$harness_dir/staging_probe.rs" crates/infra/src/tests/parquet_benchmark/staging_probe.rs
    python3 - <<'PY_SMOKE'
from pathlib import Path
path = Path("crates/infra/src/tests/parquet_benchmark.rs")
source = path.read_text()
if 'mod staging_probe;' not in source:
    source = source.replace('mod measurements;', 'mod measurements;\nmod staging_probe;', 1)
    source = source.replace('    custody.reset();', '    custody.reset();\n    let staging_probe = staging_probe::StagingProbe::start(root.path().join("case/parquet"));', 1)
    source = source.replace('    let ingest_time = started.elapsed();', '    let ingest_time = started.elapsed();\n    let (peak, errors) = staging_probe.finish();\n    println!("PARQUET_TEMPORARY_DISK sampled_peak_bytes={peak} interval_ms=100 scan_errors={errors}");\n    assert_eq!(errors, 0);', 1)
if "fn common_schema_smoke_1gib()" not in source:
    assert "fn benchmark(files: usize, multiplier: usize, label: &str)" in source
    source += '\n#[test]\n#[ignore = "paired release measurement: 1 GiB"]\nfn common_schema_smoke_1gib() { benchmark(1030, 1, "1gib"); }\n'
marker = '    let bundles = ingest\n        .compact_case'
if 'let layout_started = Instant::now();' not in source:
    assert marker in source
    source = source.replace(marker, '    let layout_started = Instant::now();\n' + marker, 1)
marker = '    println!("PARQUET_COMPACTION bundles={bundles}");'
if 'PARQUET_LAYOUT_TIME' not in source:
    assert marker in source
    source = source.replace(marker, marker + '\n    println!("PARQUET_LAYOUT_TIME seconds={:.6}", layout_started.elapsed().as_secs_f64());', 1)
if 'PARQUET_INGEST_EXACT' not in source:
    marker = '    let ingestion_limit = scenario.ingestion_limit(label);'
    assert marker in source
    source = source.replace(marker, '    println!("PARQUET_INGEST_EXACT wall_ns={}", ingest_time.as_nanos());\n' + marker, 1)
path.write_text(source)
path = Path("crates/infra/src/tests/parquet_benchmark/measurements.rs")
source = path.read_text()
if 'PARQUET_QUERY_EXACT' not in source:
    marker = '        let after = profile.query_detail_snapshot();'
    assert marker in source
    addition = '''        println!(
            "PARQUET_QUERY_EXACT scenario={} scope={scope} name={label} p50_ns={} p95_ns={} errors={errors} time_budget_hits={time_budget_hits}",
            scenario.name(), timings[2].as_nanos(), timings[4].as_nanos()
        );
'''
    source = source.replace(marker, addition + marker, 1)
if 'let mut time_budget_hits = 0;' not in source:
    assert '        let mut errors = 0;' in source
    source = source.replace('        let mut errors = 0;', '        let mut errors = 0;\n        let mut time_budget_hits = 0;', 1)
    source = source.replace('.map(|_| ())', '.map(|text| text.contains("10-second time budget"))')
    source = source.replace('"timeline" => store.timeline_filtered(id, filter, 10).map(|text| text.contains("10-second time budget")),', '"timeline" => store.timeline_filtered(id, filter, 10).map(|_| false),')
    source = source.replace('            if result.is_err() {', '            if matches!(result, Ok(true)) { time_budget_hits += 1; }\n            if result.is_err() {', 1)
    source = source.replace('met_target &= errors == 0 && timings[4]', 'met_target &= errors == 0 && time_budget_hits == 0 && timings[4]', 1)
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
if old in source:
    source = source.replace(old, new, 1)
else:
    assert 'filter(|episode| hashes.insert(episode.hash.clone()))' in source
path.write_text(source)
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
  if [[ "$stage" == baseline || "$stage" == reference ]]; then
    restore_harness
  fi
done
exit "$failed"
