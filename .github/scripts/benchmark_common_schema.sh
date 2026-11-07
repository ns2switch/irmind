#!/usr/bin/env bash
# Paired release measurements; no model, credentials or remote evidence.
set -euo pipefail
[[ "$BASE_REF" =~ ^[0-9a-f]{40}$ ]]
candidate=$(git rev-parse HEAD)
git merge-base --is-ancestor "$BASE_REF" "$candidate"
trap 'git checkout --detach "$candidate" >/dev/null' EXIT
failed=0
for stage in baseline candidate; do
  revision=$candidate
  unset IRMIND_BENCH_COMMON_EVENT
  if [[ "$stage" == baseline ]]; then revision=$BASE_REF; else export IRMIND_BENCH_COMMON_EVENT=1; fi
  git checkout --detach "$revision"
  output="common-schema-$stage.txt"
  echo "PAIRED_REVISION stage=$stage commit=$revision scenario=$IRMIND_BENCH_SCENARIO" | tee "$output"
  cargo test -p irmind-infra --release --locked --no-run
  # Exercise the new metadata and scoped-identity compaction paths before
  # spending time on large corpora. A functional rejection is not a latency.
  if [[ "$stage" == candidate ]]; then
    cargo test -p irmind-infra --lib parquet_store::tests::common --release --locked -- --test-threads 1 2>&1 | tee -a "$output"
  fi
  # Candidate smoke is at least 1 GiB. The paired 15 GB corpus is identical.
  if [[ "$stage" == candidate && ( "$IRMIND_BENCH_SCENARIO" == cloud-v2 || "$IRMIND_BENCH_SCENARIO" == endpoint-v2-64-chronological ) ]]; then
    smoke=common_schema_smoke_1gib
    for repetition in 1 2 3; do
      echo "SMOKE_REPETITION=$repetition" | tee -a "$output"
      if ! cargo test -p irmind-infra "$smoke" --release --locked -- --ignored --nocapture --test-threads 1 2>&1 | tee -a "$output"; then failed=1; fi
    done
  fi
  if ! cargo test -p irmind-infra parquet_benchmark_15gb --release --locked -- --ignored --nocapture --test-threads 1 2>&1 | tee -a "$output"; then failed=1; fi
done
exit "$failed"
