#!/usr/bin/env bash
# Manual release-only measurements. Both revisions run on this same runner.
set -euo pipefail
[[ "$BASE_REF" =~ ^[0-9a-f]{40}$ ]]
candidate=$(git rev-parse HEAD)
git merge-base --is-ancestor "$BASE_REF" "$candidate"
trap 'git checkout --detach "$candidate" >/dev/null' EXIT
failed=0
for stage in baseline candidate; do
  revision=$candidate
  if [[ "$stage" == baseline ]]; then revision=$BASE_REF; fi
  git checkout --detach "$revision"
  output="benchmark-pair-$stage.txt"
  echo "PAIRED_REVISION stage=$stage commit=$revision scenario=$IRMIND_BENCH_SCENARIO" | tee "$output"
  # Compile outside the timed ingestion, with identical release flags and lockfile.
  cargo test -p irmind-infra --release --locked --no-run
  if ! cargo test -p irmind-infra parquet_benchmark_15gb --release --locked -- --ignored --nocapture --test-threads 1 2>&1 | tee -a "$output"; then
    failed=1
  fi
  # Tests own their temporary sources and cases, including assertion failures.
done
exit "$failed"
