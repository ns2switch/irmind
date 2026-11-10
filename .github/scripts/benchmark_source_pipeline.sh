#!/usr/bin/env bash
set -euo pipefail
[[ "${BASE_REF:-}" =~ ^[0-9a-f]{40}$ ]] || { echo 'baseline must be a commit hash' >&2; exit 2; }
export CARGO_TARGET_DIR="$GITHUB_WORKSPACE/target"
export IRMIND_EVTX_HELPER_TEST="$CARGO_TARGET_DIR/release/irmind-evtx"
export IRMIND_EVTX_SOURCE_BENCH_INPUT="$RUNNER_TEMP/pipeline-synthetic.evtx"
work=$(mktemp -d "$RUNNER_TEMP/source-pipeline.XXXXXXXX")
mkdir -p pipeline-results
cleanup() {
  git worktree remove --force "$work/baseline" 2>/dev/null || true
  rm -rf -- "$work"
  rm -f -- "$IRMIND_EVTX_SOURCE_BENCH_INPUT"
}
trap cleanup EXIT
candidate=$(git rev-parse HEAD)
git cat-file -e "$BASE_REF^{commit}"
git worktree add --detach "$work/baseline" "$BASE_REF"
heaptrack_version=$(heaptrack --version | head -n 1)
export PIPELINE_BASELINE="$BASE_REF" PIPELINE_CANDIDATE="$candidate" PIPELINE_HEAPTRACK_VERSION="$heaptrack_version"
python3 - <<'PY'
import json, os
from pathlib import Path
Path('pipeline-results/metadata.json').write_text(json.dumps({
    'baseline':os.environ['PIPELINE_BASELINE'], 'candidate':os.environ['PIPELINE_CANDIDATE'],
    'heaptrack':os.environ['PIPELINE_HEAPTRACK_VERSION'], 'runner':'ubuntu-24.04',
    'build':'release', 'repetitions':3, 'minimum_source_bytes':1073741824,
    'sources':['evtx','ecs','cloudtrail','linux-journald'],
    'method':'Timings without Heaptrack; separate V3 allocation runs. Ingestion uses normal source hashing, mapping, partitioning, Parquet writing and signed custody. Nested timing intervals are labeled inclusive.'
},indent=2)+'\n')
PY
PYTHONDONTWRITEBYTECODE=1 python3 scripts/generate_evtx_mapping_benchmark.py "$IRMIND_EVTX_SOURCE_BENCH_INPUT"
cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked
build() {
  local tree=$1 label=$2
  cargo test --manifest-path "$tree/Cargo.toml" -p irmind-infra --release --locked --no-run --message-format=json > "$work/$label-build.json"
  python3 - "$work/$label-build.json" "$work/bin-$label" <<'PY'
import json, shutil, sys
executables=[]
for line in open(sys.argv[1]):
    try: value=json.loads(line)
    except ValueError: continue
    if value.get('reason')=='compiler-artifact' and value.get('target',{}).get('name')=='irmind_infra' and value.get('profile',{}).get('test') and value.get('executable'):
        executables.append(value['executable'])
if len(executables)!=1: raise SystemExit('expected one production-profile test executable')
shutil.copy2(executables[0],sys.argv[2])
PY
}
build "$work/baseline" baseline
labels=(baseline)
if [[ "$BASE_REF" != "$candidate" ]]; then
  build "$GITHUB_WORKSPACE" candidate
  labels+=(candidate)
fi
export IRMIND_PIPELINE_BYTES=1073741824
unset IRMIND_PIPELINE_VARIANT
for source in evtx ecs cloudtrail linux; do
  export IRMIND_PIPELINE_SOURCE="$source"
  for label in "${labels[@]}"; do
    exe="$work/bin-$label"
    [[ -f "$exe" && -x "$exe" ]] || { echo "missing production-profile test executable" >&2; exit 2; }
    "$exe" --exact tests::parquet_benchmark::pipeline::source_pipeline_production_1gib --ignored --nocapture --test-threads=1 > "$work/timings.txt" 2>&1
    sed -n -E '/^(PIPELINE_PRODUCTION|PIPELINE_SOURCE|CUSTODY_PHASE) /p' "$work/timings.txt" > "pipeline-results/$label-$source-timings.txt"
    test "$(grep -c '^PIPELINE_PRODUCTION ' "pipeline-results/$label-$source-timings.txt")" = 6
    IRMIND_PIPELINE_VARIANT=v3 heaptrack --output "$work/capture" "$exe" --exact tests::parquet_benchmark::pipeline::source_pipeline_production_1gib --ignored --nocapture --test-threads=1 > "$work/heaptrack.txt" 2>&1
    capture=$(find "$work" -maxdepth 1 -name 'capture*' -type f -print)
    test -n "$capture"
    heaptrack_print "$capture" --print-peaks=false --print-allocators=false --print-temporary=false --print-flamegraph "$work/stacks.txt" --flamegraph-cost-type allocations > "$work/analysis.txt" 2>&1
    revision=$candidate
    [[ "$label" != baseline ]] || revision=$BASE_REF
    python3 scripts/profile_pipeline_allocations.py "$work/stacks.txt" "pipeline-results/$label-$source-allocations.json" --source "$source" --revision "$revision" --heaptrack-version "$heaptrack_version"
    rm -f -- "$capture" "$work/stacks.txt" "$work/analysis.txt" "$work/heaptrack.txt"
  done
done
