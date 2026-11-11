#!/usr/bin/env bash
# Paired current-format release measurements on one runner; no retired writer paths.
set -euo pipefail
if [[ ! "${BASE_REF:-}" =~ ^[0-9a-f]{40}$ ]]; then
    echo 'Set BASE_REF to the full current-format reference commit.' >&2
    exit 2
fi
root=$(pwd)
scratch_root=$root
suffix=
if [[ "${OS:-}" == Windows_NT ]]; then
    suffix=.exe
    scratch_root=$(cygpath -u "${RUNNER_TEMP:-$root}")
fi
scratch=$(mktemp -d "$scratch_root/w.XXXXXXXX")
native_path() { if [[ -n "$suffix" ]]; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }
shell_path() { if [[ -n "$suffix" ]]; then cygpath -u "$1"; else printf '%s\n' "$1"; fi; }
cleanup() {
    git worktree remove --force "$scratch/reference" || true
    rm -rf -- "$scratch"
}
trap cleanup EXIT
git worktree add --detach "$scratch/reference" "$BASE_REF"
mkdir "$scratch/runtime"
export TMPDIR TMP TEMP
TMPDIR=$(native_path "$scratch/runtime")
TMP=$TMPDIR TEMP=$TMPDIR
unset IRMIND_HUNTEVAL_ROOT IRMIND_BENCH_WORKERS
export IRMIND_BENCH_SCENARIO=cloud
filter=parquet_worker_benchmark_1gib
case "${WORKER_WORKLOAD:-cloud-files}" in
    cloud-files) ;;
    endpoint-files) export IRMIND_BENCH_SCENARIO=endpoint-64-chronological ;;
    endpoint-disorder) export IRMIND_BENCH_SCENARIO=endpoint-64 ;;
    ndjson-1gib|ndjson-4gib)
        filter=benchmark_single_ndjson_release
        export IRMIND_BENCH_NDJSON_GIB=1
        if [[ "$WORKER_WORKLOAD" == ndjson-4gib ]]; then
            export IRMIND_BENCH_NDJSON_GIB=4
            free_bytes=$(python3 -c 'import shutil,sys; print(shutil.disk_usage(sys.argv[1]).free)' "$TMPDIR")
            if (( free_bytes < 134 * 1024 * 1024 * 1024 )); then
                echo 'The 4 GiB source requires 134 GiB free for normal ingest preflight.' >&2
                exit 3
            fi
        fi
        ;;
    *) echo 'Unsupported current-format worker workload.' >&2; exit 2 ;;
esac
export CARGO_TARGET_DIR
CARGO_TARGET_DIR=$(native_path "${CARGO_TARGET_DIR:-$root/target}")
build_binary() {
    local workspace=$1 target=$2
    (cd "$workspace"; CARGO_TARGET_DIR="$target" cargo test -p irmind-infra --release --locked --lib --no-run --message-format=json) |
        python3 -c '
import json,sys
paths=[]
for line in sys.stdin:
    row=json.loads(line)
    if row.get("reason")=="compiler-message":
        print(row["message"].get("rendered", ""),file=sys.stderr,end="")
    if row.get("reason")=="compiler-artifact" and row["target"]["name"]=="irmind_infra" and row.get("executable"):
        paths.append(row["executable"])
assert len(paths)==1
print(paths[0])'
}
reference=$(build_binary "$scratch/reference" "$(native_path "$scratch/reference-target")")
cp "$(shell_path "$reference")" "$scratch/reference$suffix"
rm -rf -- "$scratch/reference-target"
candidate=$(build_binary "$root" "$CARGO_TARGET_DIR")
cp "$(shell_path "$candidate")" "$scratch/candidate$suffix"
cores=$(python3 -c 'import os; print(min(os.cpu_count() or 1,256))')
printf 'reference=%s candidate=%s available_cores=%s profile=release\n' "$BASE_REF" "$(git rev-parse HEAD)" "$cores" | tee worker-sweep-metadata.txt
run() {
    local version=$1 label=$2
    if [[ -n "$suffix" ]]; then
        python3 -B scripts/benchmark_windows_peak.py "$(native_path "$scratch/$version$suffix")" "$filter" --ignored --nocapture --test-threads 1 2>&1 | tee "worker-sweep-$label.txt"
    else
        /usr/bin/time -f 'WORKER_SWEEP peak_rss_kib=%M elapsed_seconds=%e' "$scratch/$version" "$filter" --ignored --nocapture --test-threads 1 2>&1 | tee "worker-sweep-$label.txt"
    fi
}
for cap in $(printf '%s\n' 1 4 "$cores" auto | awk '!seen[$0]++'); do
    if [[ "$cap" == auto ]]; then unset IRMIND_BENCH_WORKERS; else export IRMIND_BENCH_WORKERS=$cap; fi
    for pair in 1 2 3; do
        if (( pair % 2 )); then
            run reference "reference-$cap-$pair"
            run candidate "candidate-$cap-$pair"
        else
            run candidate "candidate-$cap-$pair"
            run reference "reference-$cap-$pair"
        fi
    done
done
