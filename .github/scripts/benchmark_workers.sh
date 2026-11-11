#!/usr/bin/env bash
set -euo pipefail

if [[ ! "${BASE_REF:-}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Set BASE_REF to the full fixed-worker reference commit." >&2
    exit 2
fi
candidate=$(git rev-parse HEAD)
root=$(pwd)
suffix=
scratch_root=$root
if [[ "${OS:-}" == Windows_NT ]]; then
    suffix=.exe
    scratch_root=$(cygpath -u "${RUNNER_TEMP:-$root}")
fi
scratch=$(mktemp -d "$scratch_root/w.XXXXXXXX")
native_path() {
    if [[ -n "$suffix" ]]; then
        cygpath -m "$1"
    else
        printf '%s\n' "$1"
    fi
}
shell_path() {
    if [[ -n "$suffix" ]]; then
        cygpath -u "$1"
    else
        printf '%s\n' "$1"
    fi
}
cleanup() {
    git worktree remove --force "$scratch/reference" || true
    rm -rf -- "$scratch"
}
trap cleanup EXIT
git worktree add --detach "$scratch/reference" "$BASE_REF"
mkdir "$scratch/runtime"
export TMPDIR
TMPDIR=$(native_path "$scratch/runtime")
export TMP="$TMPDIR" TEMP="$TMPDIR"
workload=${WORKER_WORKLOAD:-cloud-files}
case "$workload" in
    cloud-files|endpoint-files|endpoint-disorder)
        # The fixed-worker reference needs the same 1 GiB corpus as the candidate.
        python3 - "$scratch/reference/crates/infra/src/tests/parquet_benchmark.rs" "$workload" <<'PYWORKLOAD'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = 'benchmark(1_000, 1, "1gb");'
assert text.count(old) == 1
new = 'benchmark(515, 2, "1gb");' if sys.argv[2] == 'endpoint-disorder' else 'benchmark(1_030, 1, "1gb");'
path.write_text(text.replace(old, new))
PYWORKLOAD
        ;;
    ndjson-1gib|ndjson-4gib)
        export IRMIND_BENCH_NDJSON_GIB=1
        if [[ "$workload" == ndjson-4gib ]]; then
            export IRMIND_BENCH_NDJSON_GIB=4
            # Allow for the 4 GiB input plus normal production disk preflight.
            free_bytes=$(python3 -c 'import shutil,sys; print(shutil.disk_usage(sys.argv[1]).free)' "$TMPDIR")
            if (( free_bytes < 134 * 1024 * 1024 * 1024 )); then
                echo "The 4 GiB workload needs at least 134 GiB free for input and normal ingest preflight." >&2
                exit 3
            fi
        fi
        # Compile the identical benchmark harness on the adaptive-pool parent.
        harness=crates/infra/src/tests/mapped_pipeline/workers
        mkdir -p "$scratch/reference/$harness"
        cp "$harness/benchmark.rs" "$scratch/reference/$harness/benchmark.rs"
        python3 - "$scratch/reference/$harness.rs" <<'PYHARNESS'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text()
if not re.search(r"(?m)^mod benchmark;$", text):
    text += "\nmod benchmark;\n"
assert len(re.findall(r"(?m)^mod benchmark;$", text)) == 1
path.write_text(text)
PYHARNESS
        ;;
    *)
        echo "Unsupported worker workload." >&2
        exit 2
        ;;
esac

export IRMIND_BENCH_SCENARIO=cloud-v2 IRMIND_BENCH_COMMON_EVENT=1
case "$workload" in
    endpoint-files) export IRMIND_BENCH_SCENARIO=endpoint-v2-64-chronological ;;
    endpoint-disorder) export IRMIND_BENCH_SCENARIO=endpoint-v2-64 ;;
esac
export CARGO_TARGET_DIR
CARGO_TARGET_DIR=$(native_path "${CARGO_TARGET_DIR:-$root/target}")
unset IRMIND_HUNTEVAL_ROOT IRMIND_BENCH_WORKERS
build_binary() {
    local workspace=$1 target=$2
    (
        cd "$workspace"
        CARGO_TARGET_DIR="$target" cargo test -p irmind-infra --release --locked --lib --no-run --message-format=json
    ) | python3 -c '
import json, sys
binaries = []
for line in sys.stdin:
    row = json.loads(line)
    if row.get("reason") == "compiler-message":
        message = row["message"].get("rendered")
        if message:
            print(message, file=sys.stderr, end="")
    if row.get("reason") == "compiler-artifact" and row["target"]["name"] == "irmind_infra" and row.get("executable"):
        binaries.append(row["executable"])
assert len(binaries) == 1
print(binaries[0])
'
}
# Never reuse first-party Cargo fingerprints between distinct source trees.
reference=$(build_binary "$scratch/reference" "$(native_path "$scratch/reference-target")")
cp "$(shell_path "$reference")" "$scratch/fixed$suffix"
rm -rf -- "$scratch/reference-target"
current=$(build_binary "$root" "$CARGO_TARGET_DIR")
cp "$(shell_path "$current")" "$scratch/adaptive$suffix"
cores=$(python3 -c 'import os; print(os.cpu_count() or 1)')
printf 'reference=%s candidate=%s available_cores=%s\n' "$BASE_REF" "$candidate" "$cores" |
    tee worker-sweep-metadata.txt
run() {
    local version=$1 filter=$2 label=$3
    if [[ -n "$suffix" ]]; then
        python3 -B scripts/benchmark_windows_peak.py "$(native_path "$scratch/$version$suffix")" \
            "$filter" --ignored --nocapture --test-threads 1 2>&1 |
            tee "worker-sweep-$label.txt"
    else
        /usr/bin/time -f 'WORKER_SWEEP peak_rss_kib=%M elapsed_seconds=%e' \
            "$scratch/$version" "$filter" --ignored --nocapture --test-threads 1 2>&1 |
            tee "worker-sweep-$label.txt"
    fi
}
if [[ "$workload" == *-files || "$workload" == endpoint-disorder ]]; then
    IRMIND_BENCH_WORKERS=4 run fixed '::parquet_benchmark_1gb' reference-four
    filter='::parquet_worker_benchmark_1gib'
else
    filter='::benchmark_single_ndjson_release'
    IRMIND_BENCH_WORKERS="$cores" run fixed "$filter" reference
fi
run adaptive "$filter" automatic
caps=(1 4)
if [[ "$cores" != 1 && "$cores" != 4 ]]; then
    caps+=("$cores")
fi
for workers in "${caps[@]}"; do
    IRMIND_BENCH_WORKERS="$workers" run adaptive "$filter" "cap-$workers"
done
