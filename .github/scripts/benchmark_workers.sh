#!/usr/bin/env bash
set -euo pipefail

if [[ ! "${BASE_REF:-}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "Set BASE_REF to the full fixed-worker reference commit." >&2
    exit 2
fi
candidate=$(git rev-parse HEAD)
root=$(pwd)
scratch=$(mktemp -d)
cleanup() {
    git worktree remove --force "$scratch/reference" || true
    rm -rf -- "$scratch"
}
trap cleanup EXIT
git worktree add --detach "$scratch/reference" "$BASE_REF"
workload=${WORKER_WORKLOAD:-cloud-files}
case "$workload" in
    cloud-files)
        # The fixed-worker reference needs the same 1 GiB corpus as the candidate.
        python3 - "$scratch/reference/crates/infra/src/tests/parquet_benchmark.rs" <<'PYWORKLOAD'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = 'benchmark(1_000, 1, "1gb");'
assert text.count(old) == 1
path.write_text(text.replace(old, 'benchmark(1_030, 1, "1gb");'))
PYWORKLOAD
        ;;
    ndjson-1gib|ndjson-4gib)
        export IRMIND_BENCH_NDJSON_GIB=1
        if [[ "$workload" == ndjson-4gib ]]; then
            export IRMIND_BENCH_NDJSON_GIB=4
            # Allow for the 4 GiB input plus normal production disk preflight.
            free_kib=$(df -Pk "${TMPDIR:-/tmp}" | awk 'NR == 2 {print $4}')
            if (( free_kib < 134 * 1024 * 1024 )); then
                echo "The 4 GiB workload needs at least 134 GiB free for input and normal ingest preflight." >&2
                exit 3
            fi
        fi
        # Compile the identical benchmark harness on the adaptive-pool parent.
        harness=crates/infra/src/tests/mapped_pipeline/workers
        mkdir -p "$scratch/reference/$harness"
        cp "$harness/benchmark.rs" "$scratch/reference/$harness/benchmark.rs"
        printf '\nmod benchmark;\n' >> "$scratch/reference/$harness.rs"
        ;;
    *)
        echo "Unsupported worker workload." >&2
        exit 2
        ;;
esac

export IRMIND_BENCH_SCENARIO=cloud-v2 IRMIND_BENCH_COMMON_EVENT=1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
unset IRMIND_HUNTEVAL_ROOT IRMIND_BENCH_WORKERS
build_binary() {
    local workspace=$1
    (
        cd "$workspace"
        cargo test -p irmind-infra --release --locked --lib --no-run --message-format=json
    ) | python3 -c '
import json, sys
rows = (json.loads(line) for line in sys.stdin)
binaries = [r["executable"] for r in rows if r.get("reason") == "compiler-artifact"
            and r["target"]["name"] == "irmind_infra" and r.get("executable")]
assert len(binaries) == 1
print(binaries[0])
'
}
reference=$(build_binary "$scratch/reference")
cp "$reference" "$scratch/fixed"
current=$(build_binary "$root")
cp "$current" "$scratch/adaptive"
cores=$(nproc)
printf 'reference=%s candidate=%s available_cores=%s\n' "$BASE_REF" "$candidate" "$cores" |
    tee worker-sweep-metadata.txt
run() {
    local version=$1 filter=$2 label=$3
    /usr/bin/time -f 'WORKER_SWEEP peak_rss_kib=%M elapsed_seconds=%e' \
        "$scratch/$version" "$filter" --ignored --nocapture --test-threads 1 2>&1 |
        tee "worker-sweep-$label.txt"
}
if [[ "$workload" == cloud-files ]]; then
    run fixed '::parquet_benchmark_1gb' fixed-four
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
