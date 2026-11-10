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
# Only the corpus size differs from the reference harness. Both runs use the
# same file generator, record contents, worktree toolchain and release profile.
python3 - "$scratch/reference/crates/infra/src/tests/parquet_benchmark.rs" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = 'benchmark(1_000, 1, "1gb");'
assert text.count(old) == 1
path.write_text(text.replace(old, 'benchmark(1_030, 1, "1gb");'))
PY

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
run fixed '::parquet_benchmark_1gb' fixed-four
run adaptive '::parquet_worker_benchmark_1gib' automatic
caps=(1 4)
if [[ "$cores" != 1 && "$cores" != 4 ]]; then
    caps+=("$cores")
fi
for workers in "${caps[@]}"; do
    IRMIND_BENCH_WORKERS="$workers" run adaptive '::parquet_worker_benchmark_1gib' "cap-$workers"
done
