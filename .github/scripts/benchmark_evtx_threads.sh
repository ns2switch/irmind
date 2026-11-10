#!/usr/bin/env bash
set -euo pipefail
release="target/$CARGO_BUILD_TARGET/release"
suffix=${SUFFIX:-}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

benchmark() {
    local label=$1 executable=$2
    local helper="$scratch/irmind-evtx$suffix"
    cp "$executable" "$helper"
    # Native tests and the benchmark use the same helper through the unchanged broker.
    if [[ -n "$suffix" ]]; then
        export IRMIND_EVTX_HELPER_TEST
        IRMIND_EVTX_HELPER_TEST=$(cygpath -m "$helper")
    else
        export IRMIND_EVTX_HELPER_TEST="$helper"
    fi
    cargo test --manifest-path helpers/evtx/Cargo.toml --release --locked \
        --test native --test decode --test witness -- --test-threads 1
    python3 -B scripts/benchmark_evtx_large.py "$release/examples/large_collection$suffix" \
        --one-gib --batch-files 1 --output "evtx-threads-$label.json"
}

benchmark one "$release/irmind-evtx$suffix"
# Linux continues to use the unchanged serial route inside seccomp.
if [[ "$(uname -s)" == Linux ]]; then
    exit 0
fi
benchmark four "$release/examples/parallel_trial_four$suffix"
benchmark all "$release/examples/parallel_trial$suffix"
