#!/usr/bin/env bash
# Synthetic Azure data, with both tagged and candidate binaries on one runner.
set -euo pipefail
root=$PWD
work=$(mktemp -d "${RUNNER_TEMP:-$root/target}/azure-pair.XXXXXXXX")
export TMPDIR="$work/runtime" CARGO_TARGET_DIR="$work/target" CARGO_INCREMENTAL=0
export IRMIND_AZURE_BENCH_MIB=1024 CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
mkdir "$TMPDIR"
git fetch --no-tags origin refs/tags/v0.6.1:refs/tags/v0.6.1
git worktree add --detach "$work/baseline" v0.6.1
rustup toolchain install 1.95.0 --profile minimal
for variant in v0.6.1 compact; do
    tree=$root
    if [[ $variant == v0.6.1 ]]; then tree=$work/baseline; fi
    (
        cd "$tree"
        cargo test --release --locked -p irmind-infra --lib benchmark_azure_flow_release \
            --no-run --message-format=json > "$work/compilation.json"
    ) 2>&1 | tee "$root/release-profile-$variant-build.txt"
    binary=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "irmind_infra" and .profile.test and .executable != null) | .executable' "$work/compilation.json")
    test -x "$binary"
    for format in vnet nsg; do
        for order in ordered disordered; do
            IRMIND_AZURE_BENCH_FORMAT=$format IRMIND_AZURE_BENCH_ORDER=$order \
                /usr/bin/time -f 'PROCESS_PEAK_RSS_KIB=%M' "$binary" \
                benchmark_azure_flow_release --ignored --nocapture --test-threads 1 \
                2>&1 | tee "$root/release-profile-$variant-azure-$format-$order.txt"
        done
    done
    if [[ $variant == v0.6.1 ]]; then
        (cd "$tree" && cargo clean --release)
    fi
done
