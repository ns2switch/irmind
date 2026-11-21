#!/usr/bin/env bash
# Compare the shipping profile and ThinLTO on the same synthetic inputs.
set -euo pipefail
root=$(pwd)
mkdir -p target
work=$(mktemp -d "${RUNNER_TEMP:-$root/target}/release-profile.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir "$work/runtime"
export TMPDIR="$work/runtime"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_STRIP=symbols
unset CARGO_PROFILE_RELEASE_LTO CARGO_PROFILE_RELEASE_CODEGEN_UNITS
unset IRMIND_HUNTEVAL_ROOT IRMIND_BENCH_WORKERS IRMIND_BENCH_NDJSON_GIB

build() (
    profile=$1
    export CARGO_TARGET_DIR="$work/$profile"
    if [[ "$profile" == thin ]]; then
        export CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
    fi
    TIMEFORMAT='RELEASE_BINARY_BUILD elapsed_seconds=%R'
    time cargo build --release --locked -p irmind
    TIMEFORMAT='RELEASE_HELPER_BUILD elapsed_seconds=%R'
    time cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked --bin irmind-evtx
    wc -c < "$CARGO_TARGET_DIR/release/irmind" | awk '{printf "RELEASE_BINARY bytes=%s\n", $1}'
    wc -c < "$CARGO_TARGET_DIR/release/irmind-evtx" | awk '{printf "RELEASE_HELPER bytes=%s\n", $1}'
    (
        cd "$CARGO_TARGET_DIR/release/build"
        find . -path '*/out/native-mapping-manifest.bin' -type f -print0 |
            sort -z | xargs -0 -r sha256sum |
            sed -E 's@ \./(.*)-[[:xdigit:]]+/out/native-mapping-manifest.bin$@ \1@' |
            sort -u
    ) > "$root/release-profile-$profile-mapping-identities.txt"
    test -s "$root/release-profile-$profile-mapping-identities.txt"
    sha256sum "$CARGO_TARGET_DIR/release/irmind" "$CARGO_TARGET_DIR/release/irmind-evtx" |
        sed -E 's@  .*/@  @' > "$root/release-profile-$profile-shipping-sha256.txt"
    cp "$CARGO_TARGET_DIR/release/irmind-evtx" "$CARGO_TARGET_DIR/shipping-irmind-evtx"
    cargo build --manifest-path helpers/evtx/Cargo.toml --release --locked --example large_collection
    cargo test --locked --release -p irmind --test identity_ingest --test format_goldens --no-run
    cargo test --locked --release -p irmind-infra --lib --no-run
    mv "$CARGO_TARGET_DIR/shipping-irmind-evtx" "$CARGO_TARGET_DIR/release/irmind-evtx"
)

exercise() (
    profile=$1
    export CARGO_TARGET_DIR="$work/$profile"
    bin="$CARGO_TARGET_DIR/release/deps"
    goldens=("$bin"/format_goldens-*)
    identities=("$bin"/identity_ingest-*)
    infra=("$bin"/irmind_infra-*)
    # Fresh build directories contain exactly one executable for each suite.
    executable() {
        local path
        for path do
            if [[ -f "$path" && -x "$path" ]]; then
                printf '%s\n' "$path"
            fi
        done
    }
    "$(executable "${goldens[@]}")" --test-threads 1
    echo "BENCHMARK source=json-cloudtrail"
    "$(executable "${infra[@]}")" benchmark_single_ndjson_release --ignored --nocapture --test-threads 1
    echo "BENCHMARK source=m365"
    IRMIND_BENCH_PARSER=m365 "$(executable "${identities[@]}")" --exact one_gib_release_throughput --ignored --nocapture --test-threads 1
    echo "BENCHMARK source=fdr"
    "$(executable "${identities[@]}")" one_gib_release_fdr_gzip_and_jsonl --ignored --nocapture --test-threads 1
    echo "BENCHMARK source=evtx"
    (
        cd "$work/runtime"
        python3 -B "$root/scripts/benchmark_evtx_large.py" "$CARGO_TARGET_DIR/release/examples/large_collection" --output "$root/release-profile-$profile-evtx.json"
    )
)
for profile in default thin; do
    build "$profile" 2>&1 | tee "release-profile-$profile-build.txt"
done
cmp release-profile-default-mapping-identities.txt release-profile-thin-mapping-identities.txt
for profile in default thin; do
    exercise "$profile" 2>&1 | tee "release-profile-$profile-benchmarks.txt"
done
