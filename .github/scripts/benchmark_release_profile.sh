#!/usr/bin/env bash
# Synthetic Azure flow benchmark against the exact v0.6.1 source.
set -euo pipefail
export CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_STRIP=symbols
export IRMIND_AZURE_BENCH_MIB=1024

git fetch --no-tags origin refs/tags/v0.6.1:refs/tags/v0.6.1
git diff --exit-code v0.6.1 -- Cargo.toml Cargo.lock crates helpers
cargo test --release --locked -p irmind-infra --lib benchmark_azure_flow_release --no-run \
  2>&1 | tee release-profile-v0.6.1-azure-build.txt

for format in vnet nsg; do
  for order in ordered disordered; do
    IRMIND_AZURE_BENCH_FORMAT="$format" IRMIND_AZURE_BENCH_ORDER="$order" \
      cargo test --release --locked -p irmind-infra --lib benchmark_azure_flow_release -- \
      --ignored --nocapture --test-threads 1 2>&1 |
      tee "release-profile-v0.6.1-azure-$format-$order.txt"
  done
done
