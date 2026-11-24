#!/usr/bin/env bash
set -euo pipefail
mkdir -p .tools
gh release download 0.13.2 -R rust-fuzz/cargo-fuzz -p cargo-fuzz-0.13.2-x86_64-unknown-linux-musl.tar.gz -O .tools/cargo-fuzz.tar.gz
printf '%s  %s\n' b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c .tools/cargo-fuzz.tar.gz | sha256sum --check
tar -xzf .tools/cargo-fuzz.tar.gz -C .tools
install -m 0755 .tools/cargo-fuzz "$HOME/.cargo/bin/cargo-fuzz"
