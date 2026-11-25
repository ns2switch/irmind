#!/usr/bin/env bash
set -euo pipefail
mode=$1
shift
case "$mode" in
  daily) seconds=90 ;;
  weekly|pr|identity) seconds=600 ;;
  *) exit 2 ;;
esac
declare -A metadata
for target in "$@"; do
  registry=${target%:*}
  name=${target##*:}
  if [[ ! "$name" =~ ^[a-z][a-z0-9_]*$ ]]; then exit 2; fi
  case "$registry" in
    fuzz|helpers/evtx/fuzz) ;;
    *) exit 2 ;;
  esac
  test -f "$registry/fuzz_targets/$name.rs"
  if [[ ! -v "metadata[$registry]" ]]; then
    metadata[$registry]=$(cargo +nightly metadata --locked --no-deps --format-version 1 --manifest-path "$registry/Cargo.toml")
  fi
  required=$(python3 -c '
import json
import sys
targets = (target for package in json.load(sys.stdin)["packages"] for target in package["targets"])
print(",".join(next(target for target in targets if target["name"] == sys.argv[1]).get("required-features", [])))
' "$name" <<< "${metadata[$registry]}")
  features=()
  if [[ -n "$required" ]]; then features=(--features "$required"); fi
  corpus="$registry/corpus/$name"
  mkdir -p "$corpus"
  case "$target" in
    fuzz:sigma_field_table)
      for table in crates/infra/src/sigma_pack/*-v1.toml; do
        sed -E 's/mapping_version = "@([^"]+)"/mapping_version = "\10000000000000000000000000000000000000000000000000000000000000000"/' "$table" \
          > "$corpus/$(basename "$table")"
      done
      cat "$corpus/"*-v1.toml > "$corpus/all-variants.toml"
      ;;
    helpers/evtx/fuzz:evtx_decode) cp "$registry/seeds/security.evtx" "$corpus/" ;;
    helpers/evtx/fuzz:evtx_protocol) cp "$registry/seeds/protocol/"* "$corpus/" ;;
    *) if [[ -d "$registry/seeds/$name" ]]; then cp "$registry/seeds/$name/"* "$corpus/"; fi ;;
  esac
  case "$target" in
    fuzz:export)
      CARGO_PROFILE_RELEASE_OPT_LEVEL=0 cargo +nightly fuzz run "$name" --target x86_64-unknown-linux-gnu --features export --sanitizer none -- -max_total_time="$seconds" -rss_limit_mb=2048 -verbosity=0
      ;;
    fuzz:sigma_admission)
      cargo +nightly fuzz run "$name" --target x86_64-unknown-linux-gnu --sanitizer address -- -max_total_time="$seconds" -rss_limit_mb=2048 -max_len=65537 -verbosity=0
      ;;
    fuzz:sigma_field_table)
      CARGO_PROFILE_RELEASE_OPT_LEVEL=1 cargo +nightly fuzz run "$name" --target x86_64-unknown-linux-gnu --features export --sanitizer address -- -max_total_time="$seconds" -rss_limit_mb=2048 -max_len=524289 -verbosity=0
      ;;
    helpers/evtx/fuzz:evtx_decode)
      cargo +nightly fuzz run "$name" --target x86_64-unknown-linux-gnu --fuzz-dir "$registry" --sanitizer address -- -max_total_time="$seconds" -rss_limit_mb=1024 -timeout=30 -max_len=131072
      ;;
    helpers/evtx/fuzz:evtx_protocol)
      cargo +nightly fuzz run "$name" --target x86_64-unknown-linux-gnu --fuzz-dir "$registry" --sanitizer address -- -max_total_time="$seconds" -rss_limit_mb=1024 -timeout=10 -max_len=4194304
      ;;
    *)
      limits=(-max_total_time="$seconds" -rss_limit_mb=2048 -verbosity=0)
      if [[ "$mode" == identity || "$mode" == pr || "$mode" == daily ]]; then
        limits+=(-max_len=4194304)
      fi
      cargo +nightly fuzz run "$name" --target x86_64-unknown-linux-gnu --fuzz-dir "$registry" --sanitizer address "${features[@]}" -- "${limits[@]}"
      ;;
  esac
done
