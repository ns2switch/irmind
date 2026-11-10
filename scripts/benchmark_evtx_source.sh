#!/bin/sh
# Optimized paired EVTX measurements; requires the matching isolated helper.
set -eu
exec cargo test --release --locked -p irmind --bin irmind \
  evtx_source_pipeline_one_gib_release -- --ignored --nocapture "$@"
