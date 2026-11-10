#!/bin/sh
# Paired synthetic ECS ingestion measurements; requires an optimized release build.
set -eu
exec cargo test --release --locked -p irmind --bin irmind \
  ecs_source_pipeline_one_gib_release -- --ignored --nocapture "$@"
