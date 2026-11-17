#!/bin/sh
# Run only the provider-free synthetic workloads. Invoke from the repository root.
set -eu
context_run_dir=${1:-target/context-cost/reproduction}
case "$context_run_dir" in /*) ;; *) context_run_dir="$PWD/$context_run_dir" ;; esac
if test -e "$context_run_dir"; then
    printf '%s\n' 'Choose a new context-cost directory; existing traces are never appended.' >&2
    exit 1
fi
mkdir -p "$context_run_dir/raw"
IRMIND_CONTEXT_COST_TRACE="$context_run_dir/raw" cargo nextest run -p irmind \
    --test skills_runtime --all-features --cargo-profile release --locked \
    --run-ignored all -E 'test(record_context_cost) | test(subagents_mixed)'
python3 scripts/context_cost/analyze.py --traces "$context_run_dir/raw" \
    --output "$context_run_dir/measured.json" --engine-commit "$(git rev-parse HEAD)"
