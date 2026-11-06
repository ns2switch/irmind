#!/usr/bin/env python3
"""Publish AST unsafe metrics without build-machine paths or diagnostic text."""
import json
import sys
from pathlib import Path


def normalize(raw):
    packages = []
    for item in raw['packages']:
        identity = item['package']['id']
        metrics = item['unsafety']
        packages.append({
            'crate': identity['name'], 'version': identity['version'],
            'forbids_unsafe': metrics['forbids_unsafe'],
            'used': metrics['used'], 'unused': metrics['unused'],
        })
    return {
        'tool': 'cargo-geiger 0.13.0', 'target': 'x86_64-unknown-linux-gnu',
        'method': 'AST metrics for all helper targets under native Linux cfg; not a safety proof',
        'limitations': [
            'Macro expansions and non-Linux cfg branches are not execution coverage.',
            'The source inventory additionally lists target-specific dependencies.',
            'Generated expressions and documentation can be outside the AST scan.',
        ],
        'packages': sorted(packages, key=lambda p: (p['crate'], p['version'])),
        'packages_without_metrics': [
            {'crate': p['name'], 'version': p['version']}
            for p in raw['packages_without_metrics']
        ],
        'unscanned_inputs': sorted(
            Path(p).name for p in raw['used_but_not_scanned_files']
        ),
    }


if __name__ == '__main__':
    print(json.dumps(normalize(json.load(sys.stdin)), indent=2, sort_keys=True))
