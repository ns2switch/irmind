#!/usr/bin/env python3
"""Publish AST unsafe metrics without build-machine paths or diagnostic text."""
import json
import sys
from pathlib import Path


def parse_errors(diagnostics, production):
    errors = []
    for line in diagnostics.splitlines():
        if not line.startswith('Failed to parse file: '):
            continue
        path = line.removeprefix('Failed to parse file: ').split(', Syn(', 1)[0]
        marker = '/registry/src/'
        parts = path.split(marker, 1)[-1].split('/')
        if marker not in path or len(parts) < 3:
            raise SystemExit('unsafe audit could not parse a first-party or unidentified source')
        package = parts[1]
        if package in production:
            raise SystemExit('unsafe audit could not parse a production dependency')
        errors.append({'package': package, 'file': '/'.join(parts[2:]),
                       'scope': 'non-production dependency; metrics incomplete'})
    return errors


def normalize(raw, diagnostics='', inventory=None):
    production = {f"{p['crate']}-{p['version']}" for p in (inventory or [])}
    failures = parse_errors(diagnostics, production)
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
        'parse_errors': failures,
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
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--diagnostics', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text())['packages']
    report = normalize(json.load(sys.stdin), args.diagnostics.read_text(), inventory)
    print(json.dumps(report, indent=2, sort_keys=True))
