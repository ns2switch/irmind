#!/usr/bin/env python3
"""Check or refresh the release's data-only skill commitments (no dependencies)."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def inventory(root):
    packages, checksums = {}, []
    for method in sorted(root.glob('*/SKILL.md')):
        files = sorted(p for p in method.parent.rglob('*') if p.is_file())
        canonical = bytearray(b'irmind-skill-package-v1\0')
        canonical.extend(struct.pack('>Q', len(files)))
        for path in files:
            name = path.relative_to(method.parent).as_posix().encode('ascii')
            content = path.read_bytes()
            digest = hashlib.sha256(content)
            canonical.extend(struct.pack('>Q', len(name)))
            canonical.extend(name)
            canonical.extend(struct.pack('>Q', len(content)))
            canonical.extend(digest.digest())
            checksums.append(f'{digest.hexdigest()}  {path.relative_to(root).as_posix()}\n')
        packages[method.parent.name] = hashlib.sha256(canonical).hexdigest()
    return {
        'package-identities.json': json.dumps(packages, indent=2) + '\n',
        'SHA256SUMS': ''.join(checksums),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / 'skills'
    for name, expected in inventory(root).items():
        path = root / name
        if args.write:
            path.write_text(expected)
        elif path.read_text() != expected:
            raise SystemExit(f'Stale skill inventory: {name}')
    print('Skill resource and canonical package commitments match.')


if __name__ == '__main__':
    main()
