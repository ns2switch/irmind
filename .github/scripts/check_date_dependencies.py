#!/usr/bin/env python3
"""Check the locked date replacement and the exact reviewed source patches."""
from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[2]
LOCKS = ('Cargo.lock', 'fuzz/Cargo.lock', 'helpers/evtx/Cargo.lock', 'helpers/evtx/fuzz/Cargo.lock')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    for relative in LOCKS:
        names = set(re.findall(r'^name = "([A-Za-z0-9_-]+)"$', (ROOT / relative).read_text(encoding="utf-8"), re.MULTILINE))
        retired = names & {'chrono', 'humantime'}
        if retired:
            raise SystemExit(f'{relative}: retired dependencies: {sorted(retired)}')
    reviewed = 0
    unsafe_sources = 0
    for name in ('arrow-array', 'parquet'):
        base = ROOT / 'vendor' / name
        manifest = json.loads((base / 'UPSTREAM.json').read_text(encoding="utf-8"))
        for relative, expected in manifest['reviewed_file_sha256'].items():
            path = base / relative
            if path.is_symlink() or not path.resolve().is_relative_to(base.resolve()):
                raise SystemExit(f'{name}: invalid reviewed source path')
            if digest(path.read_bytes()) != expected:
                raise SystemExit(f'{name}/{relative}: reviewed source hash differs')
            reviewed += 1
        for relative, expected in manifest['upstream_unsafe_source_sha256'].items():
            source = (base / relative).read_text(encoding="utf-8").replace('irmind_calendar::', 'chrono::')
            for kind in ('upstream_doc_whitespace_restoration', 'upstream_safe_diagnostic_restorations'):
                for new, old in manifest.get(kind, {}).get(relative, []):
                    if source.count(new) != 1:
                        raise SystemExit(f'{name}/{relative}: reviewed source restoration differs')
                    source = source.replace(new, old)
            if digest(source.encode()) != expected:
                raise SystemExit(f'{name}/{relative}: upstream unsafe-bearing source changed')
            unsafe_sources += 1
    print(f'Date dependencies removed from {len(LOCKS)} locks; {reviewed} reviewed files and {unsafe_sources} unchanged unsafe-bearing sources verified')


if __name__ == '__main__':
    main()
