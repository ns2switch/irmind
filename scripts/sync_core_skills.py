#!/usr/bin/env python3
"""Check the local core mirror, or sync data from an explicit local upstream commit.

Usage: python3 scripts/sync_core_skills.py [UPSTREAM_CHECKOUT COMMIT]
No network access is performed. Review and commit the resulting diff through a PR.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from skills_inventory import inventory

REPOSITORY = 'https://github.com/ns2switch/irmind-skills'
MAX_FILE_BYTES = 1_000_000
MAX_TOTAL_BYTES = 16_000_000
MAX_FILES = 512


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(root, relative):
    if not isinstance(relative, str) or not re.fullmatch(r'[A-Za-z0-9_./-]+', relative):
        raise ValueError('invalid mirror path')
    parts = relative.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('invalid mirror path component')
    target = root.joinpath(*parts)
    if root.is_symlink():
        raise ValueError('linked mirror root')
    for index in range(1, len(parts) + 1):
        if root.joinpath(*parts[:index]).is_symlink():
            raise ValueError('linked mirror path')
    return target


def validate_rows(rows):
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
        raise ValueError('invalid mirror file count')
    sources, destinations = set(), set()
    for row in rows:
        if set(row) != {'source', 'path', 'sha256'}:
            raise ValueError('unsupported mirror entry')
        source, destination = row['source'], row['path']
        safe_path(Path('.'), source)
        safe_path(Path('.'), destination)
        if source.startswith('core/'):
            parts = source.split('/')
            if len(parts) < 3 or not re.fullmatch('[a-z][a-z0-9-]{0,63}', parts[1]):
                raise ValueError('invalid core package path')
            if destination != 'skills/' + source[5:]:
                raise ValueError('core mirror destination changed')
        elif source.startswith('episodes/'):
            if not destination.startswith(('crates/testkit/fixtures/',
                                           'crates/modules/parser-json/tests/fixtures/')):
                raise ValueError('episode mirror escapes fixture directories')
            if Path(destination).suffix not in ('.json', '.jsonl', '.ndjson', '.log', '.csv', '.txt'):
                raise ValueError('episode mirror must contain data only')
        else:
            raise ValueError('unsupported upstream data path')
        if not isinstance(row['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', row['sha256']):
            raise ValueError('invalid resource commitment')
        if source in sources or destination in destinations:
            raise ValueError('duplicate mirror entry')
        sources.add(source)
        destinations.add(destination)
    if rows != sorted(rows, key=lambda row: row['source']):
        raise ValueError('mirror entries must be ordered by source')


def validate_pin(pin):
    if set(pin) != {'format_version', 'repository', 'commit', 'packages', 'files'}:
        raise ValueError('unsupported pin fields')
    if pin['format_version'] != 1 or pin['repository'] != REPOSITORY:
        raise ValueError('unsupported upstream identity')
    if not isinstance(pin['commit'], str) or not re.fullmatch('[0-9a-f]{40}', pin['commit']):
        raise ValueError('upstream commit must be a full object ID')
    if not isinstance(pin['packages'], dict) or not 1 <= len(pin['packages']) <= 64:
        raise ValueError('invalid package inventory')
    for name, checksum in pin['packages'].items():
        if not re.fullmatch('[a-z][a-z0-9-]{0,63}', name) or not re.fullmatch('[0-9a-f]{64}', checksum):
            raise ValueError('invalid package identity')
    validate_rows(pin['files'])


def check(root):
    pin = json.loads(safe_path(root, 'skills/upstream.json').read_bytes())
    validate_pin(pin)
    total = 0
    for row in pin['files']:
        target = safe_path(root, row['path'])
        if target.stat().st_size > MAX_FILE_BYTES:
            raise ValueError('mirror resource exceeds development limit')
        data = target.read_bytes()
        total += len(data)
        if digest(data) != row['sha256']:
            raise ValueError('mirror checksum mismatch: ' + row['path'])
    if total > MAX_TOTAL_BYTES:
        raise ValueError('mirror exceeds total development limit')
    packages = set(pin['packages'])
    observed = set()
    for method in (root / 'skills').glob('*/SKILL.md'):
        name = method.parent.name
        observed.add(name)
        expected = {row['path'] for row in pin['files'] if row['source'].startswith('core/' + name + '/')}
        actual = set()
        for path in method.parent.rglob('*'):
            if path.is_symlink():
                raise ValueError('linked package resource')
            if path.is_file():
                actual.add(path.relative_to(root).as_posix())
        if actual != expected:
            raise ValueError('untracked or missing core resource: ' + name)
    if observed != packages:
        raise ValueError('core package set differs from upstream pin')
    generated = inventory(root / 'skills')
    if json.loads(generated['package-identities.json']) != pin['packages']:
        raise ValueError('canonical package commitments differ from upstream pin')
    for name, value in generated.items():
        if safe_path(root, 'skills/' + name).read_bytes() != value.encode():
            raise ValueError('stale core inventory: ' + name)
    return pin


def git_blob(checkout, commit, path):
    safe_path(Path('.'), path)
    entry = subprocess.check_output(['git', '-C', str(checkout), 'ls-tree', commit, '--', path], text=True)
    fields = entry.strip().split('\t')
    if len(fields) != 2 or fields[1] != path:
        raise ValueError('missing upstream blob: ' + path)
    mode, kind, object_id = fields[0].split()
    if mode != '100644' or kind != 'blob':
        raise ValueError('upstream resource must be a regular non-executable blob')
    size = int(subprocess.check_output(['git', '-C', str(checkout), 'cat-file', '-s', object_id]))
    if size > MAX_FILE_BYTES:
        raise ValueError('upstream blob exceeds development limit')
    return subprocess.check_output(['git', '-C', str(checkout), 'cat-file', 'blob', object_id])


def synchronize(root, checkout, commit):
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('supply the full immutable upstream commit')
    resolved = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', '--verify', commit + '^{commit}'], text=True).strip()
    if resolved != commit:
        raise ValueError('upstream object is not the requested commit')
    mapping = json.loads(git_blob(checkout, commit, 'source-map.json'))
    if set(mapping) != {'format_version', 'files'} or mapping['format_version'] != 1:
        raise ValueError('unsupported upstream source map')
    pin = {'format_version': 1, 'repository': REPOSITORY, 'commit': commit,
           'packages': json.loads(git_blob(checkout, commit, 'core/package-identities.json')),
           'files': mapping['files']}
    validate_pin(pin)
    copies, total = {}, 0
    for row in pin['files']:
        target = safe_path(root, row['path'])
        data = git_blob(checkout, commit, row['source'])
        if digest(data) != row['sha256']:
            raise ValueError('upstream resource checksum mismatch')
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('upstream mirror exceeds total development limit')
        copies[target] = data
    old_pin = root / 'skills/upstream.json'
    obsolete = []
    if old_pin.exists():
        old = check(root)
        destinations = {row['path'] for row in pin['files']}
        obsolete = [safe_path(root, row['path']) for row in old['files'] if row['path'] not in destinations]
    # Validate the complete candidate before changing tracked data.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='irmind-core-check-') as temporary:
        candidate = Path(temporary)
        for path, data in copies.items():
            staged = candidate / path.relative_to(root)
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(data)
        for name, value in inventory(candidate / 'skills').items():
            (candidate / 'skills' / name).write_text(value, encoding='utf-8', newline='\n')
        (candidate / 'skills/upstream.json').write_text(json.dumps(pin, indent=2) + '\n', encoding='utf-8')
        check(candidate)
    for path, data in copies.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for path in obsolete:
        path.unlink()
    for name, value in inventory(root / 'skills').items():
        safe_path(root, 'skills/' + name).write_text(value, encoding='utf-8', newline='\n')
    safe_path(root, 'skills/upstream.json').write_text(json.dumps(pin, indent=2) + '\n', encoding='utf-8', newline='\n')
    return check(root)


def main():
    root = Path(__file__).resolve().parents[1]
    if len(sys.argv) == 1:
        pin = check(root)
    elif len(sys.argv) == 3:
        pin = synchronize(root, Path(sys.argv[1]).resolve(), sys.argv[2])
    else:
        raise ValueError(__doc__)
    print(f"Core mirror matches {pin['commit']}: {len(pin['packages'])} packages, {len(pin['files'])} resources and fixtures.")


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
