#!/usr/bin/env python3
"""Report the lexical unsafe surface of the separately locked helper dependencies.

This is a source inventory, not a reachability analysis or a safety proof.
"""
import hashlib
import json
import subprocess
from pathlib import Path
from check_unsafe_boundary import unsafe_offsets


def report():
    metadata=json.loads(subprocess.check_output([
        'cargo','metadata','--manifest-path','helpers/evtx/Cargo.toml',
        '--format-version','1','--locked',
    ],text=True))
    nodes={node['id']:node for node in metadata['resolve']['nodes']}
    included=set()
    pending=[metadata['resolve']['root']]
    while pending:
        node=pending.pop()
        if node in included: continue
        included.add(node)
        pending.extend(dep['pkg'] for dep in nodes[node]['deps']
                       if any(kind['kind'] != 'dev' for kind in dep['dep_kinds']))
    output=[]
    for package in sorted(metadata['packages'], key=lambda p:(p['name'],p['version'])):
        if package['id'] not in included: continue
        root=Path(package['manifest_path']).parent
        digest=hashlib.sha256()
        sites=0
        files=0
        for source in sorted(root.rglob('*.rs')):
            if any(part in ('target','.git','fuzz','tests','benches','examples') for part in source.relative_to(root).parts): continue
            data=source.read_bytes()
            digest.update(source.relative_to(root).as_posix().encode()+b'\0'+data)
            count=len(unsafe_offsets(data.decode('utf-8')))
            sites+=count
            files+=bool(count)
        output.append({'crate':package['name'],'version':package['version'],
                       'license':package['license'],'unsafe_sites':sites,
                       'files_with_unsafe':files,'rust_source_sha256':digest.hexdigest(),
                       'build_script':any('custom-build' in target['kind'] for target in package['targets'])})
    print(json.dumps({'method':'lexical source inventory; not a safety or reachability proof',
                      'packages':output},indent=2,sort_keys=True))

if __name__=='__main__': report()
