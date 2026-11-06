#!/usr/bin/env python3
"""Exercise the actual helper on Linux without privileged containers or network."""
import json
import os
import re
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

HELPER=Path(sys.argv[1]).resolve(strict=True)
FIXTURE=Path('crates/testkit/fixtures/parser-evtx/source/Security.evtx').resolve(strict=True)
CANARY='irmind-containment-canary'


def check(command, directory):
    with FIXTURE.open('rb') as source:
        run=subprocess.run(command,stdin=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                           cwd=directory,env={},timeout=20,check=False)
    if run.returncode != 0 or len(run.stdout)>4096:
        raise SystemExit('EVTX native isolation probe failed')
    if json.loads(run.stdout) != {'kind':'probe','protocol':'irmind-evtx-ndjson-v1','isolated':True}:
        raise SystemExit('EVTX native isolation handshake was invalid')


def main():
    with tempfile.TemporaryDirectory(prefix='.evtx-native-',dir=Path.cwd()) as temporary:
        directory=Path(temporary)
        os.chmod(directory,0o700)
        canary=directory/CANARY
        canary.write_bytes(b'synthetic isolation canary')
        os.chmod(canary,0o600)
        check([str(HELPER),'--probe-v1'],directory)
        with FIXTURE.open('rb') as source:
            decoded=subprocess.run([str(HELPER),'--protocol-v1'],stdin=source,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=directory,env={},timeout=20,check=False)
    if decoded.returncode != 0 or len(decoded.stdout)>4*1024*1024:
        raise SystemExit('EVTX native decoding failed')
    frames=[json.loads(line) for line in decoded.stdout.splitlines()]
    if frames[-1] != {'kind':'complete','accepted':14,'rejected':0}:
        raise SystemExit('EVTX native record counts differed')
    print(json.dumps({'native_userspace':Path('/etc/os-release').read_text(),
                      'native_kernel':os.uname().release,'probe':'passed'},sort_keys=True))
    if sys.argv[2:] == ['native-only']: return
    for image in (
        'debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc',
        'fedora:44@sha256:15da97ed9aa94dd3d92c3925eb89520f6c80e07ea7ee24cba848d1f8b6912b3e',
    ):
        subprocess.run(['docker','pull',image],check=True)
        script='mkdir /work; chmod 700 /work; printf synthetic > /work/'+CANARY+'; chmod 600 /work/'+CANARY+'; cd /work; exec /opt/helper --probe-v1 < /opt/evidence.evtx'
        name='irmind-evtx-'+uuid.uuid4().hex
        try:
            result=subprocess.run(['docker','run','--rm','--name',name,'--network','none',
                '--mount',f'type=bind,src={HELPER},dst=/opt/helper,readonly',
                '--mount',f'type=bind,src={FIXTURE},dst=/opt/evidence.evtx,readonly',
                '--entrypoint','/bin/sh',image,'-ec',script],capture_output=True,timeout=30,check=False)
        finally:
            subprocess.run(['docker','rm','--force',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        if result.returncode != 0 or json.loads(result.stdout).get('isolated') is not True:
            # Only fixed diagnostic categories/version tokens, never arbitrary output.
            errors=result.stderr.decode('utf-8',errors='replace')[:4096]
            print(json.dumps({'container_exit':result.returncode,
                              'required_glibc':sorted(set(re.findall(r'GLIBC_[0-9.]+',errors))),
                              'landlock_required':'fully enforced Landlock' in errors,
                              'file_denial_failed':'file isolation verification failed' in errors,
                              'network_denial_failed':'network' in errors},sort_keys=True),flush=True)
            raise SystemExit('EVTX container isolation failed for '+image)
        print(json.dumps({'userspace':image,'shared_host_kernel':os.uname().release,'probe':'passed'},sort_keys=True))

if __name__=='__main__': main()
