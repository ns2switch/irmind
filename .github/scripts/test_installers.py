#!/usr/bin/env python3
"""Offline installer behavior tests; real signature checks remain release gates."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
FAKE=r'''
import json,os,shutil,sys
from pathlib import Path
from urllib.parse import urlparse
name=Path(sys.argv[0]).stem
args=sys.argv[1:]
if name=='fake_tool':name,args=args[0],args[1:]
with open(os.environ['IRMIND_INSTALL_TEST_LOG'],'a',encoding='utf-8') as log:
 log.write(json.dumps([name]+args)+'\n')
if name=='uname':
 print('Linux' if args==['-s'] else 'x86_64')
elif name=='curl':
 url=args[-1]
 if not url.startswith('https://github.com/ns2switch/irmind/releases/download/'):
  sys.exit(22)
 file=Path(urlparse(url).path).name
 try:shutil.copyfile(Path(os.environ['IRMIND_INSTALL_TEST_ASSETS'])/file,args[args.index('--output')+1])
 except OSError:sys.exit(22)
elif name=='cosign':
 if args==['version']:print('GitVersion: v3.1.4')
 elif Path(args[1]).name==os.environ.get('IRMIND_INSTALL_TEST_FAIL_SIGNATURE'):sys.exit(1)
elif name=='gh':
 if '--help' not in args and Path(args[2]).name==os.environ.get('IRMIND_INSTALL_TEST_FAIL_ATTESTATION'):sys.exit(1)
else:sys.exit(2)
'''


class Installers(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='.irmind-installer-test-',dir=Path.home())
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.assets=self.root/'assets';self.assets.mkdir()
        tools=self.root/'tools';tools.mkdir()
        self.install=self.root/'home'/'bin';self.install.parent.mkdir()
        self.env=os.environ.copy()
        self.env.update(HOME=str(self.install.parent),IRMIND_INSTALL_TEST_ASSETS=str(self.assets),
                        IRMIND_INSTALL_TEST_LOG=str(self.root/'calls.jsonl'),
                        IRMIND_TEST_EXECUTED=str(self.root/'download-was-executed'))
        self.env['PATH']=str(tools)+os.pathsep+self.env['PATH']
        tool_source=tools/'fake_tool.py';tool_source.write_text(FAKE,encoding='utf-8')
        for name in ('uname','curl','cosign','gh'):
            if os.name=='nt':
                (tools/(name+'.cmd')).write_text('@echo off\r\n"'+sys.executable+'" "'+str(tool_source)+'" '+name+' %*\r\nexit /b %errorlevel%\r\n')
            else:
                path=tools/name
                path.write_text('#!'+sys.executable+'\n'+FAKE,encoding='utf-8');path.chmod(0o700)
        self.main='irmind-windows-x86_64.exe' if os.name=='nt' else 'irmind-linux-x86_64'
        self.helper=self.main.replace('irmind-','irmind-evtx-',1)
        for name in (self.main,self.helper):
            (self.assets/name).write_bytes(b'#!/bin/sh\nprintf executed > "$IRMIND_TEST_EXECUTED"\n')
            (self.assets/(name+'.sigstore.json')).write_text('{}',encoding='utf-8')
        (self.assets/'SHA256SUMS.sigstore.json').write_text('{}',encoding='utf-8')
        self.checksums()

    def checksums(self, helper=True):
        names=[self.main]+([self.helper] if helper else [])
        (self.assets/'SHA256SUMS').write_text(''.join(hashlib.sha256((self.assets/name).read_bytes()).hexdigest()+'  '+name+'\n' for name in names),encoding='utf-8')

    def run_installer(self, version='v0.2.0'):
        if os.name=='nt':
            source=(ROOT/'install.ps1').read_text(encoding='utf-8')
            replacement=r'''function Download-Https([string]$Url, [string]$Destination, [long]$MaximumBytes) {
    if (-not $Url.StartsWith('https://github.com/ns2switch/irmind/releases/download/')) { throw 'unexpected test URL' }
    $name = [System.IO.Path]::GetFileName(([System.Uri]$Url).LocalPath)
    Copy-Item -LiteralPath (Join-Path $env:IRMIND_INSTALL_TEST_ASSETS $name) -Destination $Destination
}'''
            source,count=re.subn(r'(?ms)^function Download-Https\(.*?^}',lambda _:replacement,source,count=1)
            self.assertEqual(count,1,'the test must replace only network transfer, not verification')
            script=self.root/'installer-under-test.ps1';script.write_text(source,encoding='utf-8')
            command=['pwsh','-NoProfile','-File',str(script),'-Version',version,'-InstallDir',str(self.install)]
        else:
            command=['sh',str(ROOT/'install.sh'),version,str(self.install)]
        result=subprocess.run(command,env=self.env,capture_output=True,text=True,timeout=30)
        self.assertFalse((self.root/'download-was-executed').exists())
        return result

    def test_matching_helper_and_main_are_verified_before_installation(self):
        result=self.run_installer()
        self.assertEqual(result.returncode,0,result.stderr)
        calls=[json.loads(line) for line in (self.root/'calls.jsonl').read_text().splitlines()]
        for source,destination in [(self.main,'irmind.exe' if os.name=='nt' else 'irmind'),(self.helper,'irmind-evtx.exe' if os.name=='nt' else 'irmind-evtx')]:
            self.assertEqual((self.install/destination).read_bytes(),(self.assets/source).read_bytes())
            self.assertTrue(any(call[:2]==['cosign','verify-blob'] and Path(call[2]).name==source for call in calls))
            self.assertTrue(any(call[:3]==['gh','attestation','verify'] and Path(call[3]).name==source for call in calls))

    def test_modified_helper_is_rejected_before_either_binary_is_installed(self):
        (self.assets/self.helper).write_bytes(b'altered helper')
        self.assertNotEqual(self.run_installer().returncode,0)
        self.assertFalse(self.install.exists())

    def test_missing_helper_checksum_is_rejected(self):
        self.checksums(helper=False)
        self.assertNotEqual(self.run_installer().returncode,0)
        self.assertFalse(self.install.exists())

    def test_failed_helper_signature_is_rejected(self):
        self.env['IRMIND_INSTALL_TEST_FAIL_SIGNATURE']=self.helper
        self.assertNotEqual(self.run_installer().returncode,0)
        self.assertFalse(self.install.exists())

    def test_failed_helper_attestation_is_rejected(self):
        self.env['IRMIND_INSTALL_TEST_FAIL_ATTESTATION']=self.helper
        self.assertNotEqual(self.run_installer().returncode,0)
        self.assertFalse(self.install.exists())

    def test_older_releases_keep_the_single_binary_installation(self):
        self.checksums(helper=False)
        result=self.run_installer('v0.1.6')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(list(self.install.iterdir())),1)


if __name__=='__main__':unittest.main()
