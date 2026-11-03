#!/usr/bin/env python3
"""Capture the first three real demo-presentation scenes with the reviewed VHS image."""
import argparse
import getpass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'ghcr.io/charmbracelet/vhs@sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path)
    args = parser.parse_args()
    output = ROOT / 'docs/ux/demo-guide/presentation-preview'
    with tempfile.TemporaryDirectory(prefix='irmind-demo-preview-') as temporary:
        scratch = Path(temporary)
        executable = scratch / 'irmind'
        shutil.copyfile(args.binary, executable)
        executable.chmod(0o755)
        shutil.copyfile(ROOT / 'docs/demo/presentation-preview.tape', scratch / 'preview.tape')
        run = subprocess.run([
            'docker', 'run', '--rm', '--init', '--network', 'none', '--pull=never',
            '--memory', '1g', '--cpus', '2', '--pids-limit', '256',
            '--user', f'{os.getuid()}:{os.getgid()}', '--env', 'HOME=/tmp/irmind-demo-home',
            '--mount', f'type=bind,src={scratch},dst=/app', '--workdir', '/app',
            IMAGE, 'preview.tape',
        ], text=True, capture_output=True)
        if run.returncode:
            raise SystemExit('VHS preview failed: ' + run.stderr[-3000:] + run.stdout[-1000:])
        transcript = (scratch / 'preview.ascii').read_text(errors='replace')
        for private in [str(Path.home()), getpass.getuser(), os.uname().nodename, '/home/', '/Users/', 'C:\\Users\\']:
            if private and private in transcript:
                raise SystemExit('Preview contains environment-specific data')
        for term in ['Step 1 of 10', 'Step 2 of 10', 'Step 3 of 10', 'Evidence ready:', '90% confidence', 'IRMind v0.1.5']:
            if term not in transcript:
                raise SystemExit('Preview is missing a real scene result: ' + term)
        output.mkdir(parents=True, exist_ok=True)
        for name in ['01-welcome.png', '02-case.png', '03-evidence.png']:
            shutil.copyfile(scratch / name, output / name)
    print('Captured three offline scenes; temporary files removed.')


if __name__ == '__main__':
    main()
