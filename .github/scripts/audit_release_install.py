#!/usr/bin/env python3
"""Install a signed release in a clean runner, using an exact tag or the stable default."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

from release_version import release_kind


def command(args):
    result = subprocess.run([str(x) for x in args], capture_output=True, timeout=600)
    if result.returncode:
        raise SystemExit('Verified installation audit failed; no raw environment diagnostics published.')
    return result.stdout.decode('utf-8').strip()


def verified_installer(tag, installer, root):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', tag):
        raise SystemExit('Choose an exact release tag')
    for asset in [installer, 'SHA256SUMS', 'SHA256SUMS.sigstore.json']:
        command(['gh', 'release', 'download', tag, '-R', 'ns2switch/irmind', '-p', asset, '-D', root])
    command(['cosign', 'verify-blob', root / 'SHA256SUMS', '--bundle', root / 'SHA256SUMS.sigstore.json',
             '--certificate-identity', f'https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/{tag}',
             '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'])
    matches = [line.split()[0] for line in (root / 'SHA256SUMS').read_text().splitlines()
               if len(line.split()) == 2 and line.split()[1] == installer]
    if len(matches) != 1 or hashlib.sha256((root / installer).read_bytes()).hexdigest() != matches[0]:
        raise SystemExit('Installer checksum verification failed')
    return root / installer


def stable_tag():
    release = json.loads(command(['gh', 'api', 'repos/ns2switch/irmind/releases/latest',
                                  '--jq', '{tag_name, draft, prerelease}']))
    tag = release['tag_name']
    if release_kind(tag) != 'stable' or release['draft'] is not False or release['prerelease'] is not False:
        raise SystemExit('Expected a published stable release')
    return tag


def main(tag):
    default = tag == 'latest'
    if default:
        tag = stable_tag()
    windows = platform.system() == 'Windows'
    installer = 'install.ps1' if windows else 'install.sh'
    with tempfile.TemporaryDirectory(prefix='irmind-install-audit-') as temporary:
        script = Path(installer).resolve() if default else verified_installer(tag, installer, Path(temporary))
        if windows:
            binary = Path(os.environ['LOCALAPPDATA']) / 'IRMind/bin/irmind.exe'
            helper = binary.with_name('irmind-evtx.exe')
            args = ['pwsh', '-NoProfile', '-File', script]
            if not default:
                args += ['-Version', tag]
        else:
            binary = Path.home() / '.local/bin/irmind'
            helper = binary.with_name('irmind-evtx')
            args = ['sh', script]
            if not default:
                args.append(tag)
        if binary.exists() or helper.exists():
            raise SystemExit('Installation target is not clean')
        command(args)
        if not helper.is_file() or command([binary, '--version']) != 'irmind ' + tag[1:]:
            raise SystemExit('Installed release/helper did not match the tag')
        command([binary, '--help'])
        with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as env:
            env.write('IRMIND_DEMO_PTY_BINARY=' + str(binary) + '\n')
        print(f'Installed and verified {tag} ({"stable default" if default else "exact tag"}). CLI help passed.')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--tag', required=True)
    main(p.parse_args().tag)
