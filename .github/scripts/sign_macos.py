#!/usr/bin/env python3
"""Tag-only Developer ID signing; dormant until the protected environment is ready."""
import argparse
import base64
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import subprocess
import tempfile

FIELDS = ('APPLE_SIGNING_CERTIFICATE_P12_BASE64', 'APPLE_SIGNING_CERTIFICATE_PASSWORD',
          'APPLE_SIGNING_IDENTITY', 'APPLE_API_KEY_ID', 'APPLE_API_ISSUER_ID',
          'APPLE_API_PRIVATE_KEY')


def enabled_environment(env):
    if env.get('GITHUB_EVENT_NAME') != 'push' or not re.fullmatch(
            r'refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', env.get('GITHUB_REF', '')):
        raise ValueError('Native signing requires a release tag push')
    if env.get('MACOS_NATIVE_SIGNING_ENABLED') != 'true':
        raise ValueError('Native signing is disabled')
    if any(not env.get(name) for name in FIELDS):
        raise ValueError('The protected release environment is incomplete')
    if not env['APPLE_SIGNING_IDENTITY'].startswith('Developer ID Application: '):
        raise ValueError('A Developer ID Application identity is required')


def run(*args):
    # Never expose command arguments or raw diagnostics: import uses a password.
    result = subprocess.run([str(x) for x in args], capture_output=True, timeout=1800)
    if result.returncode:
        raise RuntimeError(f'{Path(args[0]).name} failed; native release is blocked')
    return result.stdout.decode('utf-8', errors='replace')


def sign(source):
    enabled_environment(os.environ)
    if platform.system() != 'Darwin':
        raise ValueError('Developer ID signing requires a macOS runner')
    original_keychains = run('security', 'list-keychains', '-d', 'user').splitlines()
    original_keychains = [x.strip().strip('"') for x in original_keychains]
    with tempfile.TemporaryDirectory(prefix='irmind-sign-', dir=os.environ['RUNNER_TEMP']) as temp:
        root = Path(temp); root.chmod(0o700)
        certificate = root / 'certificate.p12'; key = root / 'notary.p8'
        certificate.write_bytes(base64.b64decode(os.environ[FIELDS[0]], validate=True))
        key.write_text(os.environ['APPLE_API_PRIVATE_KEY'])
        certificate.chmod(0o600); key.chmod(0o600)
        keychain = root / 'signing.keychain-db'; password = secrets.token_hex(32)
        try:
            run('security', 'create-keychain', '-p', password, keychain)
            run('security', 'set-keychain-settings', '-lut', '1800', keychain)
            run('security', 'unlock-keychain', '-p', password, keychain)
            run('security', 'list-keychains', '-d', 'user', '-s', keychain, *original_keychains)
            run('security', 'import', certificate, '-k', keychain, '-P',
                os.environ['APPLE_SIGNING_CERTIFICATE_PASSWORD'], '-T', '/usr/bin/codesign')
            run('security', 'set-key-partition-list', '-S', 'apple-tool:,apple:', '-s',
                '-k', password, keychain)
            identity = os.environ['APPLE_SIGNING_IDENTITY']
            payload = root / 'payload'; payload.mkdir()
            for name in ('irmind', 'irmind-evtx'):
                binary = source / name
                if not binary.is_file() or binary.is_symlink():
                    raise ValueError('Missing regular macOS release binary')
                run('codesign', '--force', '--options', 'runtime', '--timestamp', '--sign',
                    identity, '--keychain', keychain, binary)
                run('codesign', '--verify', '--strict', binary)
                # codesign writes display output to stderr; validate runtime with -dv separately.
                details = subprocess.run(['codesign', '-dv', '--verbose=4', str(binary)],
                                         capture_output=True, timeout=30)
                if details.returncode or b'runtime' not in details.stderr:
                    raise ValueError('Hardened runtime verification failed')
                shutil.copy2(binary, payload / name)
            dmg = source / 'IRMind-macos-aarch64.dmg'
            run('hdiutil', 'create', '-volname', 'IRMind', '-srcfolder', payload,
                '-format', 'UDZO', dmg)
            run('codesign', '--force', '--timestamp', '--sign', identity, '--keychain', keychain, dmg)
            response = json.loads(run('xcrun', 'notarytool', 'submit', dmg, '--key', key,
                                     '--key-id', os.environ['APPLE_API_KEY_ID'], '--issuer',
                                     os.environ['APPLE_API_ISSUER_ID'], '--wait', '--timeout', '25m',
                                     '--output-format', 'json'))
            if response.get('status') != 'Accepted':
                raise ValueError('Apple did not accept the notarization submission')
            log = json.loads(run('xcrun', 'notarytool', 'log', response['id'], '--key', key,
                                 '--key-id', os.environ['APPLE_API_KEY_ID'], '--issuer',
                                 os.environ['APPLE_API_ISSUER_ID']))
            if log.get('issues'):
                raise ValueError('Notarization returned issues; review privately before release')
            run('xcrun', 'stapler', 'staple', dmg)
            run('xcrun', 'stapler', 'validate', dmg)
            run('hdiutil', 'verify', dmg)
            print('Developer ID, hardened runtime and stapled DMG notarization verified.')
        finally:
            try:
                run('security', 'list-keychains', '-d', 'user', '-s', *original_keychains)
            finally:
                if keychain.exists():
                    run('security', 'delete-keychain', keychain)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    try:
        sign(parser.parse_args().source)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired):
        raise SystemExit('Native signing/notarization failed closed; no signed artifact published.') from None
