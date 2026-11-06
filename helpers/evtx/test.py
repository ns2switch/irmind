#!/usr/bin/env python3
"""Test the normal helper binary independently of integration-test feature unification."""
import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def check_decoder_features(root, env):
    tree = subprocess.check_output([
        'cargo', 'tree', '--manifest-path', 'helpers/evtx/Cargo.toml', '--locked',
        '-e', 'normal,build,features', '--prefix', 'none',
    ], cwd=root, env=env, text=True)
    forbidden = ['irmind-process-containment feature "launcher"',
                 'windows-sys feature "Win32_UI_Shell"',
                 'windows-sys feature "Win32_System_Com"']
    if any(feature in tree for feature in forbidden):
        raise SystemExit('decoder build contains broker-only native features')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--profile', default='ci')
    parser.add_argument('--test-threads')
    parser.add_argument('--decoder-rustflags', default='')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env.setdefault('CARGO_TARGET_DIR', str(root / 'target'))
    target = Path(env['CARGO_TARGET_DIR']).resolve()
    output = target / env.get('CARGO_BUILD_TARGET', '')
    executable = output / ('debug' if args.profile == 'dev' else args.profile)
    executable /= 'irmind-evtx.exe' if os.name == 'nt' else 'irmind-evtx'
    command = ['cargo', 'build', '--manifest-path', 'helpers/evtx/Cargo.toml',
               '--bin', 'irmind-evtx', '--profile', args.profile, '--locked']
    decoder_env = dict(env)
    if args.decoder_rustflags:
        decoder_env.pop('CARGO_ENCODED_RUSTFLAGS', None)
        decoder_env['RUSTFLAGS'] = (env.get('RUSTFLAGS', '') + ' ' + args.decoder_rustflags).strip()
    check_decoder_features(root, decoder_env)
    subprocess.run(command, cwd=root, env=decoder_env, check=True)
    with tempfile.TemporaryDirectory(prefix='evtx-tested-', dir=target) as temporary:
        frozen = Path(temporary) / executable.name
        shutil.copy2(executable, frozen)
        env['IRMIND_EVTX_HELPER_TEST'] = str(frozen)
        command = ['cargo', 'nextest', 'run', '--manifest-path', 'helpers/evtx/Cargo.toml',
                   '--cargo-profile', args.profile, '--locked']
        if args.test_threads:
            command.extend(['--test-threads', args.test_threads])
        try:
            subprocess.run(command, cwd=root, env=env, check=True)
        finally:
            # Cargo's test graph enables broker-only APIs through dev dependencies.
            # Keep the production binary beside the main CLI for its native tests.
            shutil.copy2(frozen, executable)


if __name__ == '__main__':
    main()
