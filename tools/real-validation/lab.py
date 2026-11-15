#!/usr/bin/env python3
"""Explicit, local-only validation lab; no production dependency or provider key."""
import argparse
import base64
from datetime import datetime, timezone, timedelta
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / 'target/real-validation'
INDEX = 'irmind-validation-events'
IMAGES = {
    'amd64': 'sha256:5a0702b4b97e89bb4d4a9b27b1dcbf983e7a4147954a42228b9efc5287a467e2',
    'arm64': 'sha256:32bce97c9af202e98708897d0445ac72275ded8b7887a2064d7605f07c8ebd2d'}


def private_write(path, data):
    with path.open('xb') as f:
        os.chmod(path, 0o600)
        f.write(data)


def prepare():
    LAB.mkdir(parents=True, exist_ok=True, mode=0o700)
    arch = subprocess.check_output(['docker', 'version', '--format', '{{.Server.Arch}}'], text=True).strip()
    if arch not in IMAGES:
        raise ValueError('This lab pins only Docker amd64 and arm64 images')
    password = getpass.getpass('Choose a disposable Elasticsearch admin password (16+ chars): ')
    if len(password) < 16 or '\n' in password or '\r' in password:
        raise ValueError('Use at least 16 characters without line breaks')
    private_write(LAB / 'elastic-password.txt', password.encode())
    private_write(LAB / 'compose.env', f'ELASTIC_IMAGE=docker.elastic.co/elasticsearch/elasticsearch:9.5.6@{IMAGES[arch]}\n'.encode())
    print('Lab files prepared under target/real-validation. No IRMind configuration was changed.')


def fetch():
    LAB.mkdir(parents=True, exist_ok=True, mode=0o700)
    manifest = json.loads(Path(__file__).with_name('datasets.json').read_text())
    for item in manifest:
        target = LAB / item['name']
        if target.exists():
            data = target.read_bytes()
        else:
            url = item['url']
            if urlsplit(url).scheme != 'https' or urlsplit(url).hostname not in ('raw.githubusercontent.com', 'media.githubusercontent.com'):
                raise ValueError('Unapproved dataset origin')
            with urllib.request.urlopen(url, timeout=45) as response:
                data = response.read(item['size'] + 1)
            if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('Dataset checksum/size mismatch; no data published')
            private_write(target, data)
        if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Existing dataset differs from its pinned checksum')
        print(item['name'], 'verified', item['sha256'])


def records(offset):
    # Public lab exports are data. Preserve the exact source and its hash in each projection.
    aws = LAB / 'splunk-aws.json'
    text = aws.read_text()
    try:
        parsed = json.loads(text)
        cloud = parsed.get('Records', [parsed]) if isinstance(parsed, dict) else parsed
    except json.JSONDecodeError:
        cloud = [json.loads(line) for line in text.splitlines() if line.strip()]
    for event in cloud:
        outcome = {'Success': 'success', 'Failure': 'failure'}.get((event.get('responseElements') or {}).get('ConsoleLogin'), 'unknown')
        identity = event.get('userIdentity', {})
        yield {'@timestamp': event['eventTime'], 'ecs': {'version': '9.5.0'},
               'event': {'category': ['authentication'], 'type': ['start'], 'action': event['eventName'],
                         'outcome': outcome, 'original': json.dumps(event, sort_keys=True)},
               'user': {'name': identity.get('userName', '')},
               'source': {'ip': event['sourceIPAddress']},
               'cloud': {'provider': 'aws', 'account': {'id': identity.get('accountId', '')}},
               'labels': {'validation_account': 'lab-evaluation'},
               'irmind_validation': {'source_sha256': hashlib.sha256(aws.read_bytes()).hexdigest(), 'projection': 'lab-ecs-v1'}}
    if not re.fullmatch(r'[+-](?:0[0-9]|1[0-4]):[0-5][0-9]', offset or ''):
        raise ValueError('Confirm --windows-utc-offset explicitly, such as +00:00')
    sign = -1 if offset.startswith('-') else 1
    tz = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6])))
    windows = LAB / 'splunk-windows.log'
    for block in re.split(r'(?m)(?=^\d{2}/\d{2}/\d{4} )', windows.read_text()):
        if not block.strip():
            continue
        lines = block.splitlines()
        fields = dict(line.split('=', 1) for line in lines[1:] if '=' in line)
        stamp = datetime.strptime(lines[0].strip(), '%m/%d/%Y %I:%M:%S %p').replace(tzinfo=tz)
        code = fields.get('EventCode', '')
        yield {'@timestamp': stamp.astimezone(timezone.utc).isoformat(), 'ecs': {'version': '9.5.0'},
               'event': {'code': code, 'action': 'WindowsEvent' + code, 'outcome': 'unknown',
                         'original': block}, 'host': {'name': fields.get('ComputerName', '')},
               'labels': {'validation_account': 'lab-evaluation'},
               'irmind_validation': {'source_sha256': hashlib.sha256(windows.read_bytes()).hexdigest(),
                                     'confirmed_utc_offset': offset, 'projection': 'lab-ecs-v1'}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError('Lab endpoint redirects are not allowed')


def client():
    password = getpass.getpass('Disposable Elasticsearch admin password: ')
    context = ssl.create_default_context(cafile=str(LAB / 'ca.crt'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
    token = base64.b64encode(('elastic:' + password).encode()).decode()
    def request(path, body, method='POST', content='application/json'):
        req = urllib.request.Request('https://localhost:9200' + path, data=body,
                                     method=method, headers={'Authorization': 'Basic ' + token, 'Content-Type': content})
        with opener.open(req, timeout=45) as response:
            result = response.read(2_000_001)
        if len(result) > 2_000_000:
            raise ValueError('Lab response exceeds 2 MB')
        return json.loads(result)
    return request


def load(offset):
    fetch()
    events = list(records(offset))
    if not 1 <= len(events) <= 500:
        raise ValueError('Lab subset must contain 1–500 events')
    request = client()
    request('/' + INDEX, json.dumps({'mappings': {'properties': {'@timestamp': {'type': 'date'},
        'event': {'properties': {'action': {'type': 'keyword'}, 'category': {'type': 'keyword'}, 'outcome': {'type': 'keyword'}}},
        'user': {'properties': {'name': {'type': 'keyword'}}}, 'host': {'properties': {'name': {'type': 'keyword'}}},
        'labels': {'properties': {'validation_account': {'type': 'keyword'}}}}}}).encode(), method='PUT')
    body = ''.join(json.dumps({'create': {'_index': INDEX, '_id': str(i)}}) + '\n' + json.dumps(event) + '\n' for i, event in enumerate(events)).encode()
    result = request('/_bulk?refresh=wait_for', body, content='application/x-ndjson')
    if result.get('errors'):
        raise ValueError('One or more lab documents were rejected; inspect locally')
    print('Loaded', len(events), 'lab events. Original timestamps and projection provenance retained.')


def create_key(output):
    if output is None or output.resolve().is_relative_to(ROOT):
        raise ValueError("Choose --key-output outside every repository")
    if output.exists() or not output.parent.is_dir():
        raise ValueError('Choose a new private output file in an existing directory')
    result = client()('/_security/api_key', json.dumps({'name': 'irmind-read-only-validation',
        'expiration': '4h', 'role_descriptors': {'irmind_validation_reader': {'cluster': [],
        'indices': [{'names': [INDEX], 'privileges': ['read', 'view_index_metadata']}]}}}).encode())
    private_write(output, result['encoded'].encode())
    print('Read-only key saved to the private external file. Enter it in the IRMind keystore, then delete that working copy.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'fetch', 'load', 'create-key'])
    parser.add_argument('--windows-utc-offset')
    parser.add_argument('--key-output', type=Path)
    args = parser.parse_args()
    try:
        {'prepare': prepare, 'fetch': fetch, 'load': lambda: load(args.windows_utc_offset), 'create-key': lambda: create_key(args.key_output)}[args.command]()
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit('Lab step failed. Check the local TLS setup, credentials, confirmed timezone and pinned input files; no secret diagnostics are printed.') from None
