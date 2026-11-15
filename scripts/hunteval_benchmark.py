#!/usr/bin/env python3
"""Manual, opt-in multi-model HuntEval benchmark; provider secrets stay in IRMind."""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import time
from hunteval_model_eval import PINNED_COMMIT, checked_files, score, verify_checksum

EPISODES = [f'{p}-iam-{i:03}' for p in ('aws', 'azure', 'gcp') for i in range(1, 7)]
FIELDS = ('principal', 'account_id', 'resource', 'source_ip', 'user_agent')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
HASH = re.compile(r'[0-9a-f]{64}')
QUESTION = '''Investigate only the ingested synthetic episode, using local evidence tools.
Do not request remote enrichment. Identify suspicious events and entities, explain uncertainty,
and propose findings with source hashes. Do not confirm findings yourself. Finish with one JSON
object (no Markdown): {"events":["event ID"],"entities":["exact entity value"],
"techniques":["ATT&CK ID"],"findings":[{"claim":"short claim","event_ids":["event ID"],
"evidence_hashes":["SHA-256"]}]}. Include only observations supported by actual tool results.'''


def invoke(binary, home, password, *args, timeout=1200):
    # No provider keys/ambient IRMind overrides are inherited. The binary reads SecretBackend.
    allowed = ('PATH', 'HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'SYSTEMROOT',
               'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'DBUS_SESSION_BUS_ADDRESS',
               'XDG_RUNTIME_DIR', 'LANG', 'LC_ALL', 'TERM')
    env = {k: v for k, v in os.environ.items() if k in allowed}
    result = subprocess.run([str(binary), '--home', str(home), '--passphrase-fd', '0', *args],
                            input=password + '\n', text=True, capture_output=True,
                            timeout=timeout, env=env)
    if result.returncode:
        # Do not publish raw provider errors, local paths or credentials.
        raise ValueError('IRMind operation failed; inspect the disposable case locally')
    return result.stdout.strip()


def models_from(path):
    try:
        import tomllib
    except ModuleNotFoundError:
        raise ValueError('Reading configured model homes requires Python 3.11 or newer') from None
    data = json.loads(path.read_text())
    models = data.get('models', [])
    if not 1 <= len(models) <= 16:
        raise ValueError('Choose 1–16 separately configured model homes')
    labels, homes = set(), set()
    for model in models:
        label = model['label']
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', label) or label in labels:
            raise ValueError('Model labels must be unique public identifiers')
        home = Path(model['home']).expanduser().resolve()
        if str(home) in homes:
            raise ValueError('Use a separate configured home per model')
        config = tomllib.loads((home / 'config.toml').read_text())
        module = model['module']
        values = config.get('modules', {}).get(module, {}).get('values', {})
        field = {'llm-anthropic': 'IRMIND_ANTHROPIC_MODEL', 'llm-deepseek': 'IRMIND_DEEPSEEK_MODEL',
                 'llm-openrouter': 'IRMIND_OPENROUTER_MODEL',
                 'llm-openai-compatible': 'IRMIND_MODEL'}.get(module)
        if field is None or values.get(field) != model['model'] or config.get('llm_module') != module:
            raise ValueError('The public model ID/module must match the explicitly saved configuration')
        model['home'] = home
        labels.add(label); homes.add(str(home))
    return models


def read_verified_case(home, case_id):
    # Called only after the IRMind verifier succeeds. This is a read-only development observer.
    uri = (home / 'irmind.db').as_uri() + '?mode=ro'
    with sqlite3.connect(uri, uri=True) as db:
        rows = db.execute('SELECT kind,payload,evidence FROM audit WHERE case_id=? ORDER BY seq LIMIT 20001', (case_id,)).fetchall()
    if len(rows) > 20000:
        raise ValueError('Evaluation audit exceeds its observer bound')
    usage, calls, tool_text, final, unknown_usage = [], 0, [], None, 0
    hashes = set()
    result_bytes = 0
    retrieval_complete = True
    if sum(len(row[1]) for row in rows) > 64 * 1024 * 1024:
        raise ValueError('Evaluation audit exceeds 64 MiB')
    for kind, payload, evidence in rows:
        if evidence and HASH.fullmatch(evidence):
            hashes.add(evidence)
        if kind == 'ModelUsage':
            usage.append(json.loads(payload))
        elif kind == 'ModelReply':
            unknown_usage += 1
        elif kind in ('Allowed', 'ToolDispatch'):
            calls += 1
        elif kind == 'FinalAnswer':
            final = payload
        elif kind == 'ToolResult' and evidence:
            if not HASH.fullmatch(evidence):
                raise ValueError('Invalid result hash')
            path = home / 'evidence' / evidence
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 5_000_000:
                raise ValueError('Missing or oversized signed tool result')
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != evidence:
                raise ValueError('Signed tool-result hash mismatch')
            result_bytes += len(raw)
            if result_bytes <= 64 * 1024 * 1024:
                tool_text.append(raw.decode('utf-8', errors='replace'))
            else:
                retrieval_complete = False
    costs = [u.get('estimated_cost_microusd') for u in usage]
    return {'usage': usage, 'tool_calls': calls, 'tool_text': '\n'.join(tool_text), 'final': final,
            'known_hashes': hashes, 'retrieval_complete': retrieval_complete, 'usage_complete': len(usage) >= unknown_usage,
            'input_tokens': sum(u['input_tokens'] for u in usage) if usage else None,
            'output_tokens': sum(u['output_tokens'] for u in usage) if usage else None,
            'estimated_cost_microusd': sum(costs) if costs and len(usage) >= unknown_usage and all(x is not None for x in costs) else None}


def final_object(text):
    if text is None or len(text.encode()) > 1_000_000:
        raise ValueError('No bounded final answer')
    obj = json.loads(text)
    for key in ('events', 'entities', 'techniques'):
        values = obj.get(key)
        if not isinstance(values, list) or len(values) > 512 or not all(isinstance(v, str) and len(v) <= 1024 for v in values):
            raise ValueError('Final answer does not meet the evaluation schema')
    findings = obj.get('findings')
    if not isinstance(findings, list) or len(findings) > 128:
        raise ValueError('Final findings do not meet the evaluation schema')
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get('claim'), str):
            raise ValueError('Invalid finding')
        for key in ('event_ids', 'evidence_hashes'):
            if not isinstance(finding.get(key), list) or len(finding[key]) > 64 or not all(isinstance(v, str) and len(v) <= 128 for v in finding[key]):
                raise ValueError('Invalid finding references')
    return obj


def evaluate(observed, source, truth):
    final = final_object(observed['final'])
    events = set(truth['malicious_event_ids']); entities = set(truth['malicious_entity_ids'])
    text = observed['tool_text']
    public_entities = {str(e[f]) for e in source for f in FIELDS if f in e}
    source_hash = observed['source_hash']
    # Search/timeline hits bind zero-based source ordinals; do not score echoed query IDs.
    indices = {int(i) for i in re.findall(re.escape(source_hash) + r'#([0-9]+)', text)}
    retrieved_events = {source[i]['event_id'] for i in indices if 0 <= i < len(source)}
    retrieved_events.update(re.findall(re.escape(source_hash) + r':(evt-[0-9]{4})\b', text))
    retrieved_events.update(re.findall(r'"event_id"\s*:\s*"(evt-[0-9]{4})"', text))
    retrieved_entities = {e for e in public_entities if re.search(r'(?<![\w])' + re.escape(e) + r'(?![\w])', text)}
    findings = final['findings']
    # The ingested original was verified too; its manifest hash is not the audit
    # entry's optional tool-result evidence column. Both are valid citations.
    known_hashes = observed['known_hashes'] | {source_hash}
    supported = sum(bool(f['event_ids']) and set(f['event_ids']) <= events
                    and bool(f['evidence_hashes']) and set(f['evidence_hashes']) <= known_hashes for f in findings)
    return {'events': score(events, set(final['events'])),
            'entities': score(entities, set(final['entities'])),
            'techniques': score(set(truth['expected_attack_techniques']), set(final['techniques'])),
            'retrieved_events': score(events, retrieved_events),
            'retrieved_entities': score(entities, retrieved_entities),
            'false_positive_event_ids': sorted(set(final['events']) - events),
            'event_supported_finding_proxy': {'supported': supported, 'reported': len(findings)},
            'human_correct_findings': None, 'human_false_positive_findings': None}


def write_report(output, report):
    (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    lines = ['# HuntEval model evaluation', '', 'Exact-ID metrics, not a semantic forensic verdict. Human finding adjudication is pending.', '',
             '| Model | Episode | Status | Event P/R | Entity P/R | Tool calls | Input/output tokens | Cost (microUSD) |',
             '| --- | --- | --- | --- | --- | --- | --- | --- |']
    def metric(item, key):
        m = item.get('metrics', {}).get(key)
        return '-' if not m else f"{m['matched']}/{m['reported']} · {m['matched']}/{m['expected']}"
    for row in report['runs']:
        lines.append(f"| {row['label']} | {row['episode']} | {row['status']} | {metric(row, 'events')} | {metric(row, 'entities')} | {row.get('tool_calls', '-')} | {row.get('input_tokens')} / {row.get('output_tokens')} | {row.get('estimated_cost_microusd')} |")
    (output / 'report.md').write_text('\n'.join(lines) + '\n')
    digests = ''.join(hashlib.sha256((output / n).read_bytes()).hexdigest() + '  ' + n + '\n' for n in ('report.json', 'report.md'))
    (output / 'SHA256SUMS').write_text(digests)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hunteval-root', type=Path, required=True)
    p.add_argument('--models', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--execute', action='store_true', help='Explicitly authorize billable configured model calls')
    a = p.parse_args(); binary = a.binary.resolve(); models = models_from(a.models)
    sources = {episode: checked_files(a.hunteval_root, episode) for episode in EPISODES}
    if not a.execute:
        print(f'Plan: {len(models)} models × 18 episodes. No model called; no private answer opened. Cost unknown. Add --execute after reviewing saved provider/data-egress settings.')
        return
    a.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    report = {'format': 'irmind-hunteval-model-eval-v1', 'date_utc': datetime.now(timezone.utc).isoformat(),
              'corpus_commit': PINNED_COMMIT, 'irmind_version': subprocess.check_output([str(binary), '--version'], text=True).strip(),
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'runs': [],
              'method': 'One root-agent CLI turn per episode; no automatic approvals or analyst confirmations. Retrieval counts signed raw tool-result coverage, before model-facing truncation/guard. Exact-ID scores and event-linked finding proxies require separate human adjudication.'}
    observations = []
    # Finish every model run before opening any private answer file.
    for model in models:
        password = getpass.getpass(f"File-keystore passphrase for {model['label']} (blank only for OS-only backends): ")
        for episode in EPISODES:
            row = {k: model.get(k, 'not reported') for k in ('label', 'module', 'model', 'revision')}
            row.update(episode=episode, provider=episode.split('-')[0], status='execution_failed')
            started = time.monotonic(); source, hidden = sources[episode]
            try:
                case = invoke(binary, model['home'], password, 'case', 'new', 'HuntEval ' + episode, '--scope', 'local').splitlines()[-1]
                if not UUID.fullmatch(case):
                    raise ValueError('No case ID')
                row['case_id'] = case
                invoke(binary, model['home'], password, 'ingest', case, str(source.resolve()))
                invoke(binary, model['home'], password, '--llm-module', model['module'], 'ask', case, QUESTION)
                invoke(binary, model['home'], password, 'verify', case, '--source-root', str(source.parent.resolve()))
                observed = read_verified_case(model['home'], case)
                observed['source_hash'] = hashlib.sha256(source.read_bytes()).hexdigest()
                row.update({k: observed[k] for k in ('tool_calls', 'input_tokens', 'output_tokens', 'estimated_cost_microusd', 'usage_complete', 'retrieval_complete')})
                row['status'] = 'awaiting_score'
                observations.append((row, observed, source, hidden))
            except (ValueError, OSError, subprocess.SubprocessError, sqlite3.Error):
                row['error'] = 'Operation failed; review the disposable case locally. No raw provider diagnostic is included.'
            row['elapsed_seconds'] = round(time.monotonic() - started, 3)
            report['runs'].append(row)
            write_report(a.output, report)
        password = ''
    for row, observed, source, hidden in observations:
        try:
            verify_checksum(a.hunteval_root, hidden.relative_to(a.hunteval_root))
            truth = json.loads(hidden.read_text())
            row['metrics'] = evaluate(observed, json.loads(source.read_text()), truth)
            row['status'] = 'scored_pending_human_review'
        except (ValueError, KeyError, TypeError):
            row['status'] = 'invalid_evaluation_answer'
    report['status_counts'] = dict(Counter(row['status'] for row in report['runs']))
    write_report(a.output, report)
    print('Wrote report.json, report.md and SHA256SUMS. Review failures, raw-retrieval limitations and finding adjudications before publishing.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        raise SystemExit('Benchmark stopped. Check the explicit model homes, saved settings, pinned corpus and retained cases/report; raw provider or credential diagnostics are not published.') from None
