#!/usr/bin/env python3
"""Provider-free planning analysis; never tokenizes as a real provider or runs models."""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def tokens(request):
    return (len(canonical(request)) + 3) // 4


def prefix(request):
    # Tools-first neutral layout reflects a conceptual provider prefix, not HTTP
    # object key order or any vendor's undisclosed tokenizer/hidden instructions.
    return canonical([request['tools'], request['messages']])


def lcp(a, b):
    for i, (left, right) in enumerate(zip(a, b)):
        if left != right:
            return i
    return min(len(a), len(b))


def kind(request):
    system = request['messages'][0]['content']
    if system.startswith('Summarize prior conversation'):
        return 'compaction'
    return 'child' if 'You are an IRMind subagent' in system else 'root'


def actor(request):
    if kind(request) != 'child':
        return 'root'
    first_user = next(m['content'] for m in request['messages'] if m['role'] == 'User')
    return hashlib.sha256(first_user.encode()).hexdigest()


def actor_label(request):
    if kind(request) != 'child': return 'root'
    for m in request['messages']:
        match = re.search(r'Skill ([a-z0-9-]+) ', m['content'])
        if match: return 'child-' + match.group(1)
    return 'child-' + actor(request)[:12]


def components(request):
    result = Counter(tool_catalog=len(canonical(request['tools'])))
    calls = {c['id']: c['name'] for m in request['messages'] for c in m['tool_calls']}
    for m in request['messages']:
        text, role = m['content'], m['role']
        if role == 'System': category = 'system'
        elif 'Available forensic methods (name and description only)' in text: category = 'skill_catalog'
        elif role == 'Tool' and calls.get(m['tool_call_id']) == 'skill_read': category = 'loaded_skill'
        elif role == 'Tool': category = 'tool_results'
        elif 'Previous analyst message:' in text or 'Previous IRMind final answer:' in text: category = 'signed_history'
        elif role == 'Assistant': category = 'assistant_messages'
        else: category = 'other_context_and_input'
        result[category] += len(canonical(m))
    result['framing'] = len(canonical(request)) - sum(result.values())
    return result


def paged_size_oracle(request):
    """Offline byte-budget oracle, NOT a semantic summary or production paging."""
    value = deepcopy(request)
    calls = {c['id']: c['name'] for m in value['messages'] for c in m['tool_calls']}
    for m in value['messages']:
        if m['role'] != 'Tool' or calls.get(m['tool_call_id']) in ('skill_read', 'delegate_task'):
            continue
        data = m['content'].encode()
        if len(data) > 1184:
            m['content'] = data[:1024].decode(errors='ignore') + 'R' * 160
    return value


def frozen_archive_oracle(request):
    """Optimistic reference layout only; constant nonces are UNSAFE to deploy."""
    value = deepcopy(request)
    for m in value['messages']:
        m['content'] = re.sub(r'UNTRUSTED_[0-9a-f-]{36}',
                              'UNTRUSTED_00000000-0000-0000-0000-000000000000', m['content'])
    messages = value['messages']
    fixed, history, other = [], [], []
    for m in messages:
        if m['role'] == 'System' or 'Available forensic methods (name and description only)' in m['content']:
            fixed.append(m)
        elif 'Previous analyst message:' in m['content'] or 'Previous IRMind final answer:' in m['content']:
            history.append(m)
        else:
            other.append(m)
    value['messages'] = fixed + history + other
    return value


def cacheable(raw):
    return raw // 128 * 128 if raw >= 1024 else 0


def compaction_batches(rows):
    groups, group = [], []
    for row in rows:
        if kind(row['request']) == 'compaction':
            group.append(row['request'])
        elif group:
            groups.append(group); group = []
    if group: groups.append(group)
    total = 0
    for group in groups:
        combined = deepcopy(group[0])
        first = combined['messages'][1]['content']
        header, _ = first.split('Older turns:\n',1)
        chunks = [r['messages'][1]['content'].split('Older turns:\n',1)[1].rsplit('\n</UNTRUSTED_',1)[0] for r in group]
        closing = first.rsplit('\n</UNTRUSTED_',1)[1]
        combined['messages'][1]['content'] = header + 'Older turns:\n' + ''.join(chunks) + '\n</UNTRUSTED_' + closing
        total += tokens(combined)
    return len(groups), total


def analyze(rows):
    seen, oracle_seen = defaultdict(list), defaultdict(list)
    systems, catalogs, heads = defaultdict(set), defaultdict(set), defaultdict(set)
    previous = {}
    measured, turns, parts = [], Counter(), Counter()
    compaction_input, child_input, head_reads, head_writes = 0, 0, 0, 0
    for ordinal, row in enumerate(rows, 1):
        request = row['request']
        total = tokens(request)
        assert total == row['simulated_usage']['input_tokens']
        who, what = actor(request), kind(request)
        encoded = prefix(request)
        common = max((lcp(encoded, old) for old in seen[who]), default=0) // 4
        oracle = prefix(frozen_archive_oracle(request))
        future = max((lcp(oracle, old) for old in oracle_seen[who]), default=0) // 4
        system = canonical([m for m in request['messages'] if m['role'] == 'System'])
        catalog = canonical(request['tools'])
        repeated_system = len(system) // 4 if system in systems[who] else 0
        repeated_catalog = len(catalog) // 4 if catalog in catalogs[who] else 0
        old_messages = previous.get(who, [])
        count = 0
        for a, b in zip(request['messages'], old_messages):
            if a != b: break
            if a['role'] != 'System': count += len(canonical(a))
        by_component = components(request)
        parts.update(by_component)
        head = (len(system) + len(catalog)) // 4
        same_head = (system, catalog) in heads[who]
        if head >= 1024:
            if same_head: head_reads += head
            else: head_writes += head
        compaction_input += total if what == 'compaction' else 0
        child_input += total if what == 'child' else 0
        measured.append({'request':ordinal,'turn':row['turn'],'kind':what,
            'output_tokens_sim':row['simulated_usage']['output_tokens'],
            'actor':actor_label(request),
            'input_tokens_sim':total,'input_bytes':len(canonical(request)),
            'components_bytes':dict(by_component),'repeated_system_tokens_sim':repeated_system,
            'repeated_catalog_tokens_sim':repeated_catalog,'exact_replayed_messages_tokens_sim':count//4,
            'raw_common_prefix_tokens_sim':common,'cache_read_ceiling_sim':cacheable(common),
            'frozen_archive_cache_read_ceiling_sim':cacheable(future),
            'one_kib_tool_summary_input_tokens_sim':tokens(paged_size_oracle(request))})
        turns[row['turn']] += total
        seen[who].append(encoded); oracle_seen[who].append(oracle)
        systems[who].add(system); catalogs[who].add(catalog); heads[who].add((system, catalog)); previous[who] = request['messages']
    batch_count, batch_tokens = compaction_batches(rows)
    total = sum(r['input_tokens_sim'] for r in measured)
    paged = sum(r['one_kib_tool_summary_input_tokens_sim'] for r in measured)
    return {'requests':measured,'input_tokens_sim':total,
        'by_turn_tokens_sim':dict(sorted(turns.items())),
        'output_tokens_sim':sum(r['simulated_usage']['output_tokens'] for r in rows), 'components_bytes':dict(parts),
        'model_requests':len(rows),'regular_requests':sum(r['kind']!='compaction' for r in measured),
        'compaction_requests':sum(r['kind']=='compaction' for r in measured),
        'compaction_input_tokens_sim':compaction_input,'compaction_batches':batch_count,
        'single_batch_compaction_input_tokens_sim':batch_tokens,
        'single_batch_input_saving_tokens_sim':compaction_input-batch_tokens,'child_input_tokens_sim':child_input,
        'repeated_system_tokens_sim':sum(r['repeated_system_tokens_sim'] for r in measured),
        'repeated_catalog_tokens_sim':sum(r['repeated_catalog_tokens_sim'] for r in measured),
        'exact_replayed_messages_tokens_sim':sum(r['exact_replayed_messages_tokens_sim'] for r in measured),
        'cache_read_ceiling_sim':sum(r['cache_read_ceiling_sim'] for r in measured),
        'frozen_archive_cache_read_ceiling_sim':sum(r['frozen_archive_cache_read_ceiling_sim'] for r in measured),
        'head_only_cache_reads_sim':head_reads,'head_only_cache_writes_sim':head_writes,
        'head_only_input_cost_units_at_read_0_1_write_1_25':round(total-0.9*head_reads+0.25*head_writes,2),
        'one_kib_summary_input_tokens_sim':paged,
        'one_kib_summary_no_page_demand_saving_pct':round((total-paged)/total*100,2),
        'aux_summary_cost_reduction_pct_at_half_price':round(compaction_input/total*50,2),
        'aux_child_cost_reduction_pct_at_half_price':round(child_input/total*50,2)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--traces',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result={'method':'context-cost-simulation-v1','engine_commit':'41c174bdbcfcf770f23218e0cbcdcec7c1509c8e',
        'provider_calls':0,'provider_cost_usd':0,'tokenizer':'ceil(neutral UTF-8 JSON bytes / 4); NOT provider tokens',
        'prefix_model':'tools-first neutral JSON; perfect retention; 1024-token minimum and 128-token alignment are illustrative, not universal',
        'simulation_only':['one_kib_summary','entropy-free frozen archive','cache cost multipliers','auxiliary model price ratios'],
        'scenarios':{}}
    for path in sorted(args.traces.glob('*.jsonl')):
        rows=[json.loads(line) for line in path.read_text().splitlines()]
        result['scenarios'][path.stem]=analyze(rows)
    assert len(result['scenarios'])==4
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
    for name,data in result['scenarios'].items():
        print(name,{k:v for k,v in data.items() if k not in ('requests','components_bytes')})

if __name__=='__main__': main()
