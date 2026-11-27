#!/usr/bin/env python3
"""Reproduce the draft v0.8 contract vectors with Python and OpenSSL."""
import json
from pathlib import Path
import runpy
import struct
from tempfile import TemporaryDirectory

DOCS = Path(__file__).resolve().parents[1]
V11 = runpy.run_path(str(DOCS / 'case-7-export-v11-vectors/generate.py'))
CASE = V11['CASE']
TASK = '00000000-0000-4000-8000-000000000081'
HASH = lambda digit: digit * 64
RPC = b'IRMIND-RPC-V1\0'


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def sample(domain, value):
    body = canonical(value)
    preimage = domain.encode() + b'\0' + body
    return {
        'body': V11['vector'](body),
        'identity_preimage': V11['vector'](preimage),
        'payload': domain + ':' + body.hex(),
    }


def rpc_frame(message):
    body = canonical(message)
    return struct.pack('>I', len(body)) + body


def rpc_message(request_id, method, params):
    return dict(id=request_id, method=method, params=params)


def mcp(request_id, method, params):
    return canonical(dict(jsonrpc='2.0', id=request_id, method=method, params=params)) + b'\n'


def operation(analyst, payload):
    challenge = (
        b'irmind-operation-v1\0' + V11['audit_text']('global')
        + V11['u64'](1) + V11['u64'](V11['AT'])
        + V11['audit_text']('analyst') + V11['audit_text'](payload)
        + V11['ZERO'] + V11['frame'](analyst.key)
    )
    digest = V11['sha'](challenge)
    return dict(case_id='global', seq=1, at=V11['AT'], actor='analyst',
                operation=payload, prev=list(V11['ZERO']), hash=list(digest),
                sig=list(analyst.sign(digest)), public_key=list(analyst.key))


def build_vectors(analyst):
    hook = dict(version=1, id=TASK, program=HASH('1'), runtime=HASH('2'),
                configuration=HASH('3'), mode=0, tools=['timeline'], policy=HASH('4'),
                max_input_bytes=16384, max_output_bytes=4096, timeout_ms=1000)
    hook_object = sample('irmind-hook-admission-v1', hook)
    signed_hook = operation(analyst, hook_object['payload'])
    hook_bytes = V11['json_bytes'](signed_hook)
    proof = b'\0' + bytes(signed_hook['hash']) + V11['frame'](hook_bytes)
    mcp_admission = dict(
        version=1, id=TASK, program=HASH('1'), runtime=HASH('2'), protocol='2025-11-25',
        policy=HASH('4'),
        tools=[dict(name='inspect_row', descriptor=HASH('5'), projection=HASH('6'), risk=0)],
    )
    mcp_object = sample('irmind-mcp-admission-v1', mcp_admission)
    signed_mcp = operation(analyst, mcp_object['payload'])
    mcp_bytes = V11['json_bytes'](signed_mcp)
    mcp_proof = b'\1' + bytes(signed_mcp['hash']) + V11['frame'](mcp_bytes)

    root = analyst.entry('CaseCreated', V11['case_payload'](8))
    header, sections = analyst.sealed_empty(root)
    header['version'] = 12
    empty_v12 = V11['magic'](12) + V11['frame'](V11['json_bytes'](header)) + sections + V11['u64'](0)

    plan = json.loads((DOCS / 'subagent-format-vectors/plan.json').read_text())
    plan.update(format_version=2, query_resources=[])
    task_id = plan['tasks'][0]['task_id']
    child_binding = dict(version=1, case_id=plan['case_id'], plan=HASH('7'), task_id=task_id,
                         query_plan=HASH('8'), checkpoint=HASH('9'), branch_proposal=HASH('a'),
                         source_id='synthetic-query', source_set=HASH('b'), budget_checkpoint=HASH('c'))
    approval_binding = dict(case_id=CASE, session=TASK, proposal=HASH('a'), nonce=HASH('c'))

    v = V11['vector']
    hello = RPC + rpc_frame(rpc_message(1, 'hello', dict(version=1, client='Synthetic GUI')))
    return {
        'case_export': {
            'case_8_signed_entry': v(V11['json_bytes'](root)),
            'empty_v12': v(empty_v12),
            'reject_missing_extension_count': v(empty_v12[:-8]),
            'reject_unreferenced_hook_admission': v(empty_v12[:-8] + V11['u64'](1) + proof),
            'reject_unreferenced_mcp_admission': v(empty_v12[:-8] + V11['u64'](1) + mcp_proof),
        },
        'hooks': {
            'admission': hook_object,
            'signed_operation': v(hook_bytes),
            'invocation_receipt_sample': sample('irmind-hook-invocation-v1', dict(
                version=1, case_id=CASE, invocation=TASK, admission=bytes(signed_hook['hash']).hex(),
                phase=0, tool_action=HASH('5'), outcome=2, input=HASH('6'), result=HASH('7'),
            )),
        },
        'mcp': {
            'admission': mcp_object,
            'signed_operation': v(mcp_bytes),
            'initialize': v(mcp(1, 'initialize', dict(protocolVersion='2025-11-25',
                                                     capabilities={}, clientInfo=dict(name='IRMind', version='0.8')))),
            'list_tools': v(mcp(2, 'tools/list', {})),
            'bounded_case_row_call': v(mcp(3, 'tools/call', dict(
                name='inspect_row', arguments=dict(source=HASH('d'), row=1),
            ))),
            'reject_reverse_request': v(mcp(3, 'sampling/createMessage', {})),
        },
        'engine_api': {
            'hello': v(hello),
            'reject_oversized_length': v(RPC + struct.pack('>I', 65537)),
            'reject_client_approve_method': v(hello + rpc_frame(rpc_message(2, 'approve', dict(case_id=CASE)))),
            'approval_presentation_binding': sample('irmind-local-approval-v1', approval_binding),
        },
        'child_queries': {
            'plan_without_remote_share': sample('irmind-subagent-plan-v2', plan),
            'child_binding_codec_only': sample('irmind-child-source-query-v1', child_binding),
            'whole_plan_threshold': [
                {'reserved': held, 'remaining': left,
                 'verdict': 'reject' if held > left else 'confirm' if held * 4 > left else 'normal'}
                for held, left in ((0, 0), (1, 0), (25, 100), (26, 100), (50, 100))
            ],
        },
    }


if __name__ == '__main__':
    with TemporaryDirectory(prefix='irmind-v08-draft-vectors-') as directory:
        analyst = V11['SyntheticAnalyst'](Path(directory))
        print(json.dumps(build_vectors(analyst), ensure_ascii=False, indent=2))
