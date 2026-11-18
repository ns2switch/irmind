# Proposed source-query format vectors

These are public, synthetic **contract vectors**, not a complete sealed export,
not captured cloud responses and not tests of an implemented executor. See the
[English contract](../source-queries-format-contract.md) and
[Spanish contract](../../es/source-queries-format-contract.md). No production
credential, catalog seed, endpoint or real incident data is used.

`SHA256SUMS` covers every data vector (excluding this README and the checksum
file itself). JSON data files are exact compact UTF-8 without a final newline;
hex files contain lowercase hex and one final newline. Decode hex before hashing
binary protocol identities. The file checksum hashes the *file*, not its decoded
contents. All u64 values in binary protocol fragments are big-endian.

## Canonical method

J sorts object keys recursively by UTF-8 bytes, preserves array order and emits
compact JSON with literal UTF-8 except required JSON string escapes. Only
nonnegative u64 integers, booleans, strings, null, bounded arrays/objects occur.
Duplicate/unknown fields, floats, noncanonical bytes and trailing data are invalid.

For each query-record file, the matching preimage hex file is
`UTF8(domain) || 00 || J(record)`. The ordinary SHA-256 of those decoded bytes
is the record's ID in `identities.json`. Domains/member lists are fixed in
`schemas.json`. A preflight plan digest hashes J of
`{compiled,source,scope,limits}` without the later plan's preflight member; it
cannot recursively hash itself. The domain-separated content ID is distinct
from the existing audit-chain hash.

The existing audit challenge is unchanged:

```
"irmind-audit-v2" || 00 || u64(seq) || put(case_id) || u64(at)
|| put(actor) || put(origin) || put(kind) || put(payload)
|| 00 /* no evidence reference in these examples */ || previous_hash32
|| put(public_key32)
```

`put(bytes) = u64(length) || bytes`. The signature is Ed25519 over the SHA-256
of this challenge, not over the JSON presentation of SignedEntry.
`signed-record-chain.json` has CaseCreated5, budget, plan, Analyst approval,
reservation, intent, terminal observation, result and settlement, in that order.
Agent entries use actor `agent:main`; Analyst entries use `analyst`. Each previous
hash links to the earlier entry. These are record-level signature examples;
source-set/mapping/Parquet/branch/skill proofs needed for a complete case are not
invented or omitted from a claim of whole-case verification.

The keys are deliberately reproducible public test keys: the Ed25519 seeds are
32 repetitions of byte 77 (Analyst) and 88 (Agent). Never trust these
keys in a release. `public-keys.json` supplies their derived public keys. The
existing production catalog root is not used or accepted by these vectors.
`vector-context.json` explicitly marks the fragments as `complete_case=false`.

## Files and what they fix

| Files | Contract detail |
| --- | --- |
| `case-created-v5.json`, `v9-magic.hex`, `v9-empty-tail.hex` | Ordered creation payload with independent source-query allocation; magic and one mandatory zero capture count. |
| `configuration-adoption.json`, `signed-configuration.json`, `configuration-audit-preimage.hex` | Analyst adoption of the exact source/policy via the existing global operation signature. Its hash is referenced by the plan, never a self-reference inside the operation. |
| `budget.json` through `settlement.json`, matching preimages, `identities.json` | New domain identities and acyclic plan/approval/reservation/execution/result/settlement links. Unknown scan estimates require consent; settlement charges observed Athena scans. |
| `athena-submit-request.json` | Exact synthetic parameterized request, adapter-owned identifiers, fixed workgroup and deterministic idempotency key. A real translator must additionally prove its supported timestamp precision and schema. |
| `page-0.json`, `page-1.json`, `page-metadata.json` | Synthetic Athena response envelopes; the first-page column header is not an event. Native rows retain source fields rather than inventing a normalized original. |
| `capture-descriptor.json`, `capture.hex`, `pages-preimage.hex` | Exact two-page captured source; stream-container framing and ordered page commitment. `capture_sha256` hashes decoded capture bytes. |
| `v9-populated-tail.hex` | One mandatory query capture without a detached receipt section, with descriptor/raw frames and counts. This is a tail fragment, not a full V9 export. |
| `azure-analytics.json`, `azure-basic-rejected.json` | Analytics eligibility with missing scan telemetry represented as null; Basic rejected even though its query might succeed. |
| `partial-result-shape.json` | Shape of a local-limit partial result. Deliberately not linked into the positive chain; changing counts without rebuilding capture/proofs is invalid. |
| `recovery-rejected-shape.json` | A priced Athena execution cannot be acknowledged as an expired unknown Analytics execution. |
| `azure-partial-response.json` | HTTP-success-shaped Azure response with PartialError; never a complete result. |
| `malicious-literal.json` | SQL-looking text remains one BigQuery STRING parameter, with no new syntax. |
| `negative-cases.json`, `schemas.json` | Required future rejection cases, exact example member sets and closed enum spellings. Rejection names are proposed application errors. |

Page commitment preimage:

```
"irmind-source-query-pages-v1" || 00 || u64(page_count)
|| each (u64(ordinal) || body_hash32 || u64(body_bytes)
         || u64(event_rows) || u8(completeness))
```

`capture.hex` decodes to magic `IRMIND-QUERY-CAPTURE-V1\0`, put(J(descriptor)),
u64 page count, then put(J(metadata)) and put(raw page body) for each page.
Metadata row counts exclude the Athena column-header row. The acquisition byte
count includes the full container and envelopes. Export chunks split only the
container bytes; they do not change the container or its hash.

Detached remote-verification and subagent-plan vectors are [deferred](deferred/README.md); they are not in the v0.6 checksums or V9 tail.

## Review and future implementation checks

Recalculate SHA256SUMS, all domain IDs, capture/page commitments, configuration
and audit-chain hashes, Ed25519 signatures and export framing independently.
Then apply every negative operation described in `negative-cases.json` with a
future typed verifier. Re-signing a structurally forbidden record does not make
it valid. Check role, allocation, scope, task and terminal-state rules in addition
to signatures. Do not treat these fragments as passing runtime tests today.
