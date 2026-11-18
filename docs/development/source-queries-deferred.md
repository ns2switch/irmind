# Source-query extensions after v0.6

[Español](../es/source-queries-deferred.md)

**Future design only; excluded from v0.6.** No implementation, current export section or permission is authorized here.

## Query-enabled subagents

To bind remote source assignments and complete-plan reservations, propose
`SubagentPlanV2` (new audit label/domain `irmind-subagent-plan-v2`): retain every
V1 member and add required `query_resources`; `format_version` becomes 2.
The V2 payload uses J and its new domain; the V1 byte codec is not reinterpreted. It is an array sorted
by existing task ID, each entry `{task_id,sources,scope,scan_bytes,retained_rows,
retained_bytes}`; sources are sorted unique configured source IDs (at most 32 per
task), never substituted for local evidence hashes. Task IDs retain their current
calculation and do not hash this parent plan. Existing plan approval, reservation
and checkpoint schemas reference the new plan identity through their existing
hash fields; their byte codecs do not change. Thus consent covers the *entire*
query allocation before any child starts. A child with no query_resources entry
cannot run remote queries. This V2 plan and the expanded whole-plan threshold
are explicit review points, not silent changes to a published V1 format.

A source query consumes ordinary tool-call budget as well as scan/retention
resources. A child reserves its portion from the same case pool. For the proposed
extension of the whole-plan 25% rule, compare complete-plan scan, retained-row
and retained-byte reservations against remaining respective allocations; crossing
any applicable dimension needs Analyst-signed plan consent. Zero remaining with
positive demand is rejection; Analytics with no scan demand does not invent a
zero-over-zero fraction. Existing tokens/calls/bytes thresholds and the
confirm-all-plans preference still apply. No child approves its own plan/query.


## Exact-version remote verification

Detached `RemoteOriginalVerificationV1` has required canonical fields
`version,case_id,admission,seal,source_manifest,object,method,observed_at,outcome,observed,
sha256,transfer_bytes,reason,nonce`. `object` binds the exact immutable version;
`method` is metadata or sha256. Outcomes are identity_match, digest_match,
changed, missing, denied, unavailable, cancelled. Metadata never produces
digest_match. Opaque ETag equality is not a SHA-256 check; an ambiguous 403 is
never missing. Hash mismatch is changed even if ETag/size are equal.

Envelope `{payload,public_key,signature}` uses hex canonical J(payload), Analyst
public-key hex and Ed25519 signature hex. Signing challenge is
`"irmind-remote-original-verification-v1" || 00 || u64(len(J)) || J`.
Receipt ID is SHA-256 of that challenge. Verify the key against the expected case
Analyst/seal identity, not merely the self-declared public key. The nonce is a
fresh 32-byte receipt nonce, unrelated to UNTRUSTED delimiters. No expiry claim
or claim that a later receipt updates an earlier one is inferred.

Before a remote check, the Analyst signs a global
`remote-original-verification-admission-v1:` operation with hex(J({version,
case_id,seal,source_manifest,object,method,transfer_bytes,policy,at,nonce})).
The receipt's required `admission` is that operation's audit hash. The exact
method/target/maximum and policy snapshot are fixed before network work; no
receipt can retroactively authorize a GET. Include the signed admission in V9's
operation-proof section. An admission for metadata does not authorize sha256.

The shared broker maintains detached holds/usage under the same case/seal lock,
starting from the *remaining* transfer/call allocation authenticated at sealing.
Outstanding checks and earlier detached usage are subtracted across processes.
This bookkeeping is outside the sealed chain; it does not grant another copy of
the case budget. Unknown transfers retain/charge their admitted bound until
reconciled, never release it just on timeout. Exhaustion blocks new checks;
no implicit post-seal increase or model-token debt exception is introduced.

A sealed chain is not appended/reopened. Store the receipt independently with
the frozen seal hash; including one requires a *new* export file, never rewriting
an existing signed export. Missing receipts are not proof of failure, and a
valid receipt only attests observations at its stated time. Catalogue and scan
credentials are never exported. A new original byte GET consumes the
remaining transfer allowance through that detached admitted session; the signed
receipt is its usage record. The effective organization ceiling still applies.


## Historical proposal vectors

[Deferred vectors](source-query-format-vectors/deferred/README.md) preserve the earlier proposal for future review. They are not part of the v0.6 format or test inventory.
