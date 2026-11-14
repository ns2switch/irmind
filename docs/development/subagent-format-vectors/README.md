# Subagent contract vectors

Synthetic codec/signature fragments for the proposed v0.5 contract. They do not
implement subagents and are not complete runnable cases or export archives.
`context.json` explicitly marks the absent authenticated case prefix. Its base
checkpoint and already-admitted source/type inputs are test context, never a
substitute for validating a real signed chain.

- `bundled-types.json` freezes the proposed six type codes and tool/skill sets.
  `type-snapshot.json`, source page/set and two original synthetic JSON files
  fix source membership identities independently of completion order.
- `plan.json` reserves 250,001 of 1,000,000 remaining tokens and exactly 25 of
  100 calls. Tokens therefore require Analyst-signed threshold consent.
  `signed-plan-approval.json` and its preimage use the unchanged audit challenge.
- Negative consent files have mathematically valid Agent signatures, including
  a forged Analyst label; expected-role/key binding must still reject them.
- `threshold-cases.json` tests exactly 25%, one token/call above, zero remaining
  and wide-integer arithmetic. Its u64-maximum row is arithmetic-only and has
  policy_valid=false: it cannot bypass the current 10,000,000-token maximum.
- Preview/start/request/settlement records fix deterministic operation IDs and
  avoid double-counting parent allocations or existing dispatch accounting.
  The signed Allowed record is a local synthetic lookup, not network access.
- Branch proposal → checkpoint → request/Allowed → tool result/terminal →
  final checkpoint → settlement/result is acyclic. Branch signatures use the
  synthetic trusted Agent key; threshold consent uses a distinct Analyst key.
  No provider reasoning, credential, approval capability or real evidence exists.
- `signed-main-suffix.json` contains a contiguous signed suffix linked to the
  synthetic base checkpoint. It is not a CaseCreated prefix, complete case or
  proof that unprovided source/type admissions exist. Full integration tests
  must construct and verify those missing authenticated inputs.
- Chunk descriptors and `v8-branch-tail.hex` fix zero catalog proofs followed by
  two branch chunks. `v8-empty-tail.hex` contains both zero counts. Magic/tails
  are fragments, not archives that a full verifier should accept.

Protocol JSON is exact UTF-8 without a trailing newline; the two original
source-*.json inputs deliberately retain their original LF, included in hashes; hex files include
one final LF outside the decoded bytes. SHA256SUMS covers fixture files;
identities.json lists expected commitments. Negative scenarios describe required
aggregate/context rejection, not an instruction to trust self-declared metadata.

An independent development reference and OpenSSL verified the signatures. Current
case/export goldens are unchanged. Public fixture keys are synthetic and must
never be compiled as production trusted keys. No private key is included.
