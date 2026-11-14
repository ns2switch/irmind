# Verified original-record reads

Status: approved additive contract. Custody formats and query limits are unchanged.

## Purpose and current behavior

The existing `raw_records` tool takes a case-local signed source hash and a zero-based record index. Its current adapter reads the `text` column of an authenticated event artifact; this is a mapped projection, rather than a general original-record reader. Cluster-scoped mappings intentionally omit whole Kubernetes `requestObject` and `responseObject` bodies from that projection.

That distinction matters to the Kubernetes methods. An API operation and its outcome do not reveal a role binding's `roleRef` and `subjects`, or a pod's requested security settings. The scripted case tests must check those source facts before proposing the corresponding conclusions. A source pointer or successful API outcome alone is insufficient.

Preserve the small projection for search. Add verified, explicitly authorized access to an individual original record instead of flattening all request/response bodies into the index. This is not the decoded-record cache or remapping facility deferred in [the source-mapping design](source-mapping-design.md).

## Application port

Add an optional local `SourceEvidenceReader` port. Preserve `EnginePorts::new`; initialize the optional reader to `None` and attach it through an additive builder. Propagate it to local engine handles. Existing engines without this port keep projection reads, clearly labeled as projections. A method requiring original fields reports missing coverage rather than treating a projection as the original.

The port signatures are:

```rust
trait SourceEvidenceReader: Send + Sync {
    fn authorize_local_root(
        &self,
        case_id: &CaseId,
        root: &Path,
        sources: &[EvidenceHash],
    ) -> Result<(), AppError>;

    fn read_verified_record(
        &self,
        case_id: &CaseId,
        source: &EvidenceHash,
        record_index: u64,
        cancel: &CancellationToken,
    ) -> Result<Tainted<SourceRecordV1>, AppError>;
}
```

Use the existing typed case/hash identities and source-record bounds. The caller supplies no arbitrary field path, decoder name, filename, URL, credentials or expression. Extend the existing tool with a closed optional `view` selector: `raw_records(hash, index, view="indexed" | "original")`. The default remains `indexed`, preserving current query cost and behavior. Skills needing original fields explicitly request `original`. The new port does not add a model tool or grant remote access. An original request with no reader is unavailable, never an implicit projection fallback.

`authorize_local_root` is an analyst-origin application action, never a callable model tool. After a successful signed local ingestion, register the root selected in that ingestion and the hashes actually committed. Opening an existing case does not implicitly authorize its manifest paths. For a later session, the analyst can explicitly select the originals directory for that case before original-record reads. This selection is local acquisition state, not evidence custody, and grants no network authority.

The adapter stores at most 16 local root capabilities and at most 16,384 hash associations for the current case, in memory only. Replacing the current case clears them. An empty hash batch selects the current case without authorizing or opening any root; opening or creating a case uses that lifecycle call. If capacity is reached, refuse additional authorization with a clear message; do not broaden an existing capability or evict it silently. A copied original already held privately by the case needs no external root. Neither a source URI nor a relative path in a manifest is an authority to open a file.

## Authentication and bounded decoding

1. Verify the case chain, active artifact inventory and the relevant manifest/input-set links using the existing verification path. Require the pointer to refer to an event present in the signed active graph. Authenticate each Parquet read as today.
2. Resolve a copied original under the case's private `originals/<sha256>` location, or resolve the signed relative source path under an explicitly authorized root. Reuse the no-follow regular-file opener. Never fetch an object-storage URI or derive an external path from model input.
3. Require the exact signed decoder version to be present in the frozen catalog. Replay the signed temporal and cluster contexts. Do not select a new detector, run a newly selected mapping, install definitions, download code or infer missing acquisition context.
4. Decode with the existing limits and collect only the requested bounded `SourceRecordV1`. Recompute the complete ordered decoded-record commitment, accepted/rejected counts and formats, and compare them with `SourceRecordSetV1`. Validate the source bytes against the signed size and SHA-256 before releasing any result. Random-access decoders must satisfy both byte authentication and decoded-set reproduction; a hash checked before a separate decode alone is insufficient.
5. Use the existing record identity from the signed input set. Do not confuse accepted-record indices with original member ordinals when rejected records precede the requested record. Preserve the original provenance, offsets and member annotations.
6. Keep the existing raw pointer ceiling (index below 100,000), the 10-second local-query deadline and the existing 2,000-character tool excerpt. The deadline and cancellation must advance independently of a blocked callback. A truncated excerpt is explicitly marked and cannot establish facts outside that excerpt. Decoders retain their stricter file/record/depth/field limits and EVTX containment.
7. Return only after authentication succeeds. Missing originals, missing capabilities, unavailable decoder versions, incomplete decoding, count/commitment mismatch, timeouts and cancellation produce an explicit unavailable/error result. Never silently label an indexed projection as a verified original. Existing search and timeline tools remain available when the original cannot be read.

The signed input set already supplies the expected final record count. Prefix the replay commitment with that count, stream the canonical record tuples and verify the actual final count. This avoids a new tuple spool or decoded cache. Do not store decoded records, copy the complete original or use the system temporary directory. A later cached reader is a separate design decision.

## Guard, policy and UI

The returned value stays `Tainted<SourceRecordV1>` with its source provenance. Serialize the bounded excerpt only at the existing safe-output boundary, apply `ContentGuard`, and wrap model-visible content with the turn's UNTRUSTED nonce. Neither a decoded field nor a skill enters the system role. Existing read policy, organization ceiling, case scope, approvals and budgets apply unchanged.

Show whether a result is an indexed projection or a verified original excerpt. If original evidence is unavailable, explain how the analyst can select its local root. The model cannot supply that root. Source bodies may include confidential material; retain the existing guard and excerpt limits, and never include them in diagnostics or credentials/configuration storage.

## Formats and dependencies

No new production dependency, source-record format, artifact schema, signed event, export version, seal encoding or parser version is required. Original bytes and complete decoded input commitments already exist in the signed pipeline. Authentication is not a substitute for mapping reproduction: this read reproduces only the decoder input set, and does not claim to run `verify_graph` or reproduce mapped artifacts.

No persistent decoded cache or implicit cloud read is introduced. Remote originals remain unavailable unless the analyst explicitly obtains them through the existing authorized acquisition path or retained a private case copy.

## Required tests

- Both Kubernetes skill episodes retrieve the original audit IDs and required binding/pod facts before the scripted model proposes a finding. Ground truth stays outside the model, tools and evidence.
- A projection missing the required facts cannot satisfy the episode. Missing original roots report incomplete coverage without inventing a conclusion.
- Requesting a hash from another case, a nonexistent event, a traversal/symlink path, an unregistered root or an object URI never opens an unauthorized source.
- Byte alteration, rejected-record count changes, decoded-set commitment mismatch and wrong frozen acquisition context prevent release of any original text.
- Rejected records before the requested record preserve the exact accepted index and member ordinal. Exercise native, EKS, AKS and GKE envelopes.
- Cancellation, a blocked callback, deadline expiry and an oversized source return no partial original and create no spool. Test the authorization bounds and case-switch cleanup.
- Evidence containing instructions and secret-like material remains guarded and UNTRUSTED; the obedient false model cannot use a source body to authorize a path, change scope or call undeclared tools.
- Existing projection/query golden bytes, graph reconstruction, seals and export V7 remain unchanged. Exercise Linux, macOS, Windows and `preserve_order`.

Measure release latency and peak memory separately from ingestion. Replaying a very large original can exceed the existing query deadline; report that limitation rather than increasing the deadline. The two required synthetic episodes must complete within the current limit.
