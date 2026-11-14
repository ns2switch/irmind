# Case-scoped catalog proof storage

This supplements the [catalog format contract](skills-catalog-format-contract.md)
with an explicit case boundary for the proof store. Index, receipt, installation,
snapshot and export encodings stay exactly as defined there.
[Español](../es/catalog-case-proof-storage.md)

## Two storage scopes

An installation retains its verified catalog index in the global proof store.
Before its first snapshot or load in a case, IRMind verifies that proof against
the currently compiled catalog keys and copies it into that case's private proof
store. The case copy has the same content identity. It does not become evidence,
an admission signature or an additional publisher trust root.

Case verification and export read the case copy explicitly. They do not recover
a missing case copy from global storage or the network. Reinstalling or updating
a skill globally cannot replace a historical case proof.

## Additive application boundary

Keep `CatalogProofStore::publish` and `read` for global installation proofs. Add
two methods with an explicit validated `CaseId`:

```rust
fn publish_for_case(
    &self,
    case: &CaseId,
    proof: &VerifiedCatalogIndex,
    cancel: &CancellationToken,
) -> Result<CatalogProofId, AppError>;

fn read_for_case(
    &self,
    case: &CaseId,
    id: &CatalogProofId,
    cancel: &CancellationToken,
) -> Result<CatalogIndexBytes, AppError>;
```

Both default implementations return an explicit unavailable error. An adapter
implementing only the global methods can install a package, but cannot enable it
in a case until case-scoped proof storage is available. There is no implicit
selection of a current case, mutable ambient case context or fallback to the
global methods.

The application supplies the active case ID after its normal case verification
and locking. Model arguments cannot provide another case or a filesystem path.
The verifier remains pure and does not acquire filesystem responsibilities.

## Publication and verification

- Global limits remain 256 proofs and 64 MiB; each case independently permits
  256 proofs and 16 MiB. Count a content identity once in each scope.
- Use hash-derived filenames beneath the existing private case data directory,
  with the current Unix permissions and Windows user ACL helpers. Check free
  space before staging; check cancellation; sync before publication.
- Publish the immutable case proof before appending its first `SkillSnapshotV2`.
  A failed publication exposes no load. A failed subsequent audit append may
  leave an unreferenced private proof, but never an admitted method.
- Read bounded bytes, check the proof identity and reverify the complete index
  against current compiled keys. A stored filename is not verification.
- A missing or changed case proof prevents catalog skill use and complete case
  verification/export with an actionable error. It never triggers a download.
- Export V8 includes exactly the referenced case proofs, using the approved
  descriptor and chunk frames. Its independent verifier needs neither store nor
  network. Bundled and non-catalog installed skills still need no catalog proof.

No new dependency, credential, signed field, event label, signature challenge,
case marker or frame limit is introduced. The public catalog remains optional;
an empty compiled publisher-key list continues to report it as unavailable.

## Contract tests

1. Publish one proof globally and into case A; reading it from case B fails.
2. Remove or change A's copy while the global proof remains intact: A's load,
   complete verification and export fail without global or network recovery.
3. Change the global installation: A's immutable proof and snapshot stay fixed.
4. Exercise duplicate publication, both scope limits, cancellation, space
   preflight and failures before and after publication, with private cleanup.
5. Reject a removed publisher key in global admission, case use and independent
   V8 verification. Authentication of the Analyst operation alone remains distinct.
6. Round-trip the approved nonempty V8 proof vectors offline; reject missing,
   extra, reordered, truncated and altered frames without changing golden bytes.
