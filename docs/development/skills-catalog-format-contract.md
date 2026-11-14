# Signed catalog index, admission and case/export contract

Proposal implementing the trust boundaries of the [approved catalog architecture](skills-catalog-install.md).
Only documentation and synthetic vectors are supplied. No catalog repository,
production key, secret, dependency, application port or runtime is created here.
Review this contract before implementation and before creating `irmind-skills`.
[Español](../es/skills-catalog-format-contract.md)

## Review scope and existing boundaries

Use existing Ed25519 strict verification, SHA-256, skill compiler/store, Analyst
signer and global operation envelope. The index publisher is not an Actor or a
case signing key. Keep signed-entry/operation challenges, Parquet V3, seal V2
bytes and the unversioned `export_case` method unchanged. Sigstore/provenance
remain external release checks, not an IRMind dependency or installation step.

New concrete review points are: index/package/proof V1; installation operation V2
and skill snapshot V2 for all origins; and the shared export V8 tail described
below. Current code/goldens and V7 remain unchanged until approved implementation.
The implementation target has one current V2 installation/snapshot format, not
historical V1 readers. Unsupported old skill payloads are disabled with a warning;
the unchanged signed global envelope remains authenticatable for other operations
and startup is not blocked. Re-admission is explicit, not an implicit migration. Pre-1.0 users retain the producing executable or re-ingest
originals; opening a case never migrates it. Current-format/creator markers must
reject an unsupported case before processing records. SkillLoadV1 wire bytes and
its range/guard checks remain unchanged; its snapshot digest resolves the new
current SkillSnapshotV2. The new record kinds use the single typed audit conversion.

The shared producing case marker is `CaseCreated.version = 4`, with existing
ordered fields `version,title,severity,scope,budget` and mandatory initial budget.
No other CaseCreated field or audit challenge changes. Reject version 3/unknown
markers before case work with creating-version/re-ingestion guidance; do not
invent an exact creator patch from the marker. `case-created-v4.json` fixes these
bytes. This marker bump is part of the contract proposal, not current code.

## Catalog key identity and trust

Compiled trust contains 0–8 raw Ed25519 public keys, 32 bytes each. Zero keys means
catalog unavailable with a reason. `key_id = lowerhex(SHA256(public_key32))`;
keys are unique and ordered by this ID. Reject invalid/weak keys at construction.
Never accept a public key from an index, package, command or installed file. A
signature is exactly 64 bytes; use the existing strict Ed25519 verifier, including
canonical scalar/point checks. There is no algorithm negotiation or fallback.

For recording the verification decision only, the keyset digest is SHA-256 of
`irmind-catalog-keyset-v1\0 || u64(key_count) || public_key32...` in key-ID order.
It is not a downloaded trust root. Adding a compiled key does not invalidate a
previous receipt while its actual signing key remains accepted. Removing a key
makes new admission and active catalog use unavailable for its indexes. Global
Analyst-signed history can still authenticate; startup disables the affected
skill and explains the unavailable publisher trust instead of corrupting the
whole history or relabeling the origin. Deactivation stays possible. Standard
complete case/export verification rejects unavailable catalog trust, while any
signature diagnostics must clearly distinguish Analyst authentication alone.
The producing executable may retain an older policy; there is no automatic
revocation feed, clock or root refresh. Releasing updated keys is required.

Production private key provisioning belongs only to the protected catalog release
environment after contract approval. No private key material is put in source, build
arguments, logs or release assets. Golden public keys are synthetic test keys and
must never enter production trusted-key lists. No production credential is added
by these vectors. The future protected publishing secret holds a 32-byte seed encoded as 64
lowercase hex bytes, read only in memory by the tag publishing job and checked
against the expected public key ID before signing. Production secret access is
restricted to approved protected tags; branch dispatch rehearsals use synthetic
keys, never that secret. Public-key bootstrap and secret provisioning require
maintainer setup after review. External Sigstore identities stay as specified
in the architecture.

## Canonical signed index

Runtime assets are `index.json` and `index.ed25519` (raw signature64). Index bytes
are UTF-8 canonical JSON: exact key order below, no insignificant whitespace or
trailing newline, integer numbers only, explicit null where permitted. Reject
unknown/duplicate fields and noncanonical bytes; validate bounds before exposing
entries. The original bytes, not a normalized variant, are signed.

Signature preimage:
`UTF8("irmind-skill-catalog-index-v1") || 00 || u64be(len(index_bytes)) || index_bytes`.
Ed25519 signs that complete preimage, not an unlabelled digest. `index_sha256` is
ordinary SHA-256 of index bytes. The detached signature is not JSON/base64 and
cannot carry replacement trust material.

Index field order: `format_version,catalog,key_id,release_tag,release_commit,
release_sequence,entries`.

- format_version: 1; catalog: exactly `ns2switch/irmind-skills`.
- key_id: 64 lowercase hex derived from an accepted compiled key.
- release_tag: bounded canonical `vMAJOR.MINOR.PATCH` with optional bounded SemVer
  prerelease, no build metadata, path separators, control escapes or leading-zero
  numeric components; at most 64 ASCII bytes. Resolve under the fixed repository.
- release_commit: exactly 40 lowercase hex; a signed publisher claim, independently
  checkable with external provenance. IRMind does not claim to verify GitHub
  provenance when it checks this Ed25519 signature.
- release_sequence: positive u64. Freeze the chosen tag, signed commit and index
  digest for the entire operation. Entries: 0–1,024, unique ASCII-sorted skill names.

Each entry has this exact key order:
`name,version,package_sha256,asset,asset_sha256,asset_bytes,
minimum_irmind_version,target_schema,interpreter,sources,mappings,coverage`.
Name/version use existing skill constructors. `asset` is a single ASCII basename
(max 128 bytes, letters/digits/`._-`, no leading dot, `..`, device names or aliases).
SHA fields are lowercase64; bytes is a checked positive u64 ≤1 MiB. Min version is
canonical IRMind SemVer; it does not override current interpreter/schema support.
Target schema/interpreter equal supported compiler IDs. Source/mapping module IDs
are bounded unique sorted arrays, at most 32 IDs/64 bytes each. Required source
set matches the package metadata; mapping requirements are explicit publisher
coverage claims checked against compiled modules and actual case profiles.
Coverage is `{status,description}`: complete/partial/unavailable, at most 512 UTF-8
bytes, guarded before display. Signed coverage is not evidence of source coverage.

Index maximum: 1 MiB, depth 8, 1,024 entries, 100,000 aggregate scalar/container
values and no arbitrary URL fields. Validate header/key ID only to locate a
compiled key; trust no entry, preview or asset path until signature verification.
Use bounded errors without index/package contents.

## Package and complete proof

A transport asset is data-only JSON, e.g. `synthetic-triage-1.skill.json`, with
ordered fields `{format_version:1,files:[{path,contents},...]}`. Files are sorted
by existing validated resource path, main SKILL.md plus at most 16 resources.
No archive extractor or new dependency is needed. Asset bytes ≤1 MiB; decoded
original text ≤128 KiB, existing per-file/frontmatter/path limits unchanged.
Reject unknown/duplicate fields, aliases, extra files and unsupported resources.

Verify asset size/SHA before compiling. Construct the same `SkillPackage`,
recompute its existing `irmind-skill-package-v1` commitment and compare it with
the index. Compiler name/version/schema/interpreter and required sources must
agree. The transport checksum and package commitment are different. Full method
content passes ContentGuard; blocked content cannot be admitted despite a valid
publisher signature. No downloaded content executes and none enters system.

Proof identity is SHA-256 of
`irmind-skill-catalog-proof-v1\0 || u64(index_len) || index_bytes || signature64`.
Retain the whole signed index; a selected entry or its hash alone cannot verify
Ed25519. Entry identity is `Id(irmind-skill-catalog-entry-v1, entry_JSON)` where
`Id(D,J) = SHA256(UTF8(D) || 00 || canonical_JSON(J))`.

A private immutable `CatalogProofStore` keeps proof bytes by identity, never by
untrusted path. Limits: 256 proofs/64 MiB globally, 256 proofs/16 MiB per case.
Existing skill snapshot/history/package caps remain separate and unchanged.
Full stores reject further admission visibly; no silent eviction of referenced
proofs. Staging uses current private filesystem/ACL helpers, space preflight,
sync, cancellation and cleanup. Missing proof disables use/recovery; restoring
it is an explicit local import or analyst-approved fetch, never background I/O.

## Ports and explicit transaction

These signatures are proposed, not added to current application traits:

```rust
pub trait SkillCatalogSource: Send + Sync {
    fn index<'a>(&'a self, request: &'a AnalystCatalogRequest,
        cancel: &'a CancellationToken) -> PortFuture<'a, CatalogIndexBytes>;
    fn package<'a>(&'a self, release: &'a VerifiedCatalogRelease,
        asset: &'a CatalogAsset, cancel: &'a CancellationToken)
        -> PortFuture<'a, BoundedPackageBytes>;
}

pub trait CatalogIndexVerifier: Send + Sync {
    fn verify(&self, bytes: &CatalogIndexBytes, expected: &FrozenCatalogRelease)
        -> Result<VerifiedCatalogIndex, AppError>;
}

pub trait CatalogProofStore: Send + Sync {
    fn publish(&self, proof: &VerifiedCatalogIndex,
        cancel: &CancellationToken) -> Result<CatalogProofId, AppError>;
    fn read(&self, id: &CatalogProofId,
        cancel: &CancellationToken) -> Result<CatalogIndexBytes, AppError>;
}
```

Request/release/asset verified capabilities have private constructors and no
model deserializer. A request is minted only by the explicit analyst installation
flow; offline input calls the same verifier directly and invokes no source port.
The verifier is pure (no network, I/O, clock, secrets or admission); its infra
implementation reuses current Ed25519 code. Store reads are untrusted bytes until
reverified against current compiled keys. No second package compiler is introduced.

Per operation: at most 4 MiB downloaded including metadata, two asset bodies
(index/package), one signature64, at most three redirects/request and 30 seconds
per request. Validate HTTPS destinations and redirect hops under the fixed
GitHub release asset flow, never forwarding credentials. No arbitrary hosts,
case data, environment cloud credentials or stored GitHub token are required.
Only explicit analyst action opens network, including /skills update. No startup,
model, preview cancellation or offline import performs a request.

Compile/guard the candidate, show source/key/tag/hash/tools/content/differences,
check core/reserved-name collisions, then recheck under the global operation lock.
Persist the verified immutable proof, sign the complete approved install snapshot,
then atomically publish the active package using current recovery semantics.
Failed signature authorizes nothing; failed publish after signing leaves visible
recovery, never an active loose file. Recheck proof/key/compiler/core names on
recovery and activation. The model cannot install/update/activate or choose origin.

Remember first accepted tag/commit/sequence/index bindings in signed admission
history. Same tag or sequence with different bytes is equivocation and rejected,
not silently overwritten. A lower sequence or older package needs explicit diff
and separate downgrade consent; highest accepted sequence never decreases, even
when disabling a skill. A first offline signed index has no freshness guarantee.

## Origin catalog and current V2 methodology records

`SkillInstallationV2` uses operation label `skill-installation-v2:` plus lowercase
hex canonical JSON, fields in order:
`format_version,name,skill_version,package_sha256,origin,active,
previous_operation,catalog,files`. Version 2; global operation origin is organization/analyst/catalog. Any bundled
origin or core name is rejected; bundled snapshots use the compiled inventory. Non-catalog has catalog null;
catalog has the receipt below. Existing per-skill links, full original files,
Analyst-only global signature and 768 KiB encoded payload cap remain unchanged.

Receipt order:
`catalog,release_tag,release_commit,release_sequence,key_id,index_sha256,
proof_sha256,entry_sha256,asset,asset_sha256,asset_bytes,verification_policy,
keyset_sha256,offline,downgrade_confirmed`.
Verification policy equals `compiled-ed25519-v1`; booleans reflect the actual
analyst flow. `Id(irmind-skill-catalog-receipt-v1, receipt)` is its identity.
All signed identity/asset fields must equal the selected verified entry/index.
No self-declared origin or manual cosign check substitutes for that proof.

`SkillSnapshotV2` uses event label/domain `skill-snapshot-v2` /
`irmind-skill-snapshot-v2`, and fields:
`format_version,name,skill_version,target_schema,interpreter,package_sha256,
origin,release_inventory_sha256,admission_operation_sha256,
catalog_receipt_sha256,files`.
Version 2; Actor Analyst, evidence null as today. Bundled requires inventory and
null admission/catalog. Analyst/organization require matching V2 admission and
null inventory/catalog. Catalog requires matching V2 admission and receipt,
null inventory, and complete valid index proof. Snapshot/package equality,
core-name checks and cumulative case package limits remain mandatory.

The receipt is methodology provenance, never an EvidenceHash. Copy the referenced
proof into the private case proof set before exposing the first method load.
In-flight/historical snapshots stay immutable. SkillLoadV1 keeps exact current
fields/encoding and points at the new current snapshot identity; Agent signatures,
byte ranges, guard hashes and shared per-turn limits are unchanged.

## Shared export V8 and verifier

The proposed V8 header/magic and existing sections match the companion subagent
contract. The current skill-admission section contains exactly the referenced
Analyst SignedOperation envelopes carrying SkillInstallationV2 payloads. After it, always write a u64 catalog-proof count,
then each proof's descriptor frame and declared chunk frames, followed by the
u64 subagent branch-chunk count and its frames. Unused sections have count zero;
no community-type admission section exists in v0.5. Thus either feature can be
implemented without guessing tail layout. A nonzero unsupported extension fails.

Sort catalog descriptors by proof ID. Descriptor order:
`proof_sha256,index_sha256,key_id,signature,index_bytes,chunks`.
Signature is lowercase hex64 bytes; index length ≤1 MiB. Each chunk is
`{proof_sha256,ordinal,bytes_hex}` with at most 256 KiB decoded bytes. Exactly
ceil(index_bytes/256 KiB) chunks (1–4), ordinal order, no gaps/aliases. Frame lengths
use existing big-endian u64 and the unchanged 1 MiB serialized-frame ceiling;
chunk hex plus overhead stays below it. Stream/recompute complete index/proof
hashes with the aggregate 16 MiB case proof cap. No unrelated catalog index is
included; deduplicate exactly the references from case snapshots/admissions.

Verify expected Analyst/Agent bindings, global admission signature, full package
commitment/metadata, snapshot/load links, index canonical bytes/signature/key ID,
selected entry/asset binding, receipt digest and exact proof set. Reject missing,
extra, duplicated, reordered or modified chunks, retired keys and trailing bytes.
No network, certificate root refresh, external verifier, model or downloaded code
runs offline. Guard all displayed metadata. Seal V2 commits the audit/snapshot
references as before; it does not make the catalog publisher's claim evidence.

## Vectors and implementation gate

[catalog-format-vectors](catalog-format-vectors/README.md) includes a real
Ed25519-valid synthetic index/preimage/signature, the existing known package
commitment, signed installation using the current global challenge, new snapshot,
unchanged load shape, proof frames and V8 fragments. SHA256SUMS covers fixtures.
Unknown/removed keys, duplicate fields, modified indexes/assets, wrong frozen tags,
missing full proof, core-name conflicts and downgrade/equivocation are required
negative tests. Public fixture keys are not a production keyset.

These are encoding fragments, not a complete executable case/export. Full-case
implementation tests must install/update/restart, progressively load, verify,
seal/export independently, disable unavailable trust, preserve recovery semantics
and prove no network for offline/startup/model paths. Current golden vectors are
not changed and no historical reader is added. Repository creation and protected
key/environment provisioning follow approval of this contract, not this PR.
