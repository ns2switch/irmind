# Installable Sigma rule packages

[Español](../es/development/sigma-package-installation-contract.md)

**Status:** proposed for review. Both catalog options use the same package,
installation and case formats below. The choice of publisher and trust root,
the signed records and the ZIP reader need approval before implementation.

## Publisher and signing key

| Option | Advantages | Costs and trust boundary |
| --- | --- | --- |
| Use `irmind-skills` and its existing Ed25519 key | One repository, contribution process, protected release environment, key to provision and rotation procedure. Reuse the release infrastructure and keep discovery in one place. | The same private key can approve both catalogs. A key compromise or compromised publish workflow can affect both. Key rotation and release availability are coupled. The repository needs separate asset names, CI paths and monotonically increasing sequences for each catalog. |
| Separate Sigma catalog and maintainer-generated Ed25519 key | Independent trust, release cadence, license review, rollback history and revocation. Revoking a key for one catalog leaves the other trust root available. | An additional repository and protected environment, separate workflows, initial key provisioning and an IRMind release to compile that public key. Maintaining both takes more time. |

Recommend the separate catalog and key because rules and forensic methods
have separate contribution and licensing workflows. The maintainer chooses
the repository and provisions its key if this option is approved.
In either option, compile the publisher identity, purpose and a bounded list
of up to eight accepted Ed25519 public keys into IRMind. Verify index signatures
strictly with the existing verifier. The signature domain is specific to Sigma
even with a shared key. A signed skill index does not satisfy it. Revocation
and rotation use an IRMind release. Historical installed packs keep their
original publisher evidence. Full verification reports unavailable publisher
trust if the verifying build no longer authorizes that key.

## Package and catalog

A community or local package is a single data file with domain
`irmind-sigma-package-v1\0`, followed by `u64be(metadata_length)`, canonical UTF-8
metadata JSON, `u64be(manifest_length)`, the existing canonical
`SigmaPackManifestV1` body, and the exact raw YAML bytes in manifest path
order. Manifest sizes delimit the YAML slices. Validate paths, identities,
license, exact byte lengths, hashes and EOF, and reproduce the manifest with
the existing admission semantics. Never extract a path to disk. The content
is data-only, with no scripts, rule modifiers beyond the current compiler,
nested archives or executables. Bounds remain 4,096 rules, 64 KiB per rule,
64 MiB total rule bytes, path depth 16 and the existing manifest object cap.
Metadata is at most 8 KiB, with this key order:

```text
format_version,name,version,license,attribution
```

Use version 1, an ASCII lower-case slug of up to 64 bytes, canonical SemVer
without build metadata, and a declared SPDX license expression or the
fixed identifier `DRL-1.1`. Check the actual license and distribution
rights in catalog review. Attribution is bounded plain text (4 KiB max)
shown as untrusted data. Bounded transport storage and total limits are
checked before starting. No format negotiation, archive autodetection,
or package-supplied trust roots.

The Sigma index uses canonical JSON and exact ordered fields
`format_version,catalog,key_id,release_tag,release_commit,release_sequence,entries`.
Use the field syntax and bounds of the [skills index](skills-catalog-format-contract.md)
where shared, including a 1 MiB index limit and at most 1,024 entries.
Use version 1, the compiled catalog repository, a positive sequence, a
frozen tag and commit, and unique entries sorted by name. Unknown/duplicate
keys and noncanonical encodings are rejected. The release ships
`sigma-index.json` and an exact raw 64-byte `sigma-index.ed25519`.
Sign `UTF8("irmind-sigma-catalog-index-v1") || 00 || u64be(len(json)) || json`.
The key ID is lowercase SHA-256 of the raw public key. Freeze the index
and tag before package retrieval. No content is trusted before verification.

Each index entry uses the exact field order
`name,version,minimum_irmind_version,license,manifest_sha256,source,coverage`.
The ordered `source` variants are:

- `kind,asset,bytes,sha256` with kind `catalog-asset`. Use a single safe
  basename in that catalog release. The authenticated package metadata must
  match the index. `manifest_sha256` is the commitment of the canonical
  rule manifest and is distinct from the transport hash.
- `kind,url,bytes,sha256,attribution,selection_asset,selection_bytes`
  with kind `sigmahq-archive`. The URL
  is an exact official release asset under
  `https://github.com/SigmaHQ/sigma/releases/download/<tag>/<asset>`.
  Require an explicit version and bounded assets. Hash the original ZIP
  before parsing any entries. Record the official URL, SHA-256,
  SigmaHQ attribution and DRL 1.1. The catalog carries the reference
  and a reviewed selection. The safe `selection_asset` basename locates
  an exact `SigmaPackManifestV1` body in the signed catalog release,
  bounded by the manifest limit and `selection_bytes`. Its SHA-256
  must equal `manifest_sha256`. It lists explicit paths, hashes and sizes
  of the YAML members to use. Reject a missing or changed selected rule.
  Unselected members supply no rules. Show the number of selected and
  excluded rules and the published selection criteria in the preview.
  This lets a release include a reviewed subset when its archive also
  contains rules outside the engine's supported subset. The catalog
  publishes no SigmaHQ rule bytes. Treat GitHub blob redirects as in the existing release asset client.
  Check each hop and send no credentials or case data.
  [Pinned release](https://github.com/SigmaHQ/sigma/releases/tag/r2026-07-01) ·
  [License](https://github.com/SigmaHQ/sigma/blob/552f3fee420ef232a8e5790c4fae591847e32347/LICENSE).

`coverage` is a bounded publisher claim, represented as a sorted unique array
of at most 128 triples `[product,service,category]` with individually nullable
elements and the current Sigma taxonomy syntax. Actual case coverage comes
from the local compiler, the active source inventory and the reviewed field
table. A selected source that can supply a class does not guarantee any
matching events in the case or time range.

Exact ZIP handling for official references is a distinct review point.
Cap the archive at 64 MiB of transport and 64 MiB of total decoded
content and cap directory entries at 8,192. Apply the existing 4,096-rule
and 64 KiB per selected rule limits. Bound memory and time, and cancel
between entries and during streaming decode. Validate both
directory and local records, reject encryption, path aliases, unsafe entry
types, duplicate paths, unsupported encodings and entry methods. Allow only
stored or deflated entries, reject any discrepancy in size or CRC, and stream
validated members into bounded buffers. The raw hash and manifest pin apply
to the whole candidate. No fetching an alternative archive after failure.
The index and community bundle need no new dependency. A ZIP dependency
would require separate approval after comparing a maintained bounded reader
with the existing compression stack and available interfaces.

## Analyst flow and version state

- `/sigma list` lists locally known packages, versions, origin and active
  status. `/sigma info <name>` is read-only and local. In a case it shows
  rules with all, some or no eligible classes, omissions and their reasons,
  and the checkpoint to which coverage refers. Outside a case it shows
  publisher coverage separately from compiler compatibility.
- `/sigma install catalog:<name>` opens the network solely on explicit
  analyst action. Display source, key, version, hashes, provenance, license,
  coverage and rule counts in a guarded preview before the signed approval.
  Offline catalog installation supplies the same index, signature and exact
  bundle or official archive from local files. Plain local bundle install
  has origin `local` and uses the same compilation, preview and signed
  review flow with no publisher claim.
- `/sigma update <name>` shows added, removed and changed rule IDs/hashes,
  license, coverage and origin before confirmation. Origin and trust
  identity are pinned at first install. Changing origins needs a separate
  explicit replacement decision and preview. No fallback to another source.
- `/sigma remove <name>` signs deactivation. The highest accepted catalog
  sequence and package version survive removal. An installed pack cannot be
  activated at a lower version. Reuse of a sequence, tag or package version
  with different committed bytes is rejected. Reinstalling the exact same
  approved version and bytes is permitted. There is no first-use freshness
  guarantee for an offline index. Recheck monotonic state and candidate
  hashes under the global operation lock. Stage before signing and activate
  only once the signed operation is durable. Recover interrupted activation
  from verified staged bytes, with no background fetch.

Model, skill and subagent input cannot install, update, remove, confirm
an admission, change publisher or invoke catalog networking. Skills may
recommend pack names or a minimum version as advisory content. Installing
does not authorize execution. Every run keeps the existing attended
analyst path, policy, case scope, time window and work budget and requires
its own signed case admission. An installed pack is never selected by
name alone after the preview. Freeze version and hashes and recheck the
case checkpoint and active installation before signing. Preserve direct
local directory imports as a distinct existing origin.

## Signed records and export

Propose these additive records and proof object kinds for review. Keep the
current challenge, role keys, seal encoding, case marker 6, export V10
section framing and historical receipts. Use the existing unsigned
big-endian 64-bit counts and sizes, raw SHA-256 digests and
`u32be(length) || UTF8` text convention for binary records. Optional
digests use a single byte (`0` absent, `1` followed by a digest).
All new objects are content-addressed by SHA-256 of their full bodies.

| Record or object | Proposed canonical fields |
| --- | --- |
| Global `SigmaPackageInstallationV1` | Domain `irmind-sigma-package-installation-v1\0`, then name, version, active byte, previous installation operation digest (optional only for the first install), metadata digest, manifest digest, asset digest, license, origin byte (0 local, 1 signed catalog asset, 2 signed SigmaHQ reference), publisher-proof digest (absent exactly for local) |
| Case `SigmaCaseRunAdmissionV1` | Domain `irmind-sigma-case-run-admission-v1\0`, then existing `CaseCheckpointV1` for the pre-admission case head, installation operation digest (optional for an existing direct directory import), existing global Sigma pack admission digest, manifest digest, active artifact inventory digest, selected-sources digest, start and end UTC microseconds (signed i64 big-endian), field-table digest, compiled-rule digest, evaluator text, reserved work u64 |
| Sigma export proof kind 6 | The exact canonical Analyst-signed global installation operation, with the existing global operation encoding. SHA-256 of the body is its object identity. Authenticate the operation signature independently and match its signed operation hash to the case admission |
| Sigma export proof kind 7 | Domain `irmind-sigma-catalog-proof-v1\0`, u64 index length, exact signed JSON bytes and raw 64-byte signature. Require the full index so verification can reconstruct the signature preimage |
| Sigma export proof kind 8 | Canonical package metadata JSON as defined above. For an official reference, derive it from the signed entry, using its attribution. Match the committed digest in the installation record |

The installation operation is global and signed by Analyst. The case
record is signed by Analyst with analyst origin and no evidence attached.
The existing run links to the case admission through its checkpoint.
Commit the case admission, run receipt and findings atomically. Require
the pre-admission checkpoint, time, sources, inventory, field table,
compiled rules, evaluator and work to match. The new evaluator introduced
by the source-class contract can run on its own before packages ship.
Once this gate ships, use evaluator
`irmind-sigma-evaluator-v3-case-admission-v1` so that removing an admission can never be interpreted as a
historical ungated execution. The result proof encoding proposed in the
[class compilation contract](https://github.com/ns2switch/irmind/pull/431)
can be reused. Existing case validation must reject a sealed case or stale
checkpoint before append. Removing or updating a package cannot rewrite
a case admission, result, or a retained proof.

Keep the exact rules and manifest in the existing Sigma proof kinds.
Use the existing tail and descriptor framing for the additional kinds.
Export only proofs referenced by historically authenticated case admissions
and their runs. The recipient verifies the signed case, authenticated
installation operation, matching catalog proof or local origin,
metadata, manifest and rule bytes without network access and without
looking up the current catalog. An export proves what executed and what
publisher metadata was signed. It neither carries nor attests to
reconstructing the original transport archive. For an official reference,
the catalog record and its license are retained unmodified. The catalog's
no-redistribution rule still applies to catalog releases, and an analyst
who shares an export remains responsible for its rule licenses and any
evidence it contains.

A complete verifier checks the immutable provenance at the signed case
checkpoint. Local activation checks use current signed global history.
Proofs required by a case keep their own private copy even if the global
cache is deactivated, pruned or unavailable. Enforce existing per-rule
and proof section limits (128 MiB combined Sigma proof material per
export), verify exact proof-set unions and preserve the 1 MiB audit
frame cap. Missing, swapped, duplicated or unreferenced proofs fail
closed. Do not rely on the latest index or an installed pack as a
substitute.

## Validation and review gate

Catalog PR CI runs the same admission and compiler as the released
IRMind against the reviewed tables, reports coverage by source class,
checks declared license and provenance, and fails on invalid package
bytes or metadata. Official references are pinned and checked in CI
against the exact published archive without retaining its bytes in the
catalog. Community packs are checked with synthetic fixtures. Fork
checks have read-only permissions and no release secrets. The release
job for an approved protected tag alone uses the chosen signing key.

The [independent draft vectors](sigma-package-vectors/wire.json) fix
package, index and signature preimage, local installation and deactivation,
and case admission bytes. The index uses a synthetic publisher name.
Finalize the signed catalog proof and V10 proof-union vectors with the
publisher choice before implementing the records. Negative fixtures cover invalid signatures and signature
purpose, package swap, modified byte, rollback after removal, publishing
equivocation, stale case plans, missing admission, unexpected proof
and interrupted commits. Fuzz and test archive and canonical decoders
with bounded synthetic inputs before shipping them. The concrete key
and publisher choice, format identifiers and vectors, the ZIP path and
any new production dependency or port are separate approval points.
