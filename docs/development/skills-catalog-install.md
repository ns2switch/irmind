# Explicit installation from the community skill catalog

Approved architecture; catalog downloads and in-application index verification are
not implemented by this document. The [community repository](https://github.com/ns2switch/irmind-skills)
is separate from IRMind. Bundled skills remain the release's core and are not
copied into that repository. Current local installation, package compilation,
signed admission and case receipts remain the baseline described in the
[installation](skills-installation-contract.md) and
[case/export](skills-case-format-contract.md) contracts.

[Español](../es/skills-catalog-install.md)

## User flow and network boundary

`/skills install catalog:<name>` is an explicit analyst action. It opens a
preview of the catalog repository, selected release tag and outbound requests
before any network access. Confirming that action permits bounded downloads
from that release only. No startup, skill discovery, model tool or background
update fetches an index, checks for updates or installs content.

Freeze the selected tag, release identity and index digest for the operation.
Download the exact index and detached Ed25519 signature, verify them with the
compiled catalog keys, then download the selected hash-bound package. Show the exact source, name, version, package commitment,
minimum IRMind version, required parsers/mappings, coverage, tools and content.
Screen and safely render all metadata and file contents. Verification of the
publisher never makes methodology a trusted instruction.

Reject a name already compiled into the core, before admission and again under
the global operation lock. A new version of a bundled skill arrives through an
IRMind release; catalog installation cannot shadow it. Also reject collisions
with reserved commands and existing installation identities as today.

`/skills update` is explicit and first chooses installed catalog skills to
inspect. Show old/new release identities, versions, hashes, files, text, tools,
coverage and minimum-version changes. No automatic acceptance, wildcard bulk
consent or silent downgrade. Apply each approved replacement with the existing
signed admission transaction; leave the previous approved version intact on
cancellation, failed verification, failed signature or publication error.
Disabling a skill still uses the existing signed operation.

The current offline directory-install flow stays available. An analyst can
fetch and verify a release on another machine, inspect its contents and install
the local package. Such an installation is not labeled cryptographically
catalog-verified unless IRMind independently verifies the accompanying proof.
No offline action silently falls back to a network fetch.

## Catalog structure and compiler equivalence

One directory per community skill contains `SKILL.md`, optional allowed resource
directories and a separate synthetic episode with private expected answers.
The episode/answers are evaluation inputs, not files in the installed package.
No executable scripts or downloaded plugins are accepted. Use the project dual
license (MIT OR Apache-2.0), an English/Spanish contribution guide and a template.

CI uses the latest published non-draft IRMind release, including a pre-release
while the project has no stable release. Resolve it once per run, record the
exact tag and commit, and build the development validator against that source.
Use `SkillPackageStore::read_candidate` and `SkillCompiler::compile` from that
version, not a second approximate frontmatter validator. Run the package's
synthetic episode through the same engine, guard, signed installation and
scripted model paths; confirm findings as the analyst, verify, seal and export.
Expected answers are opened only by the evaluator after the final answer. The
model, tools, case evidence and exported package never receive them.

A contribution is accepted only if that release accepts its package and the
scripted episode succeeds. Test the template too, but never publish it as a
catalog entry. Require a package-specific coverage declaration, source fixtures,
contract assertions and an ATT&CK citation where relevant. A core-name inventory
from that exact IRMind release prevents duplication. CI is read-only on pull
requests; publishing is a separate tag workflow. Release actions are pinned by
commit; verification tools are prebuilt, version-pinned and checksum-verified.

## Index and release identity

The versioned, deterministic index is UTF-8 JSON with unknown/duplicate fields
rejected. Its signed header binds the catalog repository, frozen release tag and
commit, a sequence number and the catalog key ID. Entries are sorted by skill
name and include:

| Field | Meaning |
| --- | --- |
| `name`, `version` | Exact compiler-validated metadata identity. |
| `package_sha256` | IRMind's canonical package commitment, recomputed by its compiler. |
| `asset`, `asset_sha256`, `asset_bytes` | Exact release asset basename, ordinary SHA-256 and bounded byte count. |
| `minimum_irmind_version` | Explicit compatible producing/interpreter version policy, checked before admission. |
| `target_schema`, `interpreter` | Required schema and exact supported interpreter identity. |
| `sources`, `mappings` | Required format/module and mapping identities/versions. |
| `coverage` | Full, partial or unavailable, with bounded explanation. |

The archive checksum and logical package commitment are distinct and both are
checked. A package cannot point to arbitrary URLs: release assets are resolved
under `ns2switch/irmind-skills` at the frozen tag. Reject redirects outside the
allowlisted GitHub asset flow and revalidate each destination; never forward
credentials. Requests use no provider, system cloud credentials or case data.
The catalog is public and does not require a stored GitHub credential.

Initial proposed limits: 1 MiB index, 1,024 entries, 1 MiB transport package,
128 KiB of original package text, 16 resources, 32 KiB per resource, 8 KiB frontmatter,
64 bytes for the detached Ed25519 signature and 30 seconds per request.
The concrete contract fixes signature preimages and bounded proof retention. Package limits
must be imported from the current compiler, never enlarged by the index. Bound
total operation bytes, redirects and proof counts as well. Store downloads in a
private data-directory staging area, with disk preflight, cancellation and
cleanup after errors. Refuse absolute/traversal names, symlinks, hard links,
duplicate paths, case aliases and unsupported files before publication.

Catalog publisher verification and external release verification are distinct,
as specified below. Neither grants a package permissions.

## Ed25519 index trust and rotation

The catalog signs its canonical index with a dedicated Ed25519 catalog key.
IRMind verifies the exact versioned signature preimage using its existing
Ed25519 code and an allowlist of at most eight compiled public keys. The index
contains a key ID, never a trusted replacement public key. The concrete contract
fixes the ID derivation, field order, domain separation, counts and golden bytes.
An unknown, removed or mismatched key ID, malformed signature, changed index,
wrong repository/tag or failed asset/logical package hash rejects the operation.
There is no checksum-only fallback and no verifier subprocess or new dependency.

No clock, certificate chain, network trust-root fetch or TUF refresh is required.
The signed index plus signature and selected package are sufficient offline.
A local directory with no valid catalog proof remains an honest analyst/organization
installation; it cannot label itself catalog-verified. Model-facing metadata and
methodology remain UNTRUSTED after publisher and Analyst signatures.

Add or remove a public key only through a reviewed IRMind release. A compromised
key is removed in the next release; indexes signed by it are no longer accepted
by that executable. Older executables retain their compiled policy, so revocation
requires updating IRMind, not an automatic trust-root download. Revalidate active
catalog admissions against the current compiled keys; unavailable trust disables
use with a clear explanation rather than silently relabeling the origin. A valid
old signature is not a freshness guarantee: freeze/show the chosen release and
never silently downgrade an already admitted package.

The real private signing key exists only as a secret of the protected release
environment in `ns2switch/irmind-skills`, available only to the publishing job.
It is absent from Git, artifacts, package contents, command arguments and logs.
Public PR validation never receives it; no `pull_request_target` signing or
unreviewed PR artifact promotion. Maintainer-approved tag deployments produce
the index from the reviewed commit. Provisioning that environment/key follows
contract approval and requires explicit maintainer setup; no key is provisioned
by this document. Golden keys are synthetic test identities, never production keys.

## External release verification

Catalog releases additionally keep keyless Sigstore signatures/bundles for their
index, checksum list and package assets, and GitHub build provenance. These are
for external verification and the catalog README documents both cosign and
`gh attestation verify`. IRMind's catalog admission uses Ed25519 plus package
hashes and does not require those tools or their trust-root lifecycle.

For catalog tag `<TAG>`, external cosign verification requires exact issuer
`https://token.actions.githubusercontent.com` and identity
`https://github.com/ns2switch/irmind-skills/.github/workflows/release.yml@refs/tags/<TAG>`.
Provenance must bind the expected repository, source commit and release workflow.
Only the publishing job receives OIDC, attestation and release-write permissions;
ordinary validation retains `contents: read`. Actions/tools remain pinned and
verified. A dispatch rehearsal signs test artifacts without publishing a release.

## Application ports and signed admission

Propose two narrow ports before implementation:

- `SkillCatalogSource`: bounded, cancelable retrieval of a frozen release/index
  and named assets, callable only through the analyst installation workflow.
- `CatalogIndexVerifier`: pure bounded Ed25519 verification against compiled keys,
  expected repository and frozen tag, returning a typed verified-index receipt.
  It has no filesystem, network, clock, secret or installation capability.

The concrete contract also specifies immutable, hash-addressed retention of the
signed index proof for recovery, case snapshots and independent export. The
selected entry alone cannot verify a signature over the full index.

Reuse `SkillCompiler` and `SkillPackageStore`; do not add a second compiler or
an agent tool for acquisition. Add origin `catalog` to the signed installation
snapshot with the release tag/commit, index/asset digests, key ID, verification
policy and existing canonical package hash. Admission
is an Analyst-signed global operation after inspection, as for local packages.
Retain immutable historical package versions and verification receipts.

The Ed25519 trust strategy is fixed by this architecture. Concrete index,
admission, proof-storage and export encodings remain a pre-1.0 contract proposal. Its concrete canonical bytes, case snapshot proof
and export consequences require their own review before implementation.
Catalog content remains UNTRUSTED after signature/admission and passes through
ContentGuard before model use. It never enters a system message and cannot
expand declared tools, policy, scope, approvals or budgets. Case loads retain
exact package identities and signed receipts as today.

## Required tests

Cover valid/invalid Ed25519 signatures; unknown/removed keys; wrong
repository/tag/sequence; modified index or selected entry; wrong asset or logical
hash; missing full-index proof; duplicate core names; malformed/oversized packages;
missing mappings; guarded preview; cancellation; failed signed publication;
restart; explicit update diffs and offline operation with network unavailable.
Use a fake source/verifier to prove no network occurs without the analyst action,
on startup, during agent-selected skill loading or when cancelling preview.
A hostile package with a valid publisher signature still fails declaration,
scope and approval controls. External Sigstore verification has separate release
workflow tests and never substitutes for the index signature inside IRMind.

Next: publish concrete index, catalog-origin admission and case/export contracts
with vectors for review before implementation. Create the separate repository
only after that contract is approved. Subagent execution remains a separate feature.
