# Explicit installation from the community skill catalog

Design proposal; catalog downloads and in-application signature verification are
not implemented by this document. The [community repository](https://github.com/ns2switch/irmind-skills)
is separate from IRMind. Bundled skills remain the release's core and are not
copied into that repository. Current local installation, package compilation,
signed admission and case receipts remain the baseline described in the
[installation](skills-installation-contract.md) and
[case/export](skills-case-format-contract.md) contracts.

## User flow and network boundary

`/skills install catalog:<name>` is an explicit analyst action. It opens a
preview of the catalog repository, selected release tag and outbound requests
before any network access. Confirming that action permits bounded downloads
from that release only. No startup, skill discovery, model tool or background
update fetches an index, checks for updates or installs content.

Freeze the selected tag, release identity and index digest for the operation.
Download and verify the index, then download the selected package and its
verification material. Show the exact source, name, version, package commitment,
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
rejected. Entries are sorted by skill name and include:

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

Initial proposed limits: 1 MiB index, 1,024 entries, 1 MiB compressed package,
128 KiB expanded package, 16 resources, 32 KiB per resource, 8 KiB frontmatter,
4 MiB per signature/provenance proof and 30 seconds per request. Package limits
must be imported from the current compiler, never enlarged by the index. Bound
total operation bytes, redirects and proof counts as well. Store downloads in a
private data-directory staging area, with disk preflight, cancellation and
cleanup after errors. Refuse absolute/traversal names, symlinks, hard links,
duplicate paths, case aliases and unsupported files before publication.

Sign the index, checksum file and package assets with keyless Sigstore and
publish their bundles. Publish GitHub build provenance for the index/packages.
Only the publishing job receives OIDC, attestation and release-write permissions;
ordinary validation retains `contents: read`. A dispatch rehearsal signs test
artifacts without publishing or creating a tag. The index and all selected
assets must pass verification before preview can be approved.

## Signature verification and trust roots

The exact expected certificate issuer is
`https://token.actions.githubusercontent.com`. For catalog tag `<TAG>`, the
exact expected certificate identity is
`https://github.com/ns2switch/irmind-skills/.github/workflows/release.yml@refs/tags/<TAG>`.
Do not accept a prefix, a regular expression matching arbitrary workflows,
another repository, a branch identity or a pull-request workflow.

Verify the blob digest, Fulcio chain, signing-time certificate validity and
transparency inclusion using a separately trusted Sigstore root. Never trust a
root supplied by the downloaded package or index. Verify provenance subject
digests and the expected repository, source commit and release workflow too.
A valid signature proves publisher identity and bytes, not harmless methodology.
See [Sigstore blob verification](https://docs.sigstore.dev/cosign/verifying/verify/)
and [GitHub attestation verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

Two implementation choices require a separate review:

1. A maintained in-process Sigstore verification library, with its dependency
   graph, license and supported bundle versions reviewed before incorporation.
   Current hashing, TLS and JWT libraries alone are not a complete Sigstore
   verifier. Do not implement an ad hoc X.509/transparency verifier.
2. A configured existing `cosign` verifier and GitHub provenance verifier,
   launched without a shell, with fixed arguments, sanitized environment,
   bounded time/output and a verified supported version. IRMind must never
   download or execute a verifier automatically. Offline blob verification uses
   the bundle and an explicitly provisioned trusted root; no implicit TUF update.

Both choices need an explicit policy for trust-root refresh, stale metadata,
revoked/replaced releases and old signing keys. Refresh is itself an explicit
analyst action with displayed network destinations. Without sufficient trust
material verification fails visibly; it cannot degrade to checksums alone.
Local manually verified installation remains available with its honest origin.

## Application ports and signed admission

Propose two narrow ports before implementation:

- `SkillCatalogSource`: bounded, cancelable retrieval of a frozen release/index
  and named assets, callable only through the analyst installation workflow.
- `CatalogReleaseVerifier`: verifies the exact bytes and proofs against the
  expected repository, tag, workflow and trusted root, returning a typed
  verification receipt rather than a boolean supplied by untrusted input.

Reuse `SkillCompiler` and `SkillPackageStore`; do not add a second compiler or
an agent tool for acquisition. Add origin `catalog` to the signed installation
snapshot with the release tag/commit, index/asset digests, publisher identity,
verification policy/root identity and existing canonical package hash. Admission
is an Analyst-signed global operation after inspection, as for local packages.
Retain immutable historical package versions and verification receipts.

This is a proposed pre-1.0 definition/admission format change, not an approved
port or dependency addition. Its concrete canonical bytes, case snapshot proof
and export consequences require their own review before implementation.
Catalog content remains UNTRUSTED after signature/admission and passes through
ContentGuard before model use. It never enters a system message and cannot
expand declared tools, policy, scope, approvals or budgets. Case loads retain
exact package identities and signed receipts as today.

## Required tests

Cover valid/invalid bundles; wrong issuer/repository/workflow/tag; missing or
altered proof; wrong archive or logical hash; unsupported root or interpreter;
index downgrade; duplicate core names; malformed/oversized archives; missing
mappings; guarded preview; cancellation; failed signed publication; restart;
and old/new diff fidelity. Use a fake source/verifier to prove no network occurs
without the analyst action, on startup, during agent-selected skill loading or
when canceling preview. A hostile package with a valid publisher signature must
still fail the existing declaration, scope and approval controls.

Catalog installation implementation waits for design and contract review.
Subagents and a live Kubernetes connector are independent future designs.
