# Skill compilation and local installation contracts

This proposal is for reviewers implementing [the skills design](skills-design.md).
It specifies the next application boundaries. The package-foundation code does
not implement these ports, sign skill operations or expose an agent/TUI action.

## Scope

The first implementation provides bounded immutable `SkillPackage` bytes,
`SkillMetadata`, a distinct `SkillDigest` and strict TOML decoding. These are
untrusted values, not installation approval, evidence or executable plugins.

The next step needs two new local synchronous ports in `irmind-app`. Existing
`Repository`, `AuditLog`, `ContentGuard`, `EvidenceGraph` and parser ports stay
unchanged. Async presentation calls use `spawn_blocking` as for other local work.
No new production dependency, credential, shell, unsafe code or provider is
needed. Public/community downloads are a later explicit transport boundary;
the local importer will not fetch URLs.

## Pure compilation port

Proposed signature:

```rust
pub trait SkillCompiler: Send + Sync {
    fn compile(&self, package: SkillPackage) -> Result<CompiledSkill, AppError>;
}
```

`CompiledSkill` is an untrusted checked application value containing the original
package, parsed metadata and the exact original Markdown body byte range. It
confers no approval. Construction checks range bounds, mandatory SKILL.md,
package commitment, metadata constraints and the current target schema.

The stock implementation uses the same decoder for preview, admission, recovery
and load. There is no permissive preview parser or alternate installer path.
It validates the fixed tool catalog without enabling missing modules. Source
availability and aliases are checked when creating an active catalog, with the
one existing TUI command registry supplying reserved names.

Compilation receives no filesystem, network, clock, configuration, secret or
signing capability. Query resources are data; complete structured-template
validation must precede any eventual substitution/execution. Rule YAML remains
reference-only. Unknown tool/schema/interpreter, malformed metadata, bounds and
ambiguous definitions fail with fixed errors that contain no package content.

## Local package storage port

Proposed signatures:

```rust
pub trait SkillPackageStore: Send + Sync {
    fn read_candidate(
        &self,
        directory: &Path,
        cancel: &CancellationToken,
    ) -> Result<SkillPackage, AppError>;
    fn names(&self) -> Result<Vec<SkillName>, AppError>;
    fn read_active(&self, name: &SkillName) -> Result<Option<SkillPackage>, AppError>;
    fn publish(&self, name: &SkillName, package: &SkillPackage) -> Result<(), AppError>;
    fn deactivate(&self, name: &SkillName) -> Result<(), AppError>;
    fn clean_temporary(&self) -> Result<usize, AppError>;
}
```

The root of composition chooses the private data directory. `read_candidate`
reads only the analyst-selected folder and permitted regular resources, with
bounded directory enumeration, no symlink/reparse following or hard-link aliases,
per-file and aggregate byte limits and cancellation checks. It neither modifies
the source folder nor publishes anything. Failure leaves no partial candidate.
An unreadable/unprovable file kind fails closed; there is no relaxed platform mode.

Store an active package in one private data container keyed by validated skill
name. Resource paths remain inventory keys, not arbitrary filesystem writes.
Publish the complete generation with a case-local/private temporary, file sync,
atomic durable replacement and directory sync using `irmind-fs`. Use 0600/0700 on
Unix and the existing user-only ACL boundary on Windows. No system-temp evidence
copy or new unsafe boundary is introduced. Readers observe one whole generation.

The signed global history holds full historical snapshots, so no unsigned
archive is an authorization source. `clean_temporary` removes only owned pending
files and writes counts to diagnostics, not the signed history. It cannot delete
active generations or snapshots referenced by a case.

## Proposed global installation record

Reuse the existing `SignedOperation` envelope, global lock, Analyst key and
append path. Propose a new operation family, `skill-installation-v1:` followed
by lowercase hex of bounded canonical JSON. This is new application data; the
existing operation envelope and its signature challenge do not change.

Use a fixed struct field order, explicit nulls and a sorted file vector:

1. `format_version`: integer 1.
2. `name`: validated skill name.
3. `skill_version`: exact bounded version identifier.
4. `package_sha256`: lowercase 64-hex package commitment.
5. `origin`: `bundled`, `organization` or `analyst`; a label is not trust.
6. `active`: boolean.
7. `previous_operation`: previous operation hash for this skill, or null.
8. `files`: path-sorted `{path, contents}` entries preserving exact UTF-8 bytes.

Reject duplicate/unknown fields, noncanonical JSON, mismatched metadata/name/hash,
wrong signers and invalid per-skill previous links. Replay recomputes the package
commitment, recompiles the exact snapshot and checks built-in identities against
the compiled inventory. Reused version labels cannot silently replace hashes.
The encoded record must fit the existing 1 MiB ceiling; do not increase it.

Bound history to 256 installed names, 4,096 versions and 32 active skills. Validate
those limits before signing. Installation/update/activation/deactivation are
attended analyst actions; there is no model tool for them and no key material in
their arguments, snapshots or diagnostics. Apply ContentGuard before safe review
and on each subsequent exposure; signing never promotes methodology to system.

## Transaction and recovery

Verify existing history, validate/compile/guard the candidate, resolve name and
command collisions explicitly, then acquire/recheck the global operational lock.
Sign the complete approved snapshot before publishing the active container.
Signing failure changes neither active storage nor authorization.

A publish failure after a durable signature leaves an explicit recovery state,
not a usable loose file. Startup disables the mismatched package and offers
restoration from the signed snapshot or a separately reviewed new admission.
Never restore or accept silently. Other case operations remain available.
Updates do not mutate in-flight bytes, historical loads or existing case snapshots.

## Required contract tests and later boundaries

Every compiler/store implementation must cover strict metadata and resource
validation, preview/load equivalence, exact commitments, no secret-bearing Debug
or errors, path/platform aliases, no writes outside its private root, atomic
generation reads, cancellation and cleanup. Simulate crashes before signature,
after signature and during publish; test failed-signature and disk errors.

No skill text reaches the model in this installation step. Case `SkillSnapshotV1`
and `SkillLoadV1`, distinct skill provenance, guarded progressive reads and export
support need their own concrete current-format encoding/golden review before
integration. Do not overload an evidence hash, existing parser fields or current
export V6 to smuggle in those records. The first package-foundation PR changes
no audit event kind, signed case bytes, seal bytes or export format.
