# Native mapping build identity

**Status.** Proposal for v0.7.

Native mapping identities currently commit to each mapping crate, shared
implementation sources, the application and domain crates, the build-manifest
crate, and both root Cargo files. The manifest sorts logical paths and
production feature names and hashes file contents. A change to workspace
membership or an unrelated dev-dependency can therefore change every native
mapping identity. Identities also change when shared validation code changes,
which is expected. [Current manifest generator](../../crates/build-manifest/src/lib.rs).

## Proposed manifest

Introduce a versioned native build manifest keyed to the production dependency
closure of each mapping. Keep the mapping crate's manifest, implementation,
build script and the generated mapping inputs. Include the following in
canonical order.

| Input | What to commit |
| --- | --- |
| Workspace inheritance | Resolved manifest values that affect this crate or its reachable dependencies, including applicable overrides and patches. |
| Registry and Git dependencies | Reachable normal and build dependency edges, package name, version, source, lockfile checksum or exact Git revision, and enabled production features. |
| Workspace and patched paths | Repository-relative path, effective manifest, build inputs and source file hashes for every reachable package whose code can affect mapping output. |
| Build configuration | Format domain, target-independent semantic configuration, feature resolution and toolchain inputs that can affect the mapping. |

A package is identified by name, version and source together. Commit edges in
addition to package entries so changes in feature resolution or versions are
visible. Ignore standalone dev graphs and unrelated workspace members. Preserve
the rules against absolute paths, secrets and machine environment values.
Treat out-of-tree patches or untracked build inputs as unsupported until their
identity can be committed.

Record the production resolution for supported targets in a fixed order. First
establish that those targets produce the same normalized mapping output. Where
an input can legitimately change mapping semantics by target, include the
different input in the commitment and require a decision on the resulting
platform-specific identities before publishing. Produce the manifest during
release preparation from a locked graph and verify it in Cargo; build scripts
should consume the prepared resolution without accessing the network.

## Custody and rollout

The new manifest domain changes the hash and therefore the mapping version and
identity in newly signed profiles and receipts. Preserve the existing signed
envelopes and schema labels if their generic manifest fields can carry the
new commitment. Review the verifier's manifest validation, size cap and
native trust binding before choosing that encoding. Generate independent
vectors before implementation.

Authenticating an earlier record continues to require its original bytes and
key. A newer dependency-closure identity cannot recreate an earlier identity
by assertion. Complete reconstruction requires the precise executable or an
explicitly supported matching implementation. Under the current pre-1.0
policy, a future release may require the creating version or re-ingestion.
Document that boundary in its release notes.

Require equal identities across clean, path-independent release builds.
Test changes to unrelated workspace membership and dev-dependencies, then
verify that modifying a reachable source file, version, checksum, patch,
production feature or build input changes the applicable mapping identity.
Measure manifest size and release build time against the current generator
before deciding whether to adopt the new domain.
