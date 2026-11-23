# Native mapping build manifest V2

**Status.** Proposed encoding and independent synthetic vectors for v0.7.
See the [dependency-closure design](native-mapping-build-identity.md).

The manifest commits to the production inputs that reach one native mapping
when building the shipped IRMind binary. The SHA-256 of the canonical manifest
fills the existing mapping implementation hash. Mapping snapshots embed the
exact bytes as lowercase hex in their existing native provenance field. The
64 KiB manifest cap, snapshot bounds, signatures, and signed envelope formats
are unchanged. New native identities require the creating executable for
complete reconstruction of older cases. Declarative definition descriptors
and the hashes of bundled mapping tables are outside this change.

## Build inputs

The release build derives the closure for the shipping feature set from the
locked build of the binary. Use Cargo package metadata for identities and
lockfile checksums, but corroborate the graph and features against actual
compiler invocations for that release build. Cargo may compile the same
package with different host and target features. In particular, a flattened
workspace feature listing can include features used only by tests.
[Cargo tree feature unification](https://doc.rust-lang.org/cargo/commands/cargo-tree.html#feature-unification) ·
[Cargo resolver](https://doc.rust-lang.org/cargo/reference/resolver.html#feature-resolver-version-2).

A preflight on each native runner observes the normal, host-build and
procedural-macro units of a clean shipping build. Capture only the fields
needed for identity through an audited compiler wrapper and normalize its
artifact references to unit edges. Generate a canonical per-target
observation and combine the five observations in the existing release
pipeline before producing release binaries. Each release runner verifies its
own observation against the combined input while building and replaying.
Reject unexplained differences, unclassified inputs, paths outside approved
package roots and mismatched lockfile checksums. The build-manifest crate
reads prepared inputs offline. Preparation of a complete manifest from the
same approved target matrix is part of the reproducible build procedure.

A unit records the resolved package, source and context. Features are the
actual enabled features of that unit, including effects of unification in
the shipping binary. Edges record the child, dependency name as used by Rust
and whether the edge is normal or build-time. Registry identity includes the
registry URL and the digest from the lockfile. Git identity includes a
credential-free canonical repository URL and the full locked revision.
Local packages and applicable workspace patches use a tracked
repository-relative path and file digests. Commit the effective package
configuration for the selected unit. Derive it from resolved inheritance,
production dependency declarations, applicable patches, enabled feature
definitions, package edition and the other settings consumed by the build.
Ignore dev-only dependencies, unresolved optional features, unrelated patch
entries and workspace members outside the closure. A resolved feature
change that reaches the closure is included even when another binary module
enabled it.

Reachable local files include semantic `include!` and `include_bytes!`
inputs, tracked build-script inputs, code generated at build time and the
build-manifest implementation itself. A registry checksum or Git revision
binds its original package input; locally replaced sources are committed as
local packages. Commit digests of deterministic generated data used by a
mapping under stable logical names, and record normalized semantic build
configuration, including the exact Rust release. Exclude the generated
manifest and its own digest from observations to break the dependency
cycle. Reject unknown environment-dependent build inputs. Absolute paths,
credentials, arbitrary environment values, timestamps and compiler output
paths never enter the manifest. Require LF checkouts for committed text
inputs and hash binary files byte for byte.

A single canonical manifest carries all applicable target observations.
Merge identical units, edges and file inputs across targets and encode
their applicability masks. Every shipping target receives these same
bytes. Target-specific reachable code or features require an explanation
and a cross-platform output comparison. If the five builds do not produce
the same normalized mapping output, stop before shipping a universal
identity.

## Canonical encoding

Integers are unsigned and big-endian. `bytes` is a u32 byte length followed
by bytes, `text` is a `bytes` field containing UTF-8, and `hash` is a raw
32-byte SHA-256. Counts and indexes use u32. All lists are preceded by their
element count. Serialize only in the orders below, with no duplicates,
implicit default fields or trailing bytes. Sort text by its UTF-8 bytes,
and sort integers numerically.

| Part | Encoding in order |
| --- | --- |
| Prefix | ASCII `irmind-native-mapping-build-v2` and a zero byte. |
| Build settings | Rust release `text`, normalized semantic build settings `hash`, then root unit index u32. |
| Unit table | `list<unit>` sorted by (name, version, source kind, source identifier, content digest, context, feature list, effective manifest digest). The index is its zero-based position. |
| Unit | Name `text`, resolved version `text`, source kind u8, source identifier `text`, content `hash`, context u8, sorted `list<text>` of enabled features, effective manifest `hash`, applicability mask u8. |
| Edge table | `list<edge>`, sorted by (from, to, kind, alias). An edge contains from index u32, to index u32, kind u8, Rust alias `text`, applicability mask u8. |
| Input table | `list<input>`, sorted by (unit, kind, logical path, digest). An input contains unit index u32, kind u8, logical path `text`, `hash`, applicability mask u8. |

Source kinds are 0 for repository path, 1 for registry and 2 for Git.
The local unit content digest is 32 zero bytes and the input table commits
its files. Registry content is the lockfile SHA-256 checksum. For Git,
content is SHA-256 of the UTF-8 full lowercase locked revision. Include the
revision in the source identifier after a single ASCII `#` so it remains
independently inspectable. Unit context is 0 for target libraries, 1 for
host libraries and procedural macros, and 2 for a build script. Edges use 0
for normal and 1 for build-time dependencies. Inputs use 0 for tracked
source, data or build configuration and 1 for generated semantic data.

Bit 0 identifies Linux x86_64, bit 1 Linux arm64, bit 2 macOS Intel, bit 3
macOS Apple Silicon and bit 4 Windows x86_64. Masks are nonzero and the three
high bits are zero. A unit that appears in all five targets uses mask 31.
The root unit must cover all targets. An edge mask is a subset of both
endpoints' masks and an input mask is a subset of its unit's mask.
When the same identity appears for distinct features or different effective
settings in separate targets, encode separate units. Root mapping features
must agree across the supported release targets.

Cap the manifest at 65,536 bytes, the unit list at 256, the edge list at
1,024 and the input list at 1,024. Cap individual UTF-8 fields at 512 bytes
and a unit's feature list at 128. Reject noncanonical order, duplicates,
unknown codes, ambiguous units, a disconnected unit, non-portable logical
paths, and byte counts or indexes outside their enclosing records. Check
reachability from the root per mask. Format validation in export
verification authenticates the bytes and their hash; it never loads
executables. Full reconstruction also requires a locally trusted compiled
mapping with the identical manifest.

## Independent vectors and measurements

The [synthetic vectors](vectors/native-mapping-manifest-v2.json) include the
canonical hex and SHA-256 of a small three-unit graph. The accompanying
[Python reference](vectors/native-mapping-manifest-v2.py) uses only the
standard library. It also computes variants for different source bytes,
version, checksum, patch, feature and generated inputs. The same bytes
follow from reversing all input lists or changing an irrelevant workspace
member, a dev-only dependency or the unrelated `url` / `form_urlencoded`
lock entries. These examples specify the wire. Production resolution must
also exercise the real [dependency update in #380](https://github.com/ns2switch/irmind/pull/380)
against the actual locked graph.

Measure the original and replacement manifest size by mapper, and separate
closure preparation, clean release compilation, and the reproducibility
replay. Verify the exact mapping digest set on all five release targets.
The preflight must prove that these size bounds fit the shipping graph
before implementation adopts the encoding.
