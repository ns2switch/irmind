# Release binary size

This page is for maintainers investigating download size. It separates executable
code and data from symbol metadata so size work does not remove modules or change
runtime controls. These measurements use the published Linux x86_64 release
artifacts and a controlled copy of each artifact, not an ingestion benchmark.

## Published artifact comparison

| Artifact | Download bytes | MiB | After equal symbol stripping | MiB |
| --- | ---: | ---: | ---: | ---: |
| CLI v0.2.0 | 38,230,464 | 36.46 | 38,215,480 | 36.45 |
| CLI v0.3.0 | 55,021,024 | 52.47 | 41,316,320 | 39.40 |
| EVTX helper v0.3.0 | 1,662,056 | 1.59 | 1,305,528 | 1.25 |

The v0.2.0 asset has no static symbol table. The v0.3.0 asset contains a
10,786,528-byte `.strtab` and a 2,918,016-byte `.symtab`. Stripping the same 0.3
artifact removes 13,704,704 bytes, or 24.91% of the download. That accounts for
81.62% of the apparent 16,790,560-byte increase. With the same stripping treatment,
the remaining increase is 3,100,840 bytes, or 8.11%.

The manifest had no explicit release profile in either tag. Linux's linker setup
changed from the distribution's mold package to pinned mold 2.42.1. The artifacts
prove different metadata retention; they do not establish which compiler/linker
stage removed the earlier symbol table. The explicit profile avoids depending on
that incidental behavior. Cargo manifests stay unchanged: native mapping identities
commit the root manifest bytes, so packaging flags belong in the workflow rather
than a root profile edit. All ten generated native mapping/declarative manifests
are byte-identical against the unmodified release source tree.

Debug-only stripping with GNU objcopy is insufficient in the controlled
comparison: it leaves the 0.3 artifact at 53,586,560 bytes. The release workflow sets `CARGO_PROFILE_RELEASE_STRIP=symbols`, covering the
main workspace and the separately resolved helper workspace. Existing published assets stay unchanged;
the normal release workflow signs and attests future stripped binaries.

A Cargo release build with the workflow environment setting produces a
42,406,936-byte CLI and a 1,334,120-byte helper with GNU ld. These are supplementary
checks, not the controlled same-artifact comparison: the linker differs from
the published mold build. The built CLI version/help and native helper probe
pass, and all ten actual generated mapping manifests match the baseline bytes.

## Runtime and diagnostic checks

The release-profile current-format suite passes 21 tests (one skipped), and
workspace all-target/all-feature clippy passes with warnings denied.

The controlled copies preserve every allocated section's address, length,
read/write/execute/TLS flags and SHA-256 payload. This includes `.text`, read-only
constants, dynamic linkage, `.eh_frame` and `.gcc_except_table`. GNU objcopy also
changes a non-runtime `SHF_INFO_LINK` section-header flag; the comparison reports
runtime flags separately rather than pretending the entire file is identical.

The CLI's version and root/ingest/verify-export help outputs are byte-identical
when both copies use the same executable basename. The stripped helper passes
the native containment probe and decodes all 14 records of the synthetic EVTX
fixture, with all 9,533 protocol bytes identical before and after stripping.
A missing-export error and its exit code are identical as well. These tests supplement the unchanged current-format golden and custody
contracts.

Panic behavior remains `unwind`. Ordinary errors and their cause strings remain
available. Offline symbolized native panic backtraces need an unstripped developer
build, for example with `CARGO_PROFILE_RELEASE_STRIP=none`; this setting is not a
reason to replace normal operational error diagnostics with panics.

## Crate and feature review

The [`nm` analysis](benchmark-data/release-binary-size.json) groups defined text
symbols by their first Rust namespace or native prefix and counts same-address
aliases once. Inlining, shared generics and overlapping symbols make these
estimates approximate. They are not the bytes saved by removing a crate.

The largest groups include core/alloc monomorphizations, Parquet, Arrow arrays and
selection, aws-lc native routines, the application, SQLite and object storage.
Arrow and Parquet use one major version (59); rustls also has one version. Several
libraries span incompatible API generations: base64 0.22/0.23, digest 0.10/0.11,
rand 0.8/0.10, getrandom 0.2/0.3/0.4 and syn 2/3. Some are build-time macros;
lockfile duplication alone is not binary duplication.

Both ring and aws-lc are required by the reviewed authentication/TLS dependency
paths. Unifying providers would require a separate supported-algorithm and TLS
review. Default modules, provider credentials and TLS features are retained.

| Release setting | Current value | Action |
| --- | --- | --- |
| `opt-level` | 3 | Keep throughput-oriented code generation. |
| `lto` | false | Keep; cross-crate thin LTO needs measured size, link-time and query comparisons. |
| `codegen-units` | 16 | Keep; reducing it may increase compile time and changes generated code. |
| `strip` | symbols via environment | Make release packaging explicit for both workspaces. |
| `panic` | unwind | Keep cleanup, rollback and error behavior. |

Changing optimization level, removing unwind behavior or dropping product
features is outside this size fix. See Cargo's [profile reference](https://doc.rust-lang.org/cargo/reference/profiles.html).

## Reproduce the controlled comparison

Download the two tagged Linux assets and their `SHA256SUMS`, verify the checksums,
and verify release signatures as described in [platforms](../platforms.md).
Keep the originals unchanged. Use a copy named `release-before`, then run:

```sh
objcopy -s release-before release-after
python3 scripts/analyze_elf_size.py release-before release-after
```

For a local stripped build, set `CARGO_PROFILE_RELEASE_STRIP=symbols` when
running `cargo build --release -p irmind --locked`; the helper uses the same
environment setting in its separate workspace.

The development script needs Python 3 and GNU binutils (`readelf`, `nm`,
`objcopy` for the copy step). It never executes an input binary and adds no
production dependency. The [raw measurements](benchmark-data/release-binary-size.json)
include artifact SHA-256 values, section measurements and namespace totals.
