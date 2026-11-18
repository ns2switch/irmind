# Bounded email decoder dependency

[Español](../es/email-decoder-dependency.md)

## Proposed dependency

Use `mail-parser = "=0.11.9"`, with `default-features = false`, exclusively in
`parser-email`. The published crate is dual MIT / Apache-2.0. Its archive SHA-256
is `4ec00bda90c6e645a54506c630c2820cd6b1890cfd2b0a169b50f74b2b8c7c86`.
Its source contains no unsafe blocks. The only nonoptional dependency is the
`hashify` 0.2 compile-time macro; optional encoding, serialization and archive
features remain disabled. Resolve and review the exact transitive versions before
integration; no dependency policy exception is proposed.

The current 1.0 branch requires Rust 1.98; IRMind currently targets Rust 1.95.
This proposal does not upgrade the toolchain or copy/fork the third-party parser.
[Published crate](https://crates.io/crates/mail-parser/0.11.9),
[upstream source](https://github.com/stalwartlabs/mail-parser),
[RFC 5322](https://www.rfc-editor.org/rfc/rfc5322.html).

## Bounded use

Use the library's **headers-only** parser to handle quoted addresses, comments,
folded fields, encoded header words and content-type parameters. Do not use its
unrestricted whole-message MIME traversal. IRMind owns an iterative MIME walk
with explicit limits before entering each part: source at most 32 MiB, 1,024
headers total, 64 KiB per header block, 16 nested containers and 256 parts.
Over-limit or malformed structures are rejected with a clear bounded report.
Transport/base64 and quoted-printable decoding remain bounded by admitted bytes;
archives and attachments are never decompressed or executed. Preserve original
header order/raw offsets, especially Received; keep the original file signed.

Only metadata and SHA-256 of decoded attachment bytes become records. Text URLs
are extracted literally without following them; HTML is never rendered. Unknown
charset/body types remain original evidence with an explicit coverage notice.
All output is tainted and passes the normal ContentGuard/provenance pipeline.
No network, shell, executable, policy or process-lifetime capability is added.

## Alternative without a new dependency

Implement the supported RFC header/MIME grammar in IRMind. This avoids the crate
but duplicates address, folding, encoded-word and parameter handling, increases
maintenance and requires a larger conformance corpus. It must not silently treat
unsupported messages as fully parsed. The dependency is proposed to reduce that
parsing burden while keeping IRMind's own admission and traversal limits.

Acceptance includes malformed/folded/duplicate headers, multipart nesting,
encoded filenames and bodies, preserved Received order, oversized attachments,
URL non-fetching, terminal-control/injection content, cancellation, synthetic
fixtures, ten minutes of AddressSanitizer fuzzing and a release-build benchmark.
