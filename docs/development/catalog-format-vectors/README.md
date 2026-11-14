# Catalog contract vectors

These synthetic fixtures freeze proposed codecs, hashes and valid public-key
signatures. They create no real catalog key and must never populate a production
trust list. Current IRMind does not implement these formats.

- `index.json` is exact canonical UTF-8 without a trailing newline.
  `index-preimage.hex` fixes domain, u64 length and index bytes;
  `index-signature.hex` decodes to the detached 64-byte Ed25519 signature.
- `synthetic-triage-1.skill.json` is the package transport. Its logical package
  commitment equals the existing synthetic skill vector, independently of the
  transport checksum. `package-inventory.hex` fixes that existing inventory codec.
- `catalog-receipt.json`, `installation-v2.json`, `signed-installation.json` and
  `snapshot-v2.json` bind the index, selected entry and package. The signed
  operation uses the unchanged global operation challenge, with a synthetic
  Analyst key. Signed snapshot bytes use the current audit challenge and new label.
- `load-v1.json` preserves the current load shape while referencing the new
  snapshot identity. `proof-descriptor.json` / `proof-chunk.json` retain the
  full signed index; no selected-entry-only authentication is possible.
- `v8-catalog-tail.hex` is the extension tail: one catalog proof with one index
  chunk and zero subagent chunks. It is not a complete V8 archive. The header,
  current sections, sealed case and source material are intentionally absent.
- `negative-cases.json` identifies required rejection cases. Modified index,
  duplicated field and changed asset files are deliberately invalid. No future
  case verifier should accept a fragment or missing context as a complete case.

JSON field order and lack of trailing whitespace are normative. Hex files have
one final LF for readability; decode their ASCII hex to obtain the signed/wire
bytes. `identities.json` gives expected digests. SHA256SUMS hashes the fixture
files themselves, including their documented LF convention.

Signatures were checked with an independent development reference and OpenSSL;
new runtime/contract tests must consume these exact bytes and also exercise
full installation/recovery/case/export behavior. Public keys are in
`public-keys.json`; no private key or production secret is included.
