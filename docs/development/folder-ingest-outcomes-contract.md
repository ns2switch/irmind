# Local folder ingestion outcomes

**Status** Approved for v0.7.4.

An ingest request currently resolves the entire detection plan before any source
is committed. The old signed rejection payload stores a source reference, a
reason and optional samples. It cannot authenticate the identity of a skipped
file, or establish what an unsigned checksum declared.

## Ingestion and retry

- Build a canonical, bounded inventory of regular files under the selected
  root. Use safe rooted reads for detection, fingerprinting and input. Never
  follow links or open a path supplied by a checksum file.
- Process automatically recognized files first in canonical order. Keep
  per-file atomicity and the existing bounded group retry. A source-local
  detection, pipeline or parse error is a failed or unresolved file. Disk,
  case lock, custody, signature and cancellation failures stop the operation.
  Successfully committed inputs remain available. If another path already
  has a mapped generation for the exact same bytes, the current pipeline
  cannot ingest that duplicate. The folder records a failed pipeline outcome
  and continues, preserving the original and the existing generation.
- Present unresolved files in a single end-of-ingest TUI queue. The analyst
  can assign an available parser, skip the selected file or skip all thus far
  unresolved files. A parser-specific date or cluster question has both skip
  options. Never present a detector as selectable when its decoder or required
  mapping pipeline is disabled. A CLI folder import continues with a
  noninteractive outcome and documents how to retry a specific file.
- Recognize checksum and signature companions by the closed list `.sha256`,
  `.sha1`, `.md5`, `SHA256SUMS`, `.sig` and `.asc` with ASCII-insensitive
  matching. An execution log qualifies only under a reviewed collector
  basename and a matching bounded format signature. A generic `.log`,
  `.txt` or a prefix alone is insufficient. Log signatures and their
  negative fixtures are reviewed with the implementation.
- A skip leaves the original intact. A retry starts with the current bytes
  and can choose a parser. A new ingested manifest with the same reference
  and SHA-256 resolves the previous coverage gap. Signed attempts remain in
  history. A different digest at the same reference leaves the gap visible.

Collector recognition inspects at most 64 KiB and 128 lines. A
`Collection-*.log` file needs both Velociraptor collector startup and
container markers. KAPE `*_ConsoleLog.txt` needs timestamped version and
command-line entries. Recognized EZTools console logs need the tool name in
the basename and the author and command-line markers in the body. Unrecognized
variants remain eligible for normal detection or analyst selection.
[Velociraptor log example](https://github.com/Velocidex/velociraptor/issues/4509)
[KAPE log example](https://github.com/EricZimmerman/Issues/issues/168)

## Signed outcome

Add audit kind `ingest-file-outcome-v1`. The audit origin and signer are
Analyst, with no evidence attachment. A skipped file is not an evidence blob
or a source manifest. The payload is lowercase hexadecimal of the wire below.
Integers are unsigned big-endian. A path is u32 byte length plus strict UTF-8
for an existing validated local relative SourceReferenceV1, at most 1,024
bytes. Reject exhausting a length, unknown codes, trailing bytes, a remote
URI, a traversal, and noncanonical payloads.

| Field | Disposition variant | Integrity variant |
| --- | --- | --- |
| Domain bytes | `irmind-ingest-file-outcome-v1` followed by `00` | Same |
| Variant u8 | 0 | 1 |
| File reference | Original | Target original |
| File identity state u8 | 0 complete, 1 size only, 2 unavailable | 0 complete |
| File size and hash | State 0 has u64 size and 32-byte SHA-256. State 1 has u64 size. State 2 has neither | u64 size and 32-byte observed SHA-256 |
| Tail | u8 disposition and u8 reason | Companion path, u64 companion size, 32-byte companion SHA-256, 32-byte declared target SHA-256 and u8 verdict |

Disposition codes are 0 skipped and 1 failed. Allowed reason and disposition
pairs are fixed.

| Reason code | Reason | Disposition |
| --- | --- | --- |
| 0 | Analyst skipped unresolved input | Skipped |
| 1 | Checksum companion | Skipped |
| 2 | Signature companion | Skipped |
| 3 | Recognized collector execution log | Skipped |
| 4 | Recognized integrity digest, such as CloudTrail | Skipped |
| 5 | No parser selected in noninteractive import | Skipped |
| 6 | Pipeline unavailable | Failed |
| 7 | Invalid source format | Failed |
| 8 | Source limit exceeded | Failed |
| 9 | Source changed or disagreed with its ingestion hash | Failed |
| 10 | Source unavailable for safe read | Failed |

Fingerprint readable sources with the existing bounded, streaming and
cancellable raw-byte SHA-256 path. Where a complete read is impossible,
state 1 or 2 is permitted only for reasons 8, 9 and 10. Report the missing
fingerprint explicitly. Crash, cancellation or a failed signature cannot
produce an invented disposition or claim of integrity.

Integrity verdict 0 requires equal declared and observed hashes. Verdict 1
requires unequal hashes. A companion and destination are distinct paths in the
same enumerated import. Never compare with a path outside that inventory.
Only parse bounded `.sha256` and `SHA256SUMS` inputs under the existing
source-read controls, up to 1 MiB and 4,096 lines. Permit a single bare digest
for the same-directory basename without the final `.sha256`, or GNU-form
digest and relative name. Resolve the name from the companion directory
without dot segments, drive prefixes, backslashes or escaped names. Conflicting
declarations are an explicit warning and establish no verified integrity.
Compare against the exact bytes identified by the source manifest if ingested.
These receipts record consistency with an unsigned companion. They confer no
publisher trust or authority to ingest.

## Verification, report and export

Authenticate and validate the new kind during case open, verification and
offline V10 verification. Reuse the case-entry challenge and V10 audit
inventory. No new envelope, counter, or proof section is needed. Verify the
receipt attribution and bytes. Checking the original itself still requires
the original. Comparison with an authenticated manifest, where present,
uses the receipt's observed hash, size and reference.

Add the unresolved dispositions and checksum mismatches to the report
limitations as deterministic statements derived from its authenticated
checkpoint. Include the receipt sequence and hash. Keep ReportCoverageV2 and
existing report objects unchanged. A prefix without the new kind renders
exactly as before. Show the signed outcome and mismatch totals in /verify and
/evidence. Report a conspicuous integrity mismatch while preserving
per-file ingestion and rollback. Report the signed format addition in the
release notes. Older binaries may reject cases or exports using the new
audit kind.

## Approval vectors and acceptance tests

The [independent generator](folder-ingest-outcomes-vectors/generate.py) and
[wire vectors](folder-ingest-outcomes-vectors/wire.json) include a Unicode
skipped file, an unavailable decoder, an unreadable file, both integrity
verdicts, a signed Audit V2 entry and negative bodies. Implementation must
reproduce them in Rust. Prove exact filesystem and custody semantics with a
mixed folder containing good, ambiguous, unknown, unavailable, malformed,
checksum, signature and collector files. Include positive and mismatch
checksums and a malicious path. Verify and export a sealed case, reconstruct
an older report unchanged, and confirm retry resolution for identical bytes.

## Release-build scale check

On Linux x86-64, the synthetic corpus has 100 distinct CloudTrail files,
8,000 signature companions and 1,900 unresolved files. At 100×40 columns,
the TUI reached the queue in 1.965 s, allowed cycling it, and committed all
remaining skips in 1.347 s. CLI verification of the case with 9,900 signed
dispositions and 100 originals took 1.285 s. The receipt encoding is the
approved per-file encoding.

Run the scale check with:

```sh
cargo test --release --locked -p irmind --test folder_ingest folder_ingest_ten_thousand_files -- --ignored --nocapture
```
