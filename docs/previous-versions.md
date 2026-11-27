# Keep the IRMind version that created a case

[Español](es/previous-versions.md)

The current format is case 8 and export V12. Cases from v0.8.0-alpha.1
use case 7 and export V11 and need the exact alpha binary. To open, verify,
export or delete a case from 0.7.x, use the exact 0.7.x binary that created
it. Homebrew upgrades can remove older binaries. Before upgrading an open
case, save a verified copy of its creating binary and EVTX helper, along
with the compatible data directory and keystore.

## Download and verify a specific tag

Find the producing tag in [GitHub releases](https://github.com/ns2switch/irmind/releases).
Download the two executables for your system, their `.sigstore.json` bundles,
`SHA256SUMS` and `SHA256SUMS.sigstore.json` into a new directory. Choose one
main binary and its matching EVTX helper.

| Platform | Main asset | EVTX helper asset |
| --- | --- | --- |
| Linux x86-64 | `irmind-linux-x86_64` | `irmind-evtx-linux-x86_64` |
| Linux arm64 | `irmind-linux-aarch64` | `irmind-evtx-linux-aarch64` |
| macOS Apple Silicon | `irmind-macos-aarch64` | `irmind-evtx-macos-aarch64` |
| macOS Intel | `irmind-macos-x86_64` | `irmind-evtx-macos-x86_64` |
| Windows x64 | `irmind-windows-x86_64.exe` | `irmind-evtx-windows-x86_64.exe` |

For example, use the following for v0.7.4 on Linux x86-64. Replace the tag
and both filenames with the values for your case. Use cosign 3.1.3 or later
and a current GitHub CLI with `gh attestation verify`.

```sh
set -eu
repo=ns2switch/irmind
tag=v0.7.4
binary=irmind-linux-x86_64
helper=irmind-evtx-linux-x86_64

gh release download "$tag" -R "$repo" -p 'SHA256SUMS*' \
  -p "$binary" -p "$binary.sigstore.json" -p "$helper" -p "$helper.sigstore.json"

for file in SHA256SUMS "$binary" "$helper"; do
  cosign verify-blob "$file" --bundle "$file.sigstore.json" \
    --certificate-identity "https://github.com/$repo/.github/workflows/ci.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
done

for file in "$binary" "$helper"; do
  line=$(awk -v name="$file" '$2 == name { match_line=$0; n++ } END { if (n != 1) exit 1; print match_line }' SHA256SUMS)
  printf '%s\n' "$line" | sha256sum -c - # On macOS use shasum -a 256 -c -
  gh attestation verify "$file" -R "$repo" --signer-workflow "$repo/.github/workflows/ci.yml" --source-ref "refs/tags/$tag"
done
```

On Windows, download the same files for Windows x64. Run the same
`cosign verify-blob` and `gh attestation verify` commands for each selected
file with the exact tag as shown above. For each executable, compare
`Get-FileHash -Algorithm SHA256 .\irmind-windows-x86_64.exe` (or the helper
filename) with its single exact line in the verified `SHA256SUMS`, ignoring
hexadecimal letter case. Stop if any check fails. See the
[GitHub attestation CLI](https://cli.github.com/manual/gh_attestation_verify)
and [Sigstore verification guide](https://docs.sigstore.dev/cosign/verifying/verify/).

Keep the verified executables in a versioned directory away from your
normal install. For use, name them `irmind` and `irmind-evtx` alongside
each other, with `.exe` on Windows. On Linux and macOS, make the verified
copies executable. Run the retained binary by its path with
`--home` set to the matching data directory. If you intend to bring
the evidence into a new case, re-ingest the verified originals.

## Delete a case from 0.7.x

For a signed deletion of an unsealed case, open the compatible data
directory with the producing 0.7.x binary and run [`/case delete`](cases.md#delete-an-unsealed-case).
It refuses to delete a sealed case.

**Manual deletion is irreversible.** Close all IRMind processes using the
data directory first. If you remove a case's `parquet/<case-id>` directory
by hand, you lose its case-local files and may still see its record in the
shared database. This produces no signed tombstone or recoverable case.
If the old data directory was dedicated to cases you want to discard, you
can remove that entire directory to discard its database, retained keys,
configuration and case files together. Verify what it contains first,
including copies or originals you still need. In a shared data directory,
use the producing binary for signed deletion of an individual unsealed case.
