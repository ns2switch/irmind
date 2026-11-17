[Español](CODE_SIGNING.es.md)

# Code signing policy

## Attribution

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/)

This attribution applies to Windows Authenticode signing of IRMind's own
`irmind.exe` and isolated EVTX helper, `irmind-evtx.exe`. The maintainer has
submitted the Foundation application; approval and integration are pending.
**SignPath signing is not active. Current Windows releases do not carry SignPath
Authenticode signatures.** Linux and macOS binaries use keyless Sigstore signing.
Apple Developer ID Application signing, hardened runtime and notarization for
macOS are prepared but disabled until separately provisioned and activated.

## Team roles

- Committers and reviewers: Anibal Cañada (@ns2switch)
- Approvers: Anibal Cañada (@ns2switch)

The project account is [@ns2switch](https://github.com/ns2switch). Every SignPath
signing request requires manual approval by the approver for a published release
tag. GitHub Actions builds the binary from the public source code of that exact
tag; the workflow cannot approve its own signing request. Team members must use
multi-factor authentication for GitHub and SignPath access.

Contributions use DCO and normal review and CI checks. Release approval does not
bypass policy, custody, TLS, isolation or resource-limit tests. Additional signing
approvers must be identified in this policy before activation.

## Privacy policy

IRMind does not include telemetry. This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

When the analyst explicitly configures and approves a model provider (DeepSeek,
Anthropic, OpenAI, OpenRouter or another compatible provider) or connector
(Splunk, Elastic, Chronicle, VirusTotal, MISP or cloud services), data sent to that
service is subject to its provider's privacy policy. Review those terms before
sending case data. Configuration does not bypass policy, case scope, the
organization ceiling or required analyst approvals. Skills and subagents cannot
extend these permissions.

Explicit catalog downloads and updates are also user-requested network activity;
there are no automatic skill downloads or updates. The demo does not contact any
service: it uses a scripted model, simulated external lookups, synthetic data and
temporary keys.

## What is signed and how it is built

The project signs only its own CLI and isolated EVTX helper. Windows release
asset names include platform suffixes; the installed files are `irmind.exe` and
`irmind-evtx.exe`. The future SignPath artifact configuration must restrict signing
to those executables and enforce the IRMind product name and matching release
version on both files.

The repository's commit-pinned GitHub Actions workflow builds reviewed release
tags with locked dependencies. Only tag jobs may request native production
credentials; PRs and branch rehearsals cannot. SignPath will use the protected
`release` environment with manual approval for every signing request. Once
activated, rejection, timeout or invalid signing output blocks publication rather
than falling back to files without native signatures.

Native signing finishes before checksums, Sigstore and provenance, so they bind
the final downloadable bytes. Sigstore signs every release binary and
`SHA256SUMS`; that signed list also binds installers, licenses, SBOMs and
unsafe-code inventories. GitHub Actions attests binary and SBOM provenance.
No persistent Sigstore private key is stored in this repository.

## Verify a release

Before executing a download, follow the [platform verification guide](docs/platforms.md#verify-a-release-before-installing):
verify its checksum, the Sigstore bundle's exact repository/workflow/tag identity
and issuer, and its GitHub provenance. Verify the EVTX helper independently.

After SignPath is activated, also check both Windows executables with
PowerShell's `Get-AuthenticodeSignature`: require `Status` to be `Valid` and the
signer to match the Foundation certificate documented for that release. This
policy does not add Authenticode signatures retroactively to existing releases.

Signing attests origin and build process, not forensic correctness or fitness for
real incidents. IRMind remains pre-1.0 and evaluated principally with synthetic
data. See [SECURITY.md](SECURITY.md) and the
[native-signing setup guide](docs/development/native-signing.md).
