[Español](CODE_SIGNING.es.md)

# Code signing policy

## Current signing status

IRMind release binaries for Linux, macOS and Windows, including the isolated EVTX
helper, have keyless Sigstore signatures and SHA-256 checksums. GitHub Actions
provides build-provenance attestations and SBOMs for the main program and helper.
The signed `SHA256SUMS` also authenticates installers, licenses and audit inventories.

**Windows binaries do not currently have Authenticode signatures.** Browser
downloads can display a SmartScreen warning or an unknown publisher. Sigstore
verification does not supply Windows reputation or override operating-system
controls. Apple Developer ID Application signing, hardened runtime and notarization
are prepared but disabled; they apply only after explicit maintainer activation.

## Team roles

- Committers and reviewers: Anibal Cañada (@ns2switch)
- Approvers: Anibal Cañada (@ns2switch)

The project account is [@ns2switch](https://github.com/ns2switch). The maintainer
approves release tags. GitHub Actions builds the main executable and isolated
helper from the public source code of that exact tag with locked dependencies
and commit-pinned actions. Contributions use DCO, review and CI checks. Team
members must use multi-factor authentication for GitHub access.

Release approval does not bypass policy, custody, TLS, isolation or resource-limit
tests. Any future native-signing integration requires separate review, identified
approvers and protected tag-only credential access before activation.

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

Each current release signs the main executable and isolated EVTX helper for every
published platform with GitHub Actions OIDC and Sigstore. The installed Windows
files are `irmind.exe` and `irmind-evtx.exe`; release assets have platform suffixes.
GitHub Actions attests binary and SBOM provenance. No persistent Sigstore private
key is stored in this repository.

If native signing is activated in the future, it must finish before checksums,
Sigstore and provenance are generated so they bind the final downloadable bytes.
That integration must fail publication on rejection, timeout or invalid output,
without an unsigned fallback after native signing has been required. Native
Windows signing remains a future option, not a current release feature.

## Verify and install a release

Before executing a download, follow the [platform verification guide](docs/platforms.md#verify-a-release-before-installing):
verify the checksum, the Sigstore bundle's exact repository/workflow/tag identity
and issuer, and GitHub provenance. Verify the EVTX helper independently.

On Windows, verify the downloaded `install.ps1` against the authenticated
`SHA256SUMS`, then run it from PowerShell with the exact release version:

```powershell
./install.ps1 -Version v0.5.4
```

With current cosign and GitHub CLI available, the installer verifies the binaries'
Sigstore signatures and provenance as well as their hashes before installation.
It installs both executables for the current user without administrator privileges
or a silent PATH change. Without those verification tools, it explains the
additional manual checks. Follow organizational policy if Windows blocks an
unsigned download; do not disable SmartScreen or other protections globally.

Signing attests origin and build process, not forensic correctness or fitness for
real incidents. IRMind remains pre-1.0 evaluation software. See
[SECURITY.md](SECURITY.md), the [validation record](docs/development/manual-validation.md#result-record)
and the [native-signing setup guide](docs/development/native-signing.md).
