[Español](CODE_SIGNING.es.md)

# Code signing policy

IRMind releases are built from reviewed tag commits by the repository's pinned
GitHub Actions workflow. Maintainers approve release tags. Changes use DCO and the
normal CI checks; a release cannot bypass policy, custody, TLS or isolation tests.
The project signs only its own main CLI and isolated EVTX helper, plus the release
checksum list. Installers, licenses, SBOMs and audit inventories are bound by that
signed checksum list; binary and SBOM provenance is attested by GitHub Actions.

Sigstore keyless signing is active. Expected identities bind the exact repository,
workflow and release tag, as documented in [platforms](docs/platforms.md). No
persistent Sigstore private key is stored in this repository.

Developer ID Application signing, hardened runtime and notarization are prepared
but disabled until the maintainer provisions a protected `release` environment and
explicitly approves activation. SignPath Foundation Authenticode is pending an
application and acceptance. No current release claims those native signatures.
Only tag jobs may request native production credentials; PRs and branch rehearsals
cannot. A native signing failure blocks publication once enabled.

A signing approval attests origin and build process, not forensic correctness or
fitness for real incidents. The project remains pre-1.0 and evaluated principally
with synthetic data. See [SECURITY.md](SECURITY.md) and the
[maintainer setup guide](docs/development/native-signing.md).
