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

## Responsibilities and privacy

Contributors submit DCO-signed changes; repository maintainers review them.
The repository owner, [ns2switch](https://github.com/ns2switch), approves release
tags and future native signing requests. Additional signing approvers must be
identified explicitly before activation. SignPath integration must retain manual
approval for every signing request and confirm MFA for the participating team.

IRMind contacts a remote model, connector or catalog only through the analyst's
explicit configuration and actions. The analyst must review the selected
provider's privacy terms before sending case data. Skills and subagents do not
expand policy, case scope or approvals.

SignPath acceptance, Foundation attribution, Windows product/version metadata
checks and service-specific artifact restrictions remain integration prerequisites.
This policy does not claim that a SignPath application has been accepted or that
current Windows files carry Authenticode signatures.
