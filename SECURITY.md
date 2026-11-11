[Spanish version](SECURITY.es.md)

# Security policy

This page is for anyone reporting a vulnerability in IRMind. The project is under development and is **not ready for real incidents or sensitive data**. Fixes target the latest pre-release and the default development branch. Older patches should be upgraded; prereleases are not production support commitments.

## Report a problem

Open a [GitHub issue](https://github.com/ns2switch/irmind/issues/new/choose) with the affected version or commit, expected behavior, and a minimal synthetic reproducer. Do not include credentials, real incident evidence, personal information, or operational details from a live environment.

If you need a private contact channel, open an issue requesting contact without technical details. A maintainer will arrange a suitable channel. Do not send secrets or real evidence to demonstrate a problem.

## Pre-1.0 fixes and publication

During pre-1.0 development, fixes use ordinary public pull requests, the normal CI checks, and `main`. The next release includes a concise technical changelog entry and identifies affected published versions when known. The project does not create or publish GitHub Security Advisories or temporary private forks for fixes.

This publication policy changes no runtime control. Policy ceilings, analyst approvals, ContentGuard, provenance, signatures, hashes, custody verification, TLS verification, isolation and resource limits remain mandatory. Fixes must retain their relevant regression tests and pass the normal integration checks.

Detailed analyst reports and environment-specific validation records remain private. Public pull requests describe behavior, tests, release-profile benchmarks and design choices without personal system information or credentials.

## Response targets

| Step | Target |
| --- | --- |
| Acknowledge receipt | Within 3 business days |
| Initial assessment and reporter update | Within 7 business days |
| Updates while open | At least every 14 days |
| Fix assessment and release planning | Initial target of 90 days from report; extensions communicated |

These are response targets, not a guarantee of a fix by a fixed date. We will update the reporter as assessment and fixes progress. We do not request or accept real evidence or secrets to reproduce a bug.

For design guarantees and residual risks, read the [security model](docs/security-model.md).

## Verify a release

Starting with v0.1.1, each release binary and `SHA256SUMS` has a keyless Sigstore bundle, and GitHub records provenance attestations for each binary. Verify the checksum, the Sigstore certificate identity `https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/<TAG>`, the issuer `https://token.actions.githubusercontent.com`, and `gh attestation verify <BINARY> -R ns2switch/irmind` before use. The [platform guide](docs/platforms.md#verify-a-release-before-installing) gives exact commands. Signatures and provenance do not replace review of the code or the security limits above. Apple notarization and Windows Authenticode are still absent.
