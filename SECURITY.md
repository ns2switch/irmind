[Spanish version](SECURITY.es.md)

# Security policy

This page is for anyone reporting a vulnerability in IRMind. The project is under development and is **not ready for real incidents or sensitive data**. We review reports affecting the current public branch; no production release is supported yet.

## Report privately

Do not post vulnerabilities, exploit details, real incident data, or secrets in public issues or pull requests. On GitHub, use **Security → Advisories → Report a vulnerability** to submit a private report through Private Vulnerability Reporting. Include the affected commit or version, impact, steps to reproduce with synthetic data, and a contact method.

If the private reporting button is unavailable, open an issue asking for that channel to be enabled **without technical details of the vulnerability**. This file does not enable the GitHub feature by itself.

## Response targets

| Step | Target |
| --- | --- |
| Acknowledge receipt | Within 3 business days |
| Initial assessment and reporter update | Within 7 business days |
| Updates while open | At least every 14 days |
| Coordinated fix and disclosure | Initial target of 90 days from report; extensions communicated |

These are response targets, not a guarantee of a fix by a fixed date. We will coordinate an advisory with the reporter when a verifiable mitigation exists. We do not request or accept real evidence or secrets to reproduce a bug.

For design guarantees and residual risks, read the [security model](docs/security-model.md).

## Verify a release

Starting with v0.1.1, each release binary and `SHA256SUMS` has a keyless Sigstore bundle, and GitHub records provenance attestations for each binary. Verify the checksum, the Sigstore certificate identity `https://github.com/ns2switch/irmind/.github/workflows/ci.yml@refs/tags/<TAG>`, the issuer `https://token.actions.githubusercontent.com`, and `gh attestation verify <BINARY> -R ns2switch/irmind` before use. The [platform guide](docs/platforms.md#verify-a-release-before-installing) gives exact commands. Signatures and provenance do not replace review of the code or the security limits above. Apple notarization and Windows Authenticode are still absent.
