# Native platform signing setup

For the release maintainer. Native macOS signing is **prepared, disabled and not
validated with a production certificate**. Existing releases have Sigstore
signatures and provenance, not Developer ID or Authenticode. No signing secrets
are created or installed by this change. See [CODE_SIGNING.md](../../CODE_SIGNING.md).

## macOS prerequisites

Use your Mac and Apple Developer Program account. The Account Holder creates a
**Developer ID Application** certificate (not Apple Development, Mac Distribution
or Developer ID Installer). In Keychain Access → Certificate Assistant → Request
a Certificate From a Certificate Authority, save a CSR. In Apple Developer →
Certificates, Identifiers & Profiles → Certificates → + → Developer ID Application,
upload the CSR, download the `.cer`, and import it on that same Mac. Expand the
certificate in Keychain Access → My Certificates; it must contain its private key.
Export that identity as a password-protected `.p12`. Keep an offline backup.
[Apple certificate instructions](https://developer.apple.com/help/account/certificates/create-developer-id-certificates/).

In App Store Connect → Users and Access → Integrations → App Store Connect API,
request API access if needed. Create a **team API key** with the least role allowed
for notarization (Developer), record Key ID and Issuer ID and download its `.p8`
once. Keep that key out of the repository. Validate permitted roles with your team
administrator; do not use an individual API key with the team-issuer command.
[Apple API keys](https://developer.apple.com/documentation/appstoreconnectapi/creating-api-keys-for-app-store-connect-api).

## Protected environment and secret names

Create GitHub environment **release**, require maintainer review, prevent self-review
where available and allow deployments only from selected **tags** `v*`, not branches.
Store these **environment secrets**, never repository-wide copies:

| Name | Value |
| --- | --- |
| `APPLE_SIGNING_CERTIFICATE_P12_BASE64` | Base64 of the exported `.p12`, without line breaks. |
| `APPLE_SIGNING_CERTIFICATE_PASSWORD` | Its export password. |
| `APPLE_SIGNING_IDENTITY` | Exact `Developer ID Application: … (TEAMID)` identity shown by `security find-identity -v -p codesigning`. |
| `APPLE_API_KEY_ID` | App Store Connect team API Key ID. |
| `APPLE_API_ISSUER_ID` | Its Issuer ID. |
| `APPLE_API_PRIVATE_KEY` | Complete contents of `AuthKey_<KEYID>.p8`. |

On your Mac, write the certificate's encoding into a private temporary file with
`umask 077; base64 -i DeveloperID.p12 | tr -d '\n' > certificate-base64.txt`.
Upload it through the environment's UI or stdin:

```sh
gh secret set APPLE_SIGNING_CERTIFICATE_P12_BASE64 --repo ns2switch/irmind --env release < certificate-base64.txt
gh secret set APPLE_API_PRIVATE_KEY --repo ns2switch/irmind --env release < AuthKey_KEYID.p8
```

Enter the other four values through GitHub's masked environment-secret form.
Do not paste them into chat, command arguments or an issue. Remove unencrypted
working copies after secure backup. This guide does not authorize the agent to
create secrets or activate the job.

**The job has a literal false gate; leave repository variable
`MACOS_NATIVE_SIGNING_ENABLED` unset too.** After a separate maintainer decision,
a reviewed change can remove the literal false gate and the variable can become
`true` for a future tag. The native job runs only
on a tag push and uses the protected environment; dispatches and PRs cannot use it.
When enabled, missing secrets, invalid signatures or failed notarization block
publication rather than falling back to an unsigned macOS package.

The job signs both CLI executables with hardened runtime and secure timestamps,
verifies them, creates a signed DMG, submits it with `notarytool` in wait mode, reviews
its issues and staples/verifies the DMG. The signed executables replace the raw
macOS release payloads **before** checksums, Sigstore and provenance are produced.
The optional DMG gets its own checksum, Sigstore bundle and provenance.

Apple cannot staple tickets to standalone command-line binaries. The DMG provides
the stapled offline-distribution ticket; raw executables rely on online ticket
lookup. Native validation on an ordinary quarantined Mac download remains required.
See [Apple's notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

## Windows / SignPath

[Issue #66](https://github.com/ns2switch/irmind/issues/66) has no recorded application
or acceptance. The maintainer must review [eligibility](https://signpath.org/terms),
submit [the application](https://signpath.org/apply), name release approvers and
agree the build/signing policy. IRMind is defensive investigation software; the
Foundation decides eligibility. No application is submitted automatically.

Provide the repository, MIT/Apache license, existing signed release URL, this
project's code-signing policy, CI/build provenance and the two Windows executables
(main and isolated helper). Wait for the organization's project/policy IDs and
approved integration before adding credentials or a SignPath action. Native signing
does not guarantee immediate SmartScreen reputation. Until then use the
[Windows verification instructions](../platforms.md#windows), without disabling OS controls.
