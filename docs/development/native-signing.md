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

The maintainer has submitted the SignPath Foundation application. Acceptance and
integration configuration are pending; Authenticode is not active. The
[code signing policy](../../CODE_SIGNING.md) identifies the team and requires
manual approval of every signing request. The Foundation decides eligibility.

Provide the repository, MIT/Apache license, existing signed release URL, this
project's code-signing policy, CI/build provenance and the two Windows executables
(main and isolated helper). Wait for the organization's project/policy IDs and
approved integration before adding credentials or a SignPath action. Native signing
does not guarantee immediate SmartScreen reputation. Until then use the
[Windows verification instructions](../platforms.md#windows), without disabling OS controls.

## Check a native-signed candidate on macOS

Run these commands on a normally downloaded candidate, without removing its
quarantine attribute. Use the exact filenames of that release:

```sh
codesign --verify --strict --verbose=2 ./irmind
codesign --verify --strict --verbose=2 ./irmind-evtx
codesign -dv --verbose=4 ./irmind
spctl --assess --type execute --verbose=4 ./irmind
xcrun stapler validate ./IRMind-macos-aarch64.dmg
spctl --assess --type open --context context:primary-signature --verbose=4 ./IRMind-macos-aarch64.dmg
```

The identity must match the approved Developer ID, and the displayed code-signing
flags must include the hardened runtime. Both assessments and DMG ticket
validation must succeed. Test the stapled DMG offline as well. Raw CLI files
cannot carry a stapled ticket; assess them with network access. Record the macOS
version, candidate tag and outcomes. Current releases without native signing
are not expected to pass these native assessments.

## SignPath integration preparation (inactive)

The release workflow marks the integration point immediately before SBOM
creation. A future dedicated signing job must run only for a published tag's
push, use the protected `release` environment and submit both Windows executables
from that run's GitHub Actions artifact. Every request requires Anibal Cañada's
manual approval in SignPath. PRs and branch/manual rehearsals cannot request
production signing. Replace the staged Windows files with the approved, verified
Authenticode output before generating SHA256SUMS, Sigstore signatures and
provenance. A rejected, timed-out or invalid request must fail publication.

No SignPath action runs today. After the
Foundation approves the project and provides its configuration, prepare:

| Environment `release` setting | Purpose |
| --- | --- |
| Secret `SIGNPATH_API_TOKEN` | Foundation-provided submission credential for this project; never the approver's interactive credentials. |
| Variable `SIGNPATH_ORGANIZATION_ID` | Organization identifier. |
| Variable `SIGNPATH_PROJECT_SLUG` | Approved project identifier. |
| Variable `SIGNPATH_SIGNING_POLICY_SLUG` | Policy that requires manual approval for release signing. |
| Variable `SIGNPATH_ARTIFACT_CONFIGURATION_SLUG` | Configuration restricting signing to the two project executables and their IRMind product/version metadata. |

The identifiers are configuration, not private keys. The Foundation retains the
certificate's signing key; no Windows PFX or certificate password belongs in this
repository. The action can use the job's existing `GITHUB_TOKEN` to read its
artifact and build metadata; no additional GitHub PAT is planned. Pin the official
SignPath action to a reviewed full commit when the integration is implemented.
See the [official GitHub integration](https://docs.signpath.io/trusted-build-systems/github).
Setting any of these values alone does not activate signing: a reviewed workflow
change and explicit maintainer activation are still required.

Suggested project description:

> IRMind is an open-source terminal assistant for defensive incident response
> and forensic analysis. Analysts inspect local or explicitly configured remote
> evidence. Policy and analyst approvals govern tool use, and case records are
> signed. The Windows release contains the main CLI and an isolated EVTX decoder.
> Builds run from reviewed source in pinned GitHub Actions workflows and include
> checksums, Sigstore signatures, provenance and SBOMs.

The [Foundation's conditions](https://signpath.org/terms) require explicit team
roles, privacy disclosures, verifiable builds and approval of each signing
request. [CODE_SIGNING.md](../../CODE_SIGNING.md) identifies the project roles
and current signing status. The attribution identifies the intended Windows signing service; the policy explicitly states that integration is not active.
Windows product-name/version metadata and SignPath artifact restrictions must
be checked during integration; the policy alone does not establish compliance.
Any integration credentials and activation require a separate maintainer action.
