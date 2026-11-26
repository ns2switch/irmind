# Roadmap

IRMind is an agentic terminal assistant for incident response and digital forensics: an analyst talks with an agent that investigates local and remote evidence, loads forensic skills when needed, and delegates bounded work to parallel subagents. The model proposes, policy decides, and every action is signed.

[Español](../es/roadmap.md)

The roadmap tracks planned work. Read the [security model](../security-model.md)
before connecting a service. Under the pre-1.0 policy, minor releases may change
case, export and definition formats without migration. Keep the creating
executable or re-ingest the verified originals.

## Delivered

The [CHANGELOG](../../CHANGELOG.md) records published releases and format
changes. The entries below describe capabilities shipped in those releases.

### v0.7.x

- Native mapping identities use the V2 production dependency manifest.
  Dependency updates outside a mapping's build closure leave its identity
  unchanged. [Mapping identity design](native-mapping-build-identity.md).
- Local Sigma evaluates bounded rules on authenticated Parquet without a model.
  Signed runs retain the field bindings, exact row matches and coverage.
  [Sigma guide](../sigma.md).
- Signed Markdown and PDF reports cite evidence for analyst-confirmed findings
  and record limitations. Case marker 6 and export V10 carry the Sigma and
  report proofs. [Cases and exports](../cases.md).
- CloudTrail gzip deliveries are detected by content. Mixed deliveries retain
  the logs as evidence and identify and skip integrity digests with a notice.
  [Parser coverage](../parsers.md).

### v0.6.x

- Budgeted source-side queries for CloudTrail in Athena, Cloud Audit Logs in
  BigQuery and supported Azure Log Analytics tables on the Analytics plan.
  Queries are disabled by default. Signed captures become derived evidence for
  local analysis. The three adapters were exercised against simulators.
  [Design](source-queries-design.md) · [Format contract](source-queries-format-contract.md).
- Reproducible release builds for the main executable and the isolated EVTX
  helper on all five release targets. The signed `BUILD-ENVIRONMENT.json`
  records the exact toolchain versions used for each target.
  [Reproduction guide](../reproducible-builds.md).

### Delivered through v0.5.x

- Terminal cases, guarded conversations, policy-gated tools, signed custody,
  bounded Parquet queries, verified installers and an offline synthetic demo.
- Experimental parser modules with format detection, explicit ambiguity handling
  and isolated EVTX decoding. Windows binary artifacts are ingested through
  processed EZTools, Velociraptor and plaso exports; future native registry and
  `$MFT` decoders require isolated helpers. See [parser coverage](../parsers.md).
- The common-event pipeline separates bounded source decoding from identified
  mappings. Mapped V3 artifacts retain signed source sets, profiles and receipts;
  semantic category/outcome/role queries keep their existing limits. Multicore
  ingestion preserves deterministic ordering and signed artifacts.
- Experimental Elastic and Google SecOps connectors use structured read-only
  queries, explicit keystore credentials, full TLS verification and signed
  results. Live-service validation is still an analyst task. Chronicle instance
  scope remains explicit, confirmed, organization-bounded and visible in the TUI.
- Twenty-three progressively loaded forensic skills cover Windows, Linux, macOS,
  cloud, identity, email, web, network and Kubernetes investigations. The core
  methods live in [irmind-skills](https://github.com/ns2switch/irmind-skills),
  alongside the independently signed catalog of installable community packages.
- Version 0.5.5 expands offline decoding and mapping for identity and email,
  cloud findings and flow logs, endpoint and macOS, DNS and web access logs.
  The parser guide documents each export and its experimental coverage.
- Six bounded subagent types have separate contexts, signed branches, checkpoints,
  deterministic fusion, export V8 and visible/cancelable plans. Reservations above
  25% of remaining case tokens or calls require signed analyst confirmation;
  Preferences can require confirmation for every plan.
- Case budgets remain below the organization policy ceiling. Native model output
  maxima replace application token caps; admission happens between requests,
  actual usage and debt remain recorded. Model settings are saved together and
  connection testing uses the unsaved draft.
- Signed logical deletion of unsealed cases and a declarative, prioritized status
  bar are integrated for v0.5.2. Deletion retains signed tombstones, honors process
  locks and recovers interrupted cleanup; it is not secure physical erasure.
- Version 0.5.3 adds provider-reported cache accounting, trusted Anthropic prefix
  markers, explicit interprocess-safe plan recovery and macOS Intel packages.
  It retains per-turn nonces and charges every logical token. Version 0.5.4
  adds verified Homebrew packages and catalog signature verification.

Skills never grant tools or scope, children never approve, and external/model
content never enters trusted system instructions. No model or connector is
enabled by default. Historical release designs explain old decisions; they are
not compatibility promises for the current executable.

## Public launch

Publish the introduction, a synthetic-data demo video and community posts.
Report the validation that has been observed and document the remaining
checks. [Manual validation record](manual-validation.md).

## v0.7.x: Sigma coverage, rule packages and ingestion

1. Extend Sigma coverage. Start with compilation by source class, then broaden
   the reviewed bindings for Sysmon fields, `image_load` and `registry`, cloud
   tables with `requestParameters` and `responseElements`, and webserver and DNS
   logsources. Measure admission and exact compilation by family against the
   same hash-pinned SigmaHQ release.
   [SigmaHQ admission baseline](benchmarks/sigmahq-v070-admission.md).
2. Design installable Sigma rule packages with the same explicit installation
   model as forensic skills. The contract requires approval before
   implementation and will compare using the existing irmind-skills catalog
   and signing key with using a separate catalog and maintainer-generated key.

   - Sign the catalog index, pin versions by hash and reject version rollbacks.
   - Provide `/sigma list`, `/sigma info`, `/sigma install`, `/sigma update` and
     `/sigma remove`. Show the package's coverage against case sources in
     `/sigma info` and present the differences before signing an update.
   - Support explicit installation from the catalog or a local file with
     the same verification, preview and signed analyst admission rules as
     `/skills install`. Retain any proofs already referenced by a signed run
     when removing an installed package.
   - Installing a package grants no permissions and runs no rules. Each
     execution goes through signed admission for the case and remains subject
     to policy. Skills may recommend a package under the same policy.
   - Reference SigmaHQ releases by official URL and SHA-256 with Detection Rule
     License (DRL) 1.1 attribution. Keep SigmaHQ rule bytes out of the catalog.
     Require a declared license for community packs.
   - Validate every catalog package for admission, compilation, license and
     source coverage in CI.
3. Verify the CloudTrail digest chain as evidence of log integrity.
   [#428](https://github.com/ns2switch/irmind/issues/428).
4. Profile FDR, Unified Log and eslogger ingestion and design compact
   normalization for large Windows DNS debug and IIS W3C files.
   [Ingestion profiling #344](https://github.com/ns2switch/irmind/issues/344) ·
   [Compact storage #355](https://github.com/ns2switch/irmind/issues/355).

## v0.8: Extensibility, engine API, and validation

- Add signed local hooks around tool calls, including a status-bar script the
  analyst has explicitly admitted.
- Offer an optional MCP client, disabled by default. Each MCP tool declares
  risk, passes through policy, and returns untrusted content.
- Provide a versioned engine protocol for `serve` over stdio, a Unix
  socket, or a Windows named pipe. A client requests approval, the analyst
  confirms inside IRMind, and IRMind signs. TCP stays disabled by default.
  [Extensibility designs](https://github.com/ns2switch/irmind/pull/391).
- Add source-side queries for subagents and remote re-verification of original
  cloud objects.
- Evaluate IRMind as a complete deployment through HuntEval and publish the
  measured model benchmark. [#95](https://github.com/ns2switch/irmind/issues/95).
- Maintainer validation: run real source queries with Athena, BigQuery and
  Azure Log Analytics, validate Elastic over TLS with a private CA, and check
  isolated EVTX ingestion on Windows 11. Record outstanding H5 checks for hash
  citations, `/verify` and export verification.
  [Real-service procedure](real-validation.md) ·
  [Manual validation record](manual-validation.md) ·
  [Elastic #63](https://github.com/ns2switch/irmind/issues/63) ·
  [Windows 11 #189](https://github.com/ns2switch/irmind/issues/189) ·
  [H5 #340](https://github.com/ns2switch/irmind/issues/340).

## v0.9: Native Windows evidence, detection and interchange

- Add isolated native decoders for Windows registry hives, `$MFT`, Prefetch,
  LNK, Amcache and SRUM.
- Add local YARA scanning with bounded rule admission and execution, following
  the Sigma admission model.
- Export timelines with verifiable evidence citations for Timesketch and
  plaso-compatible super-timeline CSV. Export indicators of compromise (IOCs)
  with provenance in STIX and MISP formats.
- Extend local Sigma to correlation rules.
- Evaluate bounded, same-item projections for GCP `authorizationInfo` and
  Entra `targetResources` and `modifiedProperties`. The pinned compile audit
  estimates one additional GCP rule and three Azure rules. [Audit and scope](sigma-azure-result-type-contract.md).
- Ingest Volatility 3 outputs. [#158](https://github.com/ns2switch/irmind/issues/158).
- Decide when signed formats stabilize and how long to retain parser versions.

## Open decisions

- Decide whether to accept disk images (E01 or raw) and, if so, define the
  supported operations and custody model.
- Define multi-analyst work, including case handoff, a second signer and review.

## Work without a release assignment

- Schedule the deferred context-cost work and measure cache reuse with real
  providers after launch. [Context cost design](context-cost-design.md).
- Provision Apple Developer ID and approve notarization. Select a Windows
  Authenticode provider and reevaluate SignPath Foundation after launch.
  [Native signing setup](native-signing.md).
- Keep measuring stress ingestion, dense-entity queries and co-observation
  storage with the existing limits. [Benchmarks](benchmarks.md). Community
  maintainers can contribute additional package formats.

## 1.0 criteria

Stabilize signed formats, validate connectors, sign binaries, and complete external security review.

- Stable signed formats for cases, manifests, skills, subagent records, and the engine protocol, with tested migrations.
- Confirm the v0.9 decision on parser-version retention and stable-format compatibility before 1.0. Until then, minor releases may break case, export and definition formats without migration; keep the creating executable or re-ingest verified originals.
- An external security review.
- At least three connectors validated against real test environments.
- Signed release binaries on Linux, macOS, and Windows.
- A reviewed threat model covering skills, subagents, MCP, and the engine API.

## Outside this repository

A graphical interface for multi-agent work, the unattended gateway, and watches belong in a separate repository. They consume IRMind through its engine API.

## Out of scope for now

Containment actions (`RiskLevel::Contain`) and external anchoring of case seals remain outside the current plan. No LLM or connector is enabled by default.
