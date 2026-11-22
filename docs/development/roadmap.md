# Roadmap

IRMind is an agentic terminal assistant for incident response and digital forensics: an analyst talks with an agent that investigates local and remote evidence, loads forensic skills when needed, and delegates bounded work to parallel subagents. The model proposes, policy decides, and every action is signed.

[Español](../es/roadmap.md)

Launch preparation: [real-service validation](real-validation.md), [model evaluation](hunteval-model-benchmark.md) and [native signing setup](native-signing.md). These guides are procedures, not completed field validations.

This page is for contributors and evaluators. It describes intentions, not release commitments. Read the [security model](../security-model.md) before connecting a service.

Current pre-1.0 policy: minor versions may break formats without migration. V3 is the sole artifact layout in v0.3; compatibility statements in delivered-release sections describe those historical releases only.

## Delivered through v0.5.x

See the [changelog](../../CHANGELOG.md) for exact releases and format changes.
The following describes delivered capabilities, not field-validation claims.

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
  Fresh per-turn nonces and full logical token charging are unchanged. Later
  context-cost proposals remain deferred until after launch.

Skills never grant tools or scope, children never approve, and external/model
content never enters trusted system instructions. No model or connector is
enabled by default. Historical release designs explain old decisions; they are
not compatibility promises for the current executable.

## v0.5.x: Evaluation readiness and stabilization

- Measure real provider cache reuse with the first accounting increment. Keep fresh
  per-turn nonces and charge every logical token; defer later context-cost changes
  until after launch. No speculative warm-up or automatic routing changes.
- Rehearse the [real-service procedure](real-validation.md) with local Elasticsearch,
  TLS/CA verification and a local model. Record actual outcomes, errors and timings;
  this does not replace the analyst's real-model/connector validation.
- Exercise PTY interactions repeatedly under load with event-based synchronization,
  including first run, demo presentation, expansion and deletion.
- Publish verified Homebrew packaging. Maintain native macOS Intel and Linux
  aarch64, signed installers, exact-tag Sigstore verification, provenance and SBOM.
  AUR, Nix, winget and Scoop remain open to community maintainers.
- Activate prepared Developer ID/hardened-runtime signing and notarization only
  after the maintainer provisions the protected release environment and approves
  activation. Windows Authenticode signing remains pending; SignPath Foundation
  may be reevaluated after the public launch, alongside paid-service options.
  Provider selection and activation remain maintainer tasks; Sigstore does not
  replace native OS signing or reputation.
- Record the remaining H5 procedure details and a connector against a real test
  environment, and confirm experimental EVTX behavior on Windows 11. Do not infer
  these observations from scripted synthetic tests.
- Track stress ingestion, dense-entity queries and co-observation disk use as
  measured performance work; never change query/security limits to improve a score.

## Public launch

Publish an article, a synthetic-data demo video, community posts, a public HuntEval model benchmark, and an initial community skills catalog.

The public launch is the next milestone after v0.5.x stabilization. Publish only
measured validation claims; native signing, analyst validations and the catalog
remain explicit checklist items, not implied guarantees.

## v0.6: Source-side queries

Run structured, budgeted CloudTrail queries in Athena, Cloud Audit Logs in
BigQuery and queries on supported Azure Log Analytics tables in the Analytics
plan. Sign the result and retain it as derived evidence for local analysis.
Source-side queries in subagents and remote re-verification of cloud originals
remain follow-up work, along with additional datasets and providers.
See the [source query design](source-queries-design.md) and
[implementation contract](source-queries-format-contract.md).

## v0.7: Detection, reports, extensibility, and engine API

Add local detections, evidence-linked reports, controlled extensions, and a headless engine API.

- Prioritize dependency-scoped native mapping identities so unrelated lockfile
  updates leave reconstruction identities stable. [Design](native-mapping-build-identity.md).
- Execute Sigma rules over local Parquet without an LLM.
- Export Markdown and PDF reports that cite only confirmed evidence.
- Evaluate IRMind as a complete deployment through the HuntEval protocol.
- Add signed local hooks before or after tool calls, including an explicitly
  admitted status-bar script. The current status bar remains declarative and
  executes no external command.
- Offer an optional MCP client, disabled by default. Each MCP tool declares risk, passes through policy, and returns untrusted content; its design includes a threat model.
- Approve an engine API design before implementing the planned headless `serve` subcommand for `irmind`. The versioned protocol streams events over stdio, a Unix socket, or a Windows named pipe, with no open TCP listener by default. Keys stay inside IRMind: a client requests approval, the analyst confirms, and IRMind signs.

## 1.0 criteria

Stabilize signed formats, validate connectors, sign binaries, and complete external security review.

- Stable signed formats for cases, manifests, skills, subagent records, and the engine protocol, with tested migrations.
- Decide parser-version retention and stable-format compatibility when formats stabilize, expected around v0.6–v0.7, before 1.0. Until then, minor releases may break case, export and definition formats without migration; keep the creating executable or re-ingest verified originals.
- An external security review.
- At least three connectors validated against real test environments.
- Signed release binaries on Linux, macOS, and Windows.
- A reviewed threat model covering skills, subagents, MCP, and the engine API.

## Outside this repository

A graphical interface for multi-agent work, the unattended gateway, and watches belong in a separate repository. They consume IRMind through its engine API.

## Out of scope for now

Containment actions (`RiskLevel::Contain`) and external anchoring of case seals remain outside the current plan. No LLM or connector is enabled by default.
