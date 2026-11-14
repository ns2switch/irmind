# Roadmap

IRMind is an agentic terminal assistant for incident response and digital forensics: an analyst talks with an agent that investigates local and remote evidence, loads forensic skills when needed, and delegates bounded work to parallel subagents. The model proposes, policy decides, and every action is signed.

[Español](../es/roadmap.md)

This page is for contributors and evaluators. It describes intentions, not release commitments. Read the [security model](../security-model.md) before connecting a service.

Current pre-1.0 policy: minor versions may break formats without migration. V3 is the sole artifact layout in v0.3; compatibility statements in delivered-release sections describe those historical releases only.

## Delivered in 0.1.0 and 0.1.1

The pre-releases provide the terminal case workflow, policy-gated connectors, signed custody, guarded model conversations, bounded Parquet queries, a synthetic demo, a parser detection registry, verified installers, and Sigstore-signed and attested assets. See the [changelog](../../CHANGELOG.md) for what shipped and its limitations. H5 is complete by analyst decision; unreported procedure details and validation of a real connector remain pending.

## v0.1.x: Stabilize the pre-release

Stabilize the pre-release with manual validation, verifiable installation, and signed assets.

- H5 is complete by analyst decision after a real DeepSeek greeting test. Record the remaining procedure details and test one connector against a real test environment. See the [validation record](manual-validation.md#result-record).
- Maintain Sigstore keyless signatures, GitHub artifact attestations, and an SBOM for release assets, delivered in v0.1.1.
- Sign macOS binaries with Developer ID, hardened runtime, and `notarytool` notarization in a protected release environment that runs only on tags. The maintainer must provision the certificate and App Store Connect API key before implementation; secrets are never configured through a roadmap issue.
- Apply to the SignPath Foundation open-source program for Windows Authenticode signing. Publish `CODE_SIGNING.md` to describe signed assets, release approval, and build provenance. The application is a maintainer task.
- Maintain checksum-verified install scripts and the Linux aarch64 binary, delivered in v0.1.1. Homebrew, AUR, Nix, winget, and Scoop packaging is open to community maintainers.
- Reduce co-observation disk use, improve `entity_lookup`, and bound worst-case three-hop `path` queries ([issue #37](https://github.com/ns2switch/irmind/issues/37)).

## v0.2: Parsers and precise evidence artifacts

Syslog and Linux exports are available as experimental modules. Linux covers authentication, bounded auditd correlation, journald JSON and common/combined HTTP logs. [Parser coverage and selection](../parsers.md) describes current limits.

Version 0.2 delivered detected log parsers, precise artifact V2, explicit precision migration and mixed-generation export V5. Those historical readers and migration commands belong to that release, not the current executable.

- Extend the detection registry delivered in v0.1.1. Each parser is a Cargo module activated only when its detector recognizes the log; ambiguous matches ask the analyst. A forced choice is audited.
- Add experimental parsers for Windows EVTX; syslog; Linux authentication, auditd, journald, nginx, and Apache logs; ECS; OCSF; Velociraptor; Hayabusa; Chainsaw; plaso; EZTools; Zeek; Suricata EVE; and a user-defined declarative format.
- Zeek and Suricata were not shipped in v0.1.x. Their restored modules preserve microseconds, use host-aware V2 partitions and retain bounded parser detection and provenance.
- Existing V1 cases stay readable without automatic migration. Explicit V1 → V2 precision migration is optional; retain verified originals and historical generations.
- Track remaining log formats as [good first issues](https://github.com/ns2switch/irmind/issues?q=is%3Aissue+label%3A%22good+first+issue%22).

Windows binary artifacts (registry hives, `$MFT`, Prefetch, LNK, SRUM and Amcache) are covered through processed EZTools, Velociraptor and plaso exports. See [current Windows coverage](../parsers.md#windows-coverage) for the supported input shapes. Demand will guide [future native registry and `$MFT` parsers](https://github.com/ns2switch/irmind/issues/159); both require the same isolated-helper model approved for EVTX, rather than binary decoders inside the main process.

## v0.3: Common events, one pipeline and SIEM connectors

The current source pipeline separates bounded format decoding from identified,
validated mapping. CLI, TUI and demo use mapped V3 artifacts and export V6.
Version 0.2 cases are not readable in 0.3: keep the creating executable or
[re-ingest verified originals into a new case](case-migration.md).

- Checked common-event types and fixed codes expose category, type, outcome and entity-role filters through the existing bounded evidence tools.
- Semantic mappings cover EVTX, Linux authentication/auditd/HTTP, CloudTrail, ECS and OCSF. DFIR exports, syslog, journald, Zeek, Suricata and declarative formats retain original fields and searchable extraction without inventing classifications. Community semantic mappings remain welcome.
- Every compiled parser has an original-field source decoder. Source sets, mapping profiles and run receipts bind its interpretation to signed artifacts; reconstruction uses those exact identities.
- The isolated EVTX helper decodes independent chunks concurrently with identical output across worker counts. Native containment remains required; Windows uses one verified network witness per session.
- Multicore ingestion follows available CPUs and a memory budget. Independent framing, pure record preparation and partition completion run in parallel; signed commits and record ordering remain deterministic. Ordered sources use bounded queues and disorder retains case-local sorting.
- Experimental Elastic and Google SecOps connectors use structured queries, explicit keystore credentials, full TLS verification, synthetic contracts and signed source evidence. No connector or model is enabled by default; real-service validation remains pending. Chronicle defaults to event-account filtering; explicit instance scope requires analyst confirmation, an organization ceiling and signed case context, with a persistent TUI warning.
- Keep release measurements for the nine 15 GB cloud/endpoint scenarios and all ordinary query deadlines. Track dense-entity, stress-sort and co-observation improvements separately from changes to security limits.

## v0.4: Forensic skills

The 0.4.2 pre-release includes 15 signed, progressively loaded forensic skills,
signed case budgets, native Kubernetes audit/Falco ingestion and semantic Entra,
GCP and network coverage. Each skill passes a scripted synthetic case with
confirmed findings and an independently verified export. Real-connector
validation, broader Windows collections and publication of the separate
community catalog remain follow-up work.

- The approved [skills design](skills-design.md), [installation contract](skills-installation-contract.md) and [case receipt contract](skills-case-format-contract.md) define the 0.4 implementation. See the [usage guide](../skills.md).
- A skill is a folder with `SKILL.md` for methodology and instructions, plus optional query templates, Sigma rules, or mappings. The core catalog covers AWS, Azure, GCP, Windows, Linux, network and Kubernetes. Windows triage, Linux triage and AWS credential compromise remain the initial methods; Windows ransomware and nine other methods arrived in 0.4.1, and two Kubernetes methods in 0.4.2. M365 business email compromise remains a possible community extension.
- Bundle [**Windows triage**](https://github.com/ns2switch/irmind/issues/157): guide a scoped, synthetic KAPE or Velociraptor collection of event logs, registry hives and related transaction logs, `$MFT`, Prefetch, LNK, SRUM and Amcache. Ingest direct EVTX with its verified isolated helper, Hayabusa timelines or EvtxECmd CSV first, then EZTools exports from PECmd, AmcacheParser, AppCompatCacheParser, MFTECmd, LECmd, RECmd batch and SrumECmd. Investigate logons → execution → persistence → lateral movement → exfiltration, correlate independent sources and confirm findings with evidence. Collection and external tools remain analyst-run; a skill grants no execution rights.
- Bundle **Linux triage** for authentication, execution and persistence, and **AWS credential compromise** for CloudTrail, role/session activity and IAM changes.
- `/budget` shows signed case consumption and allocations; `/settings limits` sets defaults for new cases below the organization ceiling. Kubernetes cluster identity is confirmed explicitly, and the source-reader contract permits verified original facts without projecting entire request bodies.
- The model initially sees only a skill's name and description; it loads full content when needed. Skills may be bundled, supplied by an organization, or installed by an analyst.
- Installation is signed, and the case log records the hash of the version used. A skill can declare needed tools but cannot extend permissions: policy and the organization ceiling decide. Signing admits exact package bytes; skill content stays untrusted even after admission and never enters system messages.
- Use `/skills` to list, install, inspect, update and disable skills. User-invocable skills appear as slash commands. Maintain a separate community skills repository.

## v0.5: Subagents and parallel work

Run bounded parallel subagents with Agent-key signatures and deterministic case records.

- Approve `docs/development/subagents-design.md` before implementation. It will define types, limits, Agent-key signing, approval routing, event branches, and deterministic merging.
- The main agent delegates bounded tasks to parallel subagents with separate contexts. Built-in types cover triage, cloud, endpoint, network, Kubernetes, and threat intelligence; community-defined types come from a file.
- Subagents inherit case scope and never extend it. They cannot approve calls; requests enter the analyst queue. They sign with the Agent key, and their output returns to the main agent as untrusted data.
- Enforce concurrency, round, and token limits per subagent and a total budget per turn. Show each subagent in the TUI and allow cancellation.
- Give each subagent an event branch and merge branches deterministically into the signed case chain so reports remain reproducible. Make the TUI a client of the engine's streamed events as preparation for the engine API.

## Public launch

Publish an article, a synthetic-data demo video, community posts, a public HuntEval model benchmark, and an initial community skills catalog.

The launch follows v0.5 and includes the separate community skills repository.

## v0.6: Source-side queries

Run structured, budgeted queries at cloud sources and sign their results.

The backends cover Athena, CloudTrail Lake, and Security Lake; BigQuery and Cloud Logging Log Analytics; and Azure Data Explorer and Log Analytics. Include scan estimates where available. Add remote re-verification of cloud originals after sealing. See the [query design](cloud-query-design.md).

## v0.7: Detection, reports, extensibility, and engine API

Add local detections, evidence-linked reports, controlled extensions, and a headless engine API.

- Execute Sigma rules over local Parquet without an LLM.
- Export Markdown and PDF reports that cite only confirmed evidence.
- Evaluate IRMind as a complete deployment through the HuntEval protocol.
- Add signed local hooks before or after tool calls.
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
