# Roadmap

IRMind is an agentic terminal assistant for incident response and digital forensics: an analyst talks with an agent that investigates local and remote evidence, loads forensic skills when needed, and delegates bounded work to parallel subagents. The model proposes, policy decides, and every action is signed.

[Español](../es/roadmap.md)

This page is for contributors and evaluators. It describes intentions, not release commitments. Read the [security model](../security-model.md) before connecting a service.

## Delivered in 0.1.0 and 0.1.1

The pre-releases provide the terminal case workflow, policy-gated connectors, signed custody, guarded model conversations, bounded Parquet queries, a synthetic demo, a parser detection registry, verified installers, and Sigstore-signed and attested assets. See the [changelog](../../CHANGELOG.md) for what shipped and its limitations. Manual model and live connector validation remain open.

## v0.1.x: Stabilize the pre-release

Stabilize the pre-release with manual validation, verifiable installation, and signed assets.

- Validate H5 manually with DeepSeek and test one connector against a real test environment.
- Maintain Sigstore keyless signatures, GitHub artifact attestations, and an SBOM for release assets, delivered in v0.1.1.
- Sign macOS binaries with Developer ID, hardened runtime, and `notarytool` notarization in a protected release environment that runs only on tags. The maintainer must provision the certificate and App Store Connect API key before implementation; secrets are never configured through a roadmap issue.
- Apply to the SignPath Foundation open-source program for Windows Authenticode signing. Publish `CODE_SIGNING.md` to describe signed assets, release approval, and build provenance. The application is a maintainer task.
- Maintain checksum-verified install scripts and the Linux aarch64 binary, delivered in v0.1.1. Homebrew, AUR, Nix, winget, and Scoop packaging is open to community maintainers.
- Reduce co-observation disk use, improve `entity_lookup`, and bound worst-case three-hop `path` queries ([issue #37](https://github.com/ns2switch/irmind/issues/37)).

## v0.2: Parsers and connectors

Add detected log parsers and read-only structured-query connectors.

- Extend the detection registry delivered in v0.1.1. Each parser is a Cargo module activated only when its detector recognizes the log; ambiguous matches ask the analyst. A forced choice is audited.
- Add experimental parsers for Windows EVTX; syslog; Linux authentication, auditd, journald, nginx, and Apache logs; ECS; OCSF; Velociraptor; Hayabusa; Chainsaw; plaso; EZTools; Zeek; Suricata EVE; and a user-defined declarative format.
- Add experimental `siem-elastic` and `siem-chronicle` connectors with structured queries, minimum read permissions, synthetic contracts, and signed evidence. Community connector requests include Microsoft Sentinel and Wazuh.
- Track remaining log formats as [good first issues](https://github.com/ns2switch/irmind/issues?q=is%3Aissue+label%3A%22good+first+issue%22).

## v0.3: Forensic skills

Add signed, progressively loaded forensic skills that never extend policy permissions.

- Approve `docs/development/skills-design.md` before implementation. It will define format, progressive loading, signed installation, trust, and policy interaction.
- A skill is a folder with `SKILL.md` for methodology and instructions, plus optional query templates, Sigma rules, or mappings. Initial examples cover Windows ransomware triage, AWS credential compromise, Linux persistence, and M365 business email compromise.
- The model initially sees only a skill's name and description; it loads full content when needed. Skills may be bundled, supplied by an organization, or installed by an analyst.
- Installation is signed, and the case log records the hash of the version used. A skill can declare needed tools but cannot extend permissions: policy and the organization ceiling decide. Third-party content stays untrusted until the analyst signs it.
- Add `/skills` to list, install, inspect, and disable skills. User-invocable skills appear as slash commands. Maintain a separate community skills repository.

## v0.4: Subagents and parallel work

Run bounded parallel subagents with Agent-key signatures and deterministic case records.

- Approve `docs/development/subagents-design.md` before implementation. It will define types, limits, Agent-key signing, approval routing, event branches, and deterministic merging.
- The main agent delegates bounded tasks to parallel subagents with separate contexts. Built-in types cover triage, cloud, endpoint, network, and threat intelligence; community-defined types come from a file.
- Subagents inherit case scope and never extend it. They cannot approve calls; requests enter the analyst queue. They sign with the Agent key, and their output returns to the main agent as untrusted data.
- Enforce concurrency, round, and token limits per subagent and a total budget per turn. Show each subagent in the TUI and allow cancellation.
- Give each subagent an event branch and merge branches deterministically into the signed case chain so reports remain reproducible. Make the TUI a client of the engine's streamed events as preparation for the engine API.

## Public launch

Publish an article, a synthetic-data demo video, community posts, a public HuntEval model benchmark, and an initial community skills catalog.

The launch follows v0.4 and includes the separate community skills repository.

## v0.5: Source-side queries

Run structured, budgeted queries at cloud sources and sign their results.

The backends cover Athena, CloudTrail Lake, and Security Lake; BigQuery and Cloud Logging Log Analytics; and Azure Data Explorer and Log Analytics. Include scan estimates where available. Add remote re-verification of cloud originals after sealing. See the [query design](cloud-query-design.md).

## v0.6: Detection, reports, extensibility, and engine API

Add local detections, evidence-linked reports, controlled extensions, and a headless engine API.

- Execute Sigma rules over local Parquet without an LLM.
- Export Markdown and PDF reports that cite only confirmed evidence.
- Evaluate IRMind as a complete deployment through the HuntEval protocol.
- Add signed local hooks before or after tool calls.
- Offer an optional MCP client, disabled by default. Each MCP tool declares risk, passes through policy, and returns untrusted content; its design includes a threat model.
- Approve an engine API design before implementing a headless `serve` subcommand in the IRMind CLI. The versioned protocol streams events over stdio, a Unix socket, or a Windows named pipe, with no open TCP listener by default. Keys stay inside IRMind: a client requests approval, the analyst confirms, and IRMind signs.

## 1.0 criteria

Stabilize signed formats, validate connectors, sign binaries, and complete external security review.

- Stable signed formats for cases, manifests, skills, subagent records, and the engine protocol, with tested migrations.
- An external security review.
- At least three connectors validated against real test environments.
- Signed release binaries on Linux, macOS, and Windows.
- A reviewed threat model covering skills, subagents, MCP, and the engine API.

## Outside this repository

A graphical interface for multi-agent work, the unattended gateway, and watches belong in a separate repository. They consume IRMind through its engine API.

## Out of scope for now

Containment actions (`RiskLevel::Contain`) and external anchoring of case seals remain outside the current plan. No LLM or connector is enabled by default.
