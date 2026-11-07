# Common event schema

This design is for parser, connector and evidence-store maintainers. It proposes a typed event contract so analysts can ask the same question across cloud, endpoint and network evidence. It does not implement a parser, change signed formats, authorize credentials or enable a provider.

## Delivery sequence

The typed core is delivered separately from parser mappings. The first mapping group covers EVTX, Linux authentication/auditd, CloudTrail, ECS, OCSF, Zeek and Suricata. Remaining mappings are community tasks. Semantic migration (`CommonEventMigrationV1`) is deferred: existing cases remain readable and re-ingestion into a new case is the current alternative. The migration section below records a future design, not an implemented transformation.

## Recommendation and scope

Adopt **`irmind-common-event-v1`**, a bounded subset of [ECS 9.5.0](https://github.com/elastic/ecs/tree/v9.5.0/schemas), with explicit provenance, time precision and entity roles. ECS names describe the logical view; Rust types enforce its invariants. This is an IRMind schema inspired by ECS, not a claim of complete ECS compatibility. Future ECS releases do not change this contract automatically.

The proposal has four independently versioned parts:

| Part | Proposed identity | Responsibility |
| --- | --- | --- |
| Logical event | `irmind-common-event-v1` | Field meanings, closed classifications, bounds and validation. |
| Mapping | Each module's new parser/normalizer version | Source-specific interpretation, including outcome and roles. |
| Physical artifacts | `irmind-events-v4`, `irmind-entities-v4`, `irmind-coobservations-v3` | New columns and their stable encodings. These names are proposed, not registered. |
| Builder | A new, pinned builder identity | Deterministic construction and reconstruction of the new physical schemas. |

Do not add columns under historical schema names or infer a schema version from whichever fields happen to exist in JSON. Do not combine this change with the separate [bounded-metadata writer proposal](parquet-bounded-metadata-design.md), or make its approval implicit here.

## Current contract and design boundaries

The baseline is [main at `8eb3857`](https://github.com/ns2switch/irmind/tree/8eb3857eb3094b3c392a669065205b289646d814). [`GraphRecord`](../../crates/app/src/ingest.rs) exposes an action string, a text string, role-free entity pairs and optional relations. `IndexedGraphRecord` adds exact time and offset. Parsers emit tainted records through [`StreamingEventParser`](../../crates/app/src/ports/local.rs); no shared typed event currently validates their JSON field conventions.

The current [V2 envelope](../../crates/domain/src/custody_manifest/artifact_v2.rs) admits exactly `irmind-events-v3`, `irmind-entities-v3` and `irmind-coobservations-v2`. Its [writer](../../crates/infra/src/parquet_store/writer/precise.rs) preserves microseconds, residual nanoseconds, precision, inference and scope columns. These identifiers and historical bytes remain unchanged.

The [migration contract](parquet-v2-migration-contracts.md) currently pins parser versions and requires non-time normalized meaning to remain identical. Adding classifications and roles is a semantic change. It cannot be presented as the already approved precision-only migration.

Zeek and Suricata are included below as mapping targets. Their parser modules are not present in this baseline; the table does not claim they are delivered. Elastic and Chronicle mapping work follows the event-schema decision.

## Logical event fields

Fields are optional unless the table says otherwise. Absence means the source did not provide a supported value; it never means zero, the current time, success or permission to infer one. An absent group is different from an object full of fabricated defaults.

| Field set | Included in V1 | Why and constraints |
| --- | --- | --- |
| Schema and provenance | Required schema ID; source hash, record number, optional real byte offset; parser ID/version; raw-record reference | Tie every normalized value to authenticated input. Source paths remain references, never executable paths. Parser identity is corroborated by signed manifests, not accepted from input. |
| `@timestamp` | Optional existing `IndexedTime`, including precision and inference | Reuse UTC microseconds plus residual nanoseconds and the shared stable comparator. Missing times stay missing. No clock or mtime fallback. |
| `event` | Required bounded `category` and `type` sets; optional original `action`, `id`, `code`, `dataset`; required `outcome`; kind restricted to event, alert or state | Cross-source filtering; native event codes support Windows and Sigma. Empty classification sets represent unmapped activity. A source alert is not a confirmed case finding. |
| `host` | `id`, `name`, `hostname`, `domain`, `os.type` | Separate the affected host from a sensor or collector. Preserve identity spelling; partition normalization must not merge graph identities. |
| `user` and `user.target` | `id`, `name`, `domain`; optional effective identity in `user.effective` | Actor, managed account and effective account must not collapse into one user. A SID, UID or ARN is an identifier, not automatically a display name. |
| `source`, `destination` | `ip`, `port`, `domain`, optional endpoint user | Validated IP address, port 0–65535, bounded domain. Ports are absent when not supplied; zero is not a missing-value sentinel. Source/destination describe the logged observation, not inferred intent. |
| `process`, `process.parent` | `name`, `pid`, `entity_id`, `executable`, `command_line`, `hash.md5`, `hash.sha1`, `hash.sha256` | Execution and ancestry pivots. Parent is one nonrecursive process descriptor. A PID alone is not a global process identity. Command lines are untrusted and may contain secrets. |
| `file` | `path`, `name`, `extension`, `size`, hash set; optional created/modified/accessed times with precision | File access and artifact inventories. A path is evidence text, never a request to open that path. A filesystem time alone does not prove execution. |
| `registry` | `hive`, `key`, `path`, `value`; bounded `data.type` and `data.strings` | Windows configuration and persistence. Do not interpret or execute stored values. Binary bodies stay in the original. |
| `dns` | Question name/type/class, response code, bounded answer name/type/data list | DNS pivots and response interpretation. Query and answer roles stay distinct. No resolver call or enrichment. |
| `url` | `original`, `full`, `scheme`, `domain`, `port`, `path`, `query` | Web investigation; retain source form separately from parsed components. Never open a URL. Credentials in evidence URLs remain local untrusted evidence and are redacted before display/model use. |
| `http` | `request.method`, `response.status_code`, `version`, request/response byte counts; `user_agent.original` alongside HTTP | Web outcomes and application pivots. No request/response bodies, cookies, authorization headers or active fetching in the common projection. |
| `cloud` | `account.id`, `project.id`, `region`, `provider`, `service.name` | Distinguish AWS account, GCP project and Azure subscription-as-account. Never populate a configured account into an event that did not report it. ECS has separate account and project fields. |
| `network` | `transport`, `protocol`, `direction`, byte/packet counts, optional community ID; namespaced source flow reference | Flow correlation. Unknown protocol names remain bounded source values; direction is a closed enum with unknown. A Zeek UID or Suricata flow ID is scoped to its sensor/source, not globally unique. |
| Original and extensions | Required original-record reference; bounded, namespaced extra attributes outside the typed core | Retain unmapped source fields without making them an alternate common schema. The original is available under existing record/source limits; do not duplicate a large raw tree inside the domain object. |

The [ECS field reference](https://www.elastic.co/docs/reference/ecs/ecs-field-reference), [cloud fields](https://www.elastic.co/docs/reference/ecs/ecs-cloud) and [process fields](https://www.elastic.co/docs/reference/ecs/ecs-process) are the naming references. The typed projection does not include every field in those sets.

Keep minimal detection metadata (`rule.id`, `rule.name`, source severity and source finding ID) in a bounded detection descriptor linked to the event. Preserve ATT&CK assertions as untrusted source assertions; they become reportable case techniques only through the existing analyst-confirmation workflow. Cloud resource IDs, IAM roles, key IDs, sessions and collector references remain typed entity observations even where ECS has no suitable field in this subset. Never index a secret key's material as a key ID.

Exclude GeoIP/ASN enrichment, vulnerability inventories, full email/M365 models, container/Kubernetes inventories, PE/ELF structures, arbitrary TLS certificates, packet payloads, environment-variable dumps and computed risk scores from the first typed projection. They remain in bounded original attributes where supplied. They need separate mappings and semantics; importing all ECS field sets would add validation and storage cost without proven parser coverage.

### Closed categorization and outcome

Use the ECS 9.5.0 category values as a closed set: `api`, `authentication`, `configuration`, `database`, `driver`, `email`, `file`, `host`, `iam`, `intrusion_detection`, `library`, `malware`, `network`, `package`, `process`, `registry`, `session`, `threat`, `vulnerability`, `web`. These are sets, not a single best category. Multiple categories are useful for a network detection or an authentication/session event. See [category semantics](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-category).

Use the closed type set: `access`, `admin`, `allowed`, `change`, `connection`, `creation`, `deletion`, `denied`, `device`, `end`, `error`, `group`, `indicator`, `info`, `installation`, `protocol`, `start`, `user`. See [type semantics](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-type). Serialize sets uniquely in lexical order; unknown input labels stay in original attributes and generate a bounded mapping diagnostic. They are never admitted as new enum variants at runtime. An empty category/type set is valid; neither set invents an `unknown` ECS label.

`event.action` retains the source action verb or operation code. Do not replace it with an English label chosen by a heuristic. If no action exists, leave it absent and use a presentation-only fallback. `event.code` retains a Windows event ID or equivalent code; it is not the record's unique identity.

Outcome is exactly **success, failure or unknown**. Missing status maps to unknown. Apply a pinned source-specific status table; do not classify arbitrary text containing "failed". A denied connection is `event.type=denied`; it is not automatically a failure of the security product that successfully blocked it. An alert's severity or maliciousness is not an outcome. These distinctions follow the [ECS event semantics](https://www.elastic.co/docs/reference/ecs/ecs-event).

### Rust domain contract

Place pure value types and validation in `irmind-domain`, using only `std`. Keep serde decoding, CSV/regex adaptation, canonical JSON encoding and parser ports in application/adapters. This is an API sketch, not executable code added by this proposal; referenced component types are defined by the table and constraints above.

```rust
pub struct CommonEventV1 {
    origin: EventOrigin,
    timestamp: Option<IndexedTime>,
    event: EventHeaderV1,
    context: EventContextV1,
    observations: BoundedObservations,
}

pub struct EventHeaderV1 {
    categories: CategorySet,
    types: EventTypeSet,
    action: Option<EventAction>,
    outcome: EventOutcome,
    kind: EventKind,
    code: Option<EventCode>,
    id: Option<SourceEventId>,
    dataset: Option<DatasetId>,
}

pub enum EventOutcome { Success, Failure, Unknown }

pub struct EventContextV1 {
    host: Option<HostFields>,
    users: UserFields,
    source: Option<EndpointFields>,
    destination: Option<EndpointFields>,
    process: Option<ProcessFields>,
    file: Option<FileFields>,
    registry: Option<RegistryFields>,
    dns: Option<DnsFields>,
    url: Option<UrlFields>,
    http: Option<HttpFields>,
    cloud: Option<CloudFields>,
    network: Option<NetworkFields>,
    detection: Option<DetectionFields>,
}

impl CommonEventV1 {
    pub fn try_new(
        origin: EventOrigin,
        timestamp: Option<IndexedTime>,
        event: EventHeaderV1,
        context: EventContextV1,
        observations: BoundedObservations,
    ) -> Result<Self, EventSchemaError>;
}
```

Fields stay private, with checked constructors and borrowed accessors. Component constructors validate their own invariants; the final constructor checks cross-field consistency. Do not derive content-bearing `Debug` implementations for command lines, URLs or arbitrary attributes. Errors name the field and reason without echoing its value. The schema does not require a new production dependency.

Proposed bounds are 32 entity observations, 16 DNS answers, 512 UTF-8 bytes for ordinary identifiers, 8 KiB for command lines and URL text, and 64 KiB for the serialized typed projection. The effective bound is always the smaller of these and a parser's existing field/record bounds. No parser, frame, source, depth, field-count, decompression or record-count limit is raised by this design. A mapped value exceeding a bound rejects that record with a counted, guarded diagnostic; no silent prefix truncation creates a different identity. Original retention follows the existing file-level custody policy.

Use `std::net::IpAddr`, checked port/PID/integer wrappers and existing checked time types. Signed/native PIDs with sentinel values are not cast to unsigned; keep unsupported values in the original. Hashes use an algorithm enum and exact-length hexadecimal validation; preserve unknown algorithms in original attributes. Do not lowercase user names, file paths or commands across platforms. Normalize a DNS name for lookup only under a pinned rule, preserving original spelling. Never resolve a host or path while validating it.

The app pairs a `Tainted<CommonEventV1>` with a bounded original-record representation and its `Provenance`. Normalization does not remove taint. Screen all model/screen projections through `ContentGuard`, redaction and existing safe-output handling. No event-derived value enters a system-role message, changes tool risk or extends scope.

Types validate representation and consistency, not the truth of an attacker-controlled log. Versioned mappings and fixtures establish interpretation; provenance establishes which bytes supplied it. Categorization and roles never become an authorization authority. Canonical encoders order object keys recursively and encode checked integers/decimals without a lossy floating-point round trip. They do not depend on `serde_json::Map` iteration or its enabled features.

### Parser validation, including declarative definitions

Each parser remains a separate module. An additive common-event emission method on the parser port is proposed for a staged transition; existing methods keep historical behavior. Native modules construct the domain types directly. A compatibility bridge can expose old records as legacy/unclassified observations, but cannot manufacture new classifications or roles from field-name guesses.

The shared contract suite must validate every emitted event before staging: checked time and provenance, bounded fields, classification sets, compatible entity-role combinations, stable raw-record identity and deterministic canonical output. The app validates at the boundary even when the module already used checked constructors. Invalid records increase `ParseReport.rejected`, retain only bounded tainted samples, and do not stop other well-framed records. Framing, resource, hash or file-level failures still reject the complete source.

Declarative definitions need a new definition/engine version. Compile destination field paths to a closed `CommonField` enum, not arbitrary JSON assignments. Support explicit category/type constants and finite input-to-enum status tables with an unknown fallback. Reject invalid enum constants, unknown destinations, duplicate assignments, incompatible roles and invalid bounds at definition installation. At parse time, apply the same constructors and contract tests as native modules. No user-provided Rust, expressions, network lookups, shell execution or unrestricted transforms are introduced. Definition hashes, signed installation and historical versions retain their existing custody role.

## Entity observations and roles

Separate an entity's identity from its role in one event:

```rust
pub struct EntityObservation {
    entity: EntityRef,
    role: EntityRole,
    field: CommonField,
}

pub enum EntityRole {
    Actor, Target, Source, Destination, Parent, Subject, Observer, Related,
}
```

`EntityRef` contains a closed kind, checked value and typed identity scope. Core kinds cover IP, domain, host, user, process, file, registry, hash, account, project, resource, IAM role, key ID, session, flow, event, rule and collector artifact. An occurrence also carries its event/source provenance. Examples: `(ip, 203.0.113.77, source)`, `(user, alice, actor)`, `(user, bob, target)`. A value may have several roles in the same event; deduplicate only identical entity/role/field observations.

| Observation | Meaning and identity rule |
| --- | --- |
| `user.*` / actor, `user.target.*` / target | Use event semantics, not the first username found. A collector user is not the actor. Keep SID/UID/domain/account namespaces to avoid merging unrelated accounts. |
| `source.*` / source, `destination.*` / destination | Same IP identity can occur at both ends. Endpoint ports remain attached to their endpoint, not globally correlated as independent numeric entities. |
| `process.*` / subject, `process.parent.*` / parent | Prefer source process entity ID plus host. A PID without a lifetime identifier is only a scoped observation; never infer continuity across PID reuse. |
| Files/registry/resources / target or subject | Role depends on the operation. Inventory presence is subject/related, not proof of an action against the object. |
| Sensor and additional UDM nouns / observer or related | Preserve provenance without falsely promoting the observer to actor or destination. |

Roles label observations; they are **not additional global nodes**. `entity_lookup(ip, value)` still finds all matching roles, with an optional checked role selector and per-role counts. Explicit identity scopes disambiguate users/processes; a broad value lookup returns separate scoped matches rather than silently merging them. Legacy role-free observations remain visibly unspecified, not actor by default.

Co-observation remains symmetric evidence that entities appeared in the same record. Persist role/field with each observation and its peer descriptors in the new co-observation schema, retaining source/record references. Optional role predicates can select source-IP observations or actor-to-target co-occurrence. Do not relabel those pairs as "connected to", "created" or "caused" without a source-specific typed relation. Preserve explicit parser relations separately from co-occurrence.

`neighbors` and `path` keep their current meanings and limits. They may display roles on each supporting observation, but an actor/target pair alone does not prove a directed attack edge. Existing calls without a role filter retain co-occurrence behavior. A role-filtered query must not silently include unspecified legacy roles. Same-value/different-role observations do not create self-edges or multiply one record's neighbor count. Stable deduplication is by event identity before counting.

## Parquet representation and signed compatibility

Promote category, type and outcome to typed Parquet columns. Filtering them by parsing a JSON blob on every row defeats projection and makes the logical contract optional. Keep the typed common JSON view for inspection and existing text search, with lexically ordered object keys and set arrays. Unknown vendor attributes are canonicalized separately and never override typed fields.

| Artifact family | Proposed physical additions |
| --- | --- |
| Events | `common_schema` in checked file metadata; `event_category_bits: UInt32`, `event_type_bits: UInt32`, `event_outcome: UInt8`, `event_kind: UInt8`; deterministic typed common payload alongside original attributes/reference. Preserve all V2 time, scope, source and order columns. |
| Entities | Checked `entity_role: UInt8`, `entity_field: UInt16`, typed identity scope; same event classification columns so filtered lookups need no unbounded event join. Preserve entity sort/pruning and event references. |
| Co-observations | Same role/field/scope and event classifications; peers retain their own roles. Keep the existing event-reference/time representation for now. This does not approve the deferred co-observation-by-reference redesign. |

Assign bit positions explicitly in lexical order of the category/type lists above. Freeze them in golden fixtures; never use Rust enum discriminants as a wire specification. Zero category/type masks mean unclassified; reserved bits fail validation. Outcome codes are explicitly `unknown=0`, `success=1`, `failure=2`; event-kind codes are `event=0`, `alert=1`, `state=2`. Role and field codes require explicit golden tables before implementation. No runtime field registry allocates codes.

Projection and Arrow row predicates apply these columns directly. Outcome min/max can exclude a row group; numeric min/max of a multi-bit category mask is **not** a membership index. Do not prune on that assumption. A reproducibly computed category/type union and outcome-presence summary may be stored in bounded Parquet file metadata and used only after verifying the entire artifact hash. Row-level mask checks remain authoritative. Benchmark row-group summaries before adding more metadata or changing row-group sizes.

**This is a new physical artifact schema generation, not a silent extension of the V2 schemas already approved.** Recommended transport: keep the exact `ParquetArtifactV2` envelope layout and add explicitly reviewed variants for the three new schema IDs. The envelope already signs schema name, parser version, builder identity, source links and artifact hash. It needs no new field to bind this contract: each new schema ID fixes the logical schema and code tables, and verification checks matching file metadata. Current strict readers will reject an unknown schema ID; they must be upgraded before reading the new generation.

This approach needs approval to extend `ArtifactSchemaV2`, the parser emission contract and query filters. It does **not** require an envelope V3 merely because a physical table changes. If implementation discovers a need for a new envelope field, stop and propose a versioned envelope instead. Do not overload partition keys, normalization-policy IDs or builder strings with unsigned schema choices.

V5 export framing and source-manifest encodings can remain unchanged because they already carry complete V2 envelopes and derived files. Its verifier needs an explicit allowlist/decoder extension for the new physical IDs; it must hash every file and validate its schema against the signed envelope. Old verifiers fail clearly rather than skip unknown files. Seal inventory commitments already bind complete artifact envelopes. Keep all historical goldens, the 16 KiB manifest payload limit and the 1 MiB export metadata-frame limit.

## Proposed parser mappings

The following is a target mapping table, not a claim that existing modules already emit the proposed types. New mappings require pinned versions and synthetic positive/negative fixtures. Only documented fields present in the input may populate the projection. Ambiguous actions, statuses and roles remain unclassified/unknown and retain their source values.

| Parser / source | Category and type | Outcome rule | Main fields and roles; weak mappings |
| --- | --- | --- | --- |
| CloudTrail | `api`; add `iam`, `authentication`, `configuration` or `session` only for a versioned operation allowlist; types from that operation | Explicit error/status table; absence of an error means success only for covered CloudTrail event forms | `eventTime`, original `eventName`, `eventID`, `userIdentity` actor, recipient account, region/service, source IP and explicit target resources/role/user. `sourceIPAddress` may be a service name: it is not then an IP. An ARN is not automatically a user name. |
| Generic JSON, GCP/Azure exports, HuntEval | Recognized native envelopes use explicit provider tables; arbitrary JSON has empty sets | Supported native status code or explicit configured map; otherwise unknown | Preserve current event identity, time and extracted values. Google method/subject/resource, Azure caller/operation/status and HuntEval principal/resource need separate mappings. Unscoped nested `user`/`ip` keys get no invented role. |
| ECS | Validate native category/type arrays and the supported field subset directly | Validate native success/failure/unknown | Preserve actor/target, source/destination, process/parent and original `ecs.version`. Unknown ECS fields stay in original attributes; an unsupported categorization label is a mapping diagnostic, not a new enum. |
| OCSF | Authentication 3002 → authentication; API 6003 → api; network 4001 → network; process 1007 → process; file 1001 → file; finding 2004 → alert kind with supported detection categories | Versioned `status_id`/status table, not a generic numeric cast | `actor`, `user`, device, endpoints, process, cloud and resources by class/activity and OCSF version. Unknown classes stay unclassified; a finding's severity is not outcome. Pin tables to the input's supported schema versions. |
| Velociraptor | Artifact-specific allowlist, otherwise empty sets and state/event kind | Unknown unless the artifact provides a documented result | Timestamp, host, actor/subject, process and endpoints when the artifact defines them. `_Source` is collector metadata, not a host by default. Artifact name alone does not prove execution. |
| Hayabusa | Underlying channel/EventID uses the EVTX table where available; rule match links a detection | Underlying event's status only | Computer, channel, EventID, source event and rule descriptor. `Details` remains bounded original text unless an exact supported schema maps its fields. Do not treat every match as a confirmed finding or authentication failure. |
| Chainsaw | Supported embedded Windows events use the EVTX table; search-only objects can remain unclassified | Embedded event status only | Embedded Event/System and EventData, source, rule/group and timestamp. A hunt rule title is not `event.action`; incomplete source objects do not gain guessed actor/target roles. |
| plaso | Versioned `(parser, data_type)` table; inventory observations often file/registry with type info | Usually unknown | Preserve plaso parser/data_type, timestamp semantics, hostname, user and file reference. A file's metadata time is not necessarily event execution time. Unknown data types retain unclassified observations. |
| EZTools | PECmd → process/info; Amcache and AppCompatCache → file/process info; MFTECmd and LECmd → file/info; RECmd → registry/info; SRUM → network/process info; EvtxECmd → EVTX table when fields suffice | Unknown for inventories; explicit event status where supplied | Keep the chosen timestamp's meaning and tool/version. RunCount, cache presence, LNK target and SRUM usage are observations, not successful execution/exfiltration. Exact CSV headers remain required. |
| Zeek | conn → network/connection; dns/http → network plus web where applicable, type protocol; ssl/x509/files → supported network/file info; notice → alert; weird → network/info | Usually unknown; only a documented protocol transaction/result map changes it | `ts`, UID, originator/responder endpoints, protocol, DNS/HTTP/files. UID is sensor-scoped; conn_state alone is not a universal success/failure result. TLS/X.509 details outside the subset remain attributes. |
| Suricata EVE | flow → network/connection; dns/http/tls → network/protocol; fileinfo → file/info; alert → alert/intrusion_detection; anomaly → network/info | Unknown unless a supported transaction status proves it; allowed/blocked maps type, not automatically outcome | Timestamp, flow ID, source/destination endpoints, protocol, DNS/HTTP/file and rule descriptor. A source alert remains a proposed detection. |
| Syslog RFC 5424 / RFC 3164 | Empty sets unless a module-specific message mapping proves a category; type info only for supported generic records | Unknown; PRI severity is not failure | Checked timestamp/context, reporting host, application/PID as emitter metadata, facility, severity and original message. A syslog emitter PID is not automatically the process whose action is described. RFC 3164 year/offset/rollover retain the signed per-ingestion context. |
| Linux auth.log / secure | sshd/su → authentication and supported session events; sudo → process or iam only when its record supports that action; useradd/usermod → iam; cron → process/start only with an execution record | Explicit accepted/failed/PAM result table | Authentication subject, remote IP, acting user and sudo/su target/effective user; command and host where present. Reuse confirmed RFC 3164 context. An SSH failed login's named user is an attempted identity, not a proven authenticated actor. |
| Linux auditd | exec → process/start; supported file, authentication or configuration syscall families map explicitly | Checked `success`/`exit` by syscall semantics; absent/partial result stays unknown | Grouped serial, auid as original actor, UID/effective user, process/parent, argv, cwd, path and decoded sockaddr. Keep bounded partial-group markers; do not infer a missing peer record. |
| Linux journald JSON | Supported `_TRANSPORT`/unit/payload mapping; otherwise empty sets | Explicit supported payload status only | Full microsecond timestamp, host, UID, PID, executable and command line with their journald meanings. Priority is severity; collection process metadata alone does not establish an underlying action. |
| Linux nginx / Apache | web/access | Proposed explicit HTTP mapping: 2xx/3xx success, 4xx/5xx failure from the server request perspective; other statuses unknown | Client source IP, request method/URL, response status/bytes and authenticated user when supplied. Common/combined logs do not supply server host by default. Custom formats use a reviewed declarative definition. |
| EVTX | Per provider/channel/EventID table below | Explicit event result/status; not severity | Preserve 100 ns timestamp precision, actual record ID/offset, host, subject/target users, process/parent, endpoints and original fields. No role chosen merely by field-list precedence. |
| Declarative | Explicit checked constants or finite source maps | Explicit finite status map, otherwise unknown | Every supported field goes through the same constructors. New definition version/hash records classification and role mapping. No inference from arbitrary action strings. |

The [Zeek connection reference](https://docs.zeek.org/en/current/reference/logs/conn.html) and [Suricata EVE reference](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html) define their endpoint and correlation fields. They do not establish a universal event-outcome conversion.

### EVTX mapping coverage

Dispatch by provider and channel as well as EventID. A numeric ID from a different provider does not inherit these mappings. Keep the existing isolated helper and trust boundary unchanged; normalization stays in the main parser module.

| Channel / IDs already recognized | Proposed category / type | Outcome and role caveat |
| --- | --- | --- |
| Security 4624, 4625 | authentication/start | Success/failure respectively. The attempted/logged-on account is the authentication subject; SubjectUserName can be a reporting service. Use event-specific actor/target semantics. |
| Security 4634 | session/end | Completed logoff is success only under the supported event schema; the account is session subject. |
| Security 4648 | authentication/info | Explicit credentials attempted; success is not proven by the event alone. Subject is actor; credential account is target/related with its exact field recorded. |
| Security 4672 | iam/info | Privileges assigned to the reported logon identity; not proof of attacker privilege escalation. Keep the privilege list. |
| Security 4688 | process/start | New process is subject, creator process is parent, Subject identity is actor; preserve ProcessId/NewProcessId distinction and hexadecimal parsing. |
| Security 4697; System 7045 | configuration/creation | Service installation, actor only where supplied; executable/service data are not necessarily a running process. |
| Security 4698 | configuration/creation | Scheduled task creation; preserve subject and task data. No execution inferred. |
| Security 4720 | iam with user/creation | Subject actor, new account target. |
| Security 4732 | iam with group/change | Subject actor, member user and target group remain distinct observations. |
| Security 4768, 4769, 4776 | authentication/info | Decode each event's own result/status code; zero success only where its schema defines it. Account, service and endpoints have event-specific roles. |
| Security 1102 | configuration/change | Audit-log clearing; keep subject identity. Do not invent a file-delete event. |
| PowerShell 4103, 4104 | process/info | Module/script-block telemetry, not universal execution success. Script text stays bounded, untrusted and original. |
| Sysmon 1 | process/start | Subject process, explicit parent and reported user. |
| Sysmon 3 | network/connection | Source/destination endpoints and originating process; outcome unknown without supporting result. |
| Sysmon 7 | library/info | Loaded image as target file/library, loading process as subject; do not create a new process. |
| Sysmon 8, 10 | process/access | Preserve source and target processes separately as role-bearing observations; target process details outside the selected ECS subset remain original attributes. |
| Sysmon 11, 23 | file/creation or file/deletion | Target file and initiating process. |
| Sysmon 12, 13 | registry with creation/deletion/change from EventType | Target registry object and source process; ID 12 alone cannot distinguish creation from deletion. |
| Sysmon 22 | network/protocol | DNS question, process and query result; use the documented QueryStatus table, not a free-text success guess. |

Unsupported or ambiguous Windows fields remain original data. New fixtures must distinguish success, failure, missing status, Subject/Target reversal, parent/source process and same-value roles for these IDs.

## Connector mappings

### Elastic

`siem-elastic` consumes native ECS fields from the authenticated response. Its normalizer validates ECS categorization, copies the supported sets and constructs the same types as `parser-ecs`. Elastic alert rule metadata stays a detection descriptor; preserve the original event timestamp separately from alert creation time, and never substitute one silently. Custom/non-ECS index mappings require explicit configured field maps to the closed common fields.

Structured query compilation can translate supported category/outcome filters to ECS term filters, combined with the configured index, account/host and time constraints. Those constraints stay server-side and cannot be replaced by model arguments. Unsupported mappings fail clearly rather than run a broader query. Connector response handling remains bounded, read-only, tainted and independently authenticated; no credential change is authorized here.

### Google SecOps / Chronicle

Use a pinned UDM mapping table, not field-name similarity. The [UDM overview](https://docs.cloud.google.com/chronicle/docs/event-processing/udm-overview) distinguishes actors, targets, observers and other participants; the [UDM field list](https://docs.cloud.google.com/chronicle/docs/reference/udm-field-list) supplies event and field enums.

| UDM input | Common view |
| --- | --- |
| `metadata.event_timestamp`, `product_event_type`, product log ID | Checked event time, original action/code and source ID, preserving precision. Collection time remains metadata. |
| `metadata.event_type` | Versioned category/type mapping: USER_LOGIN → authentication/start; PROCESS_LAUNCH → process/start; NETWORK_CONNECTION → network/connection; NETWORK_DNS → network/protocol; supported FILE/REGISTRY operations → their operation-specific types. Unknown UDM enums remain unclassified. |
| `principal`, `target` | Actor/subject and target observations with noun/event-type semantics; distinguish endpoint identity from a user inside that endpoint. Target is not always a network destination. |
| `src`, `intermediary`, `observer`, `about` | Preserve source-object, intermediary, observer and related observations. Never map `src` blindly to `source.ip` or drop extra nouns into the actor. |
| `network` | Supported endpoint, protocol, DNS and HTTP descriptors. |
| `security_result` | Detection descriptor and allowed/denied types where supported. Action BLOCK does not by itself set outcome=failure. |

Authentication result conversions require explicit event-type/product status evidence. If an API returns only detections rather than original UDM events, preserve that distinction; do not fabricate a source event. Structured UDM search must apply scope/time before retrieval. Unsupported filter or account mappings return an error. No JWT library or service-account credential is introduced by this design.

## Sigma compatibility

ECS names reduce field translation work, but do not make every Sigma rule executable. [Sigma processing pipelines](https://sigmahq.io/docs/digging-deeper/pipelines.html) map rule fields and log sources to a backend. Propose an IRMind pipeline with a closed field map, supported operators and explicit product/service/category requirements. Existing pipelines can inform mappings; arbitrary pipeline code or generated free-form SQL is not executed inside IRMind.

Examples are `CommandLine` → `process.command_line`, `ParentImage` → `process.parent.executable`, `EventID` → `event.code`, and `TargetFilename` → `file.path`. `Image` maps to `process.executable` only for a matching Windows process log source; `TargetObject` requires a registry/file-aware mapping. Keep Windows provider/channel and original field references for rules outside the common subset.

The future local Sigma evaluator uses checked common fields and original-field access through an explicit bounded allowlist. It reports unsupported fields/modifiers, unmapped source coverage and unsupported aggregation/correlation rather than silently treating them as no matches. Category/outcome can narrow scans, but do not replace a rule's detection conditions. A Sigma match is a proposed finding with evidence links; analyst confirmation still controls reports. No LLM, remote execution or policy extension is required.

## Existing tools and agent queries

Extend the existing typed graph filter with optional category, type, outcome and entity-role selectors, after approval of the additive port/schema change. Keep the existing tools: `text_search`, `entity_lookup`, `neighbors`, `timeline`, `path`, `graph_summary` and `raw_records`. No SQL, KQL, JSON-pointer expressions or user-defined predicates are accepted from the model.

A proposed `timeline` argument object is:

```json
{"category":"authentication","outcome":"failure","from":"2026-01-02T00:00:00Z","to":"2026-01-02T23:59:59Z","limit":20,"budget":1000}
```

This is a proposed tool shape, not a new CLI command. One category/type selector means set membership; specified selectors combine with AND. Exact case/organization scope filters always remain in force. Unknown enum labels, invalid roles or unsupported combinations fail validation before scanning; they never remove a filter. Remote translations use the structured query model and a module's explicit capabilities. No model-supplied index or source field can replace configuration.

For `neighbors`/`path`, event predicates apply to every supporting record at every hop, not just the initial entity lookup. Role predicates apply to the selected observations, not to the entity's global identity. Preserve current caps: up to 20 returned neighbors, 4,096 sampled matching records, three path hops, 200 expanded entities, 50 candidate neighbors per expansion and the 10-second query deadline. Keep token/result limits, cancellation, per-artifact hash verification and partial/truncated labels. The implementation must test any narrower tool-specific limits too.

Mixed old/new cases remain queryable. Do not infer a failure outcome for a legacy record from a familiar text key. Unmapped legacy classifications and unspecified roles do not match the corresponding typed filter; results report incomplete schema coverage. Distinguish "no matching classified events" from "no such activity occurred". With no new filters, historical queries retain their existing behavior and legacy observations.

## Compatibility and explicit migration

Increment every parser/normalizer version whose output changes. Declarative definitions/engine versions are pinned by their signed hash; module code upgrades never reinterpret an old signed definition in place. Connector normalization versions are pinned independently of live API response versions. The source manifest, artifact schema and builder together identify how a generation was produced.

Existing V1 and V2 cases remain readable and exportable without migration. Keep strict historical readers and existing goldens. Reading a case cannot reparse it, change its source manifest or add inferred categories. Historical raw fields remain accessible, with guarded display and the existing parser-retirement caveats. This does not promise byte reconstruction for parser versions already retired before this proposal.

Reuse the existing explicit migration **workflow**, not its precision-only authorization. Propose a new, domain-separated `CommonEventMigrationV1` record that binds:

1. A closed transformation identifier for this common-schema upgrade.
2. The complete source, previous-artifact and replacement-artifact set commitments using the existing bounded canonical commitment rules.
3. Old/new parser and builder identities, exact physical/logical schema identifiers, and commitments to their source subsets.
4. Per-source accepted/rejected counts and a commitment to the bounded mapping-difference report, including classifications, role changes and unsupported values.

The transformation preserves original hashes, record identities and exact time/order semantics. It can enrich normalized meaning only through the reviewed mapping tables, not arbitrary parser substitutions. A count/identity change is not silently accepted: it stops this transformation and requires a separately reviewed re-ingestion path. The difference report is evidence-derived untrusted content, guarded for analyst review; it cannot approve itself.

An attended analyst reviews the changes, then the app verifies the full chain and originals, stages and reconstructs the new generation, and signs the complete replacement batch atomically under the case lock. Historical generations remain linked and retained. Shared lineage interpretation must recognize the new typed migration record in queries, verify, seal and export before it can activate replacements. Unknown transformations fail closed. Cancellation, disk-space checks, private staging, cleanup and crash recovery keep the old set active until a complete commit. Sealed cases remain immutable; a new case is the alternative when migration is unavailable or originals cannot be resolved.

New migration record bytes, audit kind, schema variants, parser-port/filter additions and export-reader support require review and new golden tests before implementation. No historical audit string, source-manifest field, seal format or export frame is rewritten by this document. If a new envelope field or export framing is needed, submit a separate versioned design rather than changing V2/V5 in place.

## Cost and benchmark plan

These are planning estimates, **not measured results**. Category/type masks plus outcome add 9 uncompressed bytes per event-bearing row; kind adds one more. Repeating classifications in entity/co-observation rows costs `10 * (events + entity_rows + coobservation_rows)` bytes before validity/encoding overhead, not just ten bytes per source record. Role plus field adds another three bytes per observation, before scoped identity and peer-role data. Parquet compression may reduce these costs; no compression ratio is assumed. Report the co-observation contribution separately so classification work does not hide its existing size problem.

Rewriting any artifact changes its hash. Optional migration needs space for the entire old and new generations plus bounded staging, and must preflight it. Do not delete historical artifacts to make the estimate fit. Sources kept in place need another full hash pass; reconstructibility requires additional reads and conversion. Normalization CPU, peer-role expansion and file-metadata retention must be profiled separately. The separate bounded-metadata work remains a dependency only if these measurements show it is necessary, not an implied part of this approval.

| Validation tier | Work and estimated budget |
| --- | --- |
| Mapping/contract | Every parser fixture, unknown/malformed fields, roles and outcomes; preserve-order canonical goldens; mixed-schema queries, migration, export and fault tests on all three systems. No production throughput claim from unit tests. |
| 1 GiB smoke | Same source files through old and proposed mappings for representative cloud, ECS, OCSF, endpoint, DFIR, syslog/Linux and network sources. Measure parse/validation/extraction/Parquet/custody, peak memory, disk and exact accepted/rejected identities in release builds. |
| Full 15 GB comparison | Cloud plus endpoint chronological and disordered corpora at 1, 64, 1,024 and 1,025 hosts: nine variants, baseline and candidate, three repetitions on the same runner class. This processes 810 GB of source input before hash/reconstruction passes. |
| Runner reservation | Using the existing 900 s cloud/chronological and 1,350 s stress targets solely for capacity planning gives about 16.5 runner-hours of ingestion for that full matrix. Query suites, verification, reconstruction, generation and builds are additional. It is not a forecast that the new schema already meets those targets. |

Record p50/p95 for every existing query and the new authentication-failure and role-filtered queries, selected/hashed bytes, row groups decoded, file count, schema coverage, compressed column sizes and bin/lockfile changes. Repeat deterministic HuntEval and needle-in-haystack evaluation, including expected actor/target roles. Use release builds only and the same fixtures/runner class before and after. Keep existing performance gates and all result, memory, time and custody controls; ask for a design adjustment if they cannot be met.

## Acceptance and review decisions

The recommended decisions are the ECS-derived V1 logical contract, checked domain types, role-bearing observations, new physical schema IDs inside an explicitly extended V2 envelope, and a separately versioned semantic migration record. They are proposals for review, not implementation approval.

Before any writer or connector adopts the contract, require:

- Pinned field/enum/code tables and canonical fixtures independent of JSON map features and platform.
- Contract fixtures for every mapping above, including unsupported fields, unknown outcomes and misleading source data.
- Same IP in both roles, distinct actor/target, PID reuse, multiple users, observer/target differences and alert-versus-confirmed-finding tests.
- Declarative compile-time/runtime validation, signed definition pinning, preserved taint/provenance and guarded model/screen projections.
- Exact historical-reader behavior; mixed-schema coverage warnings; no automatic migration; explicit signed semantic migration with rollback and reproducible artifacts.
- Shared graph-tool validation and remote structured-query compilation that never broadens case or organization scope.
- Release-profile evidence for storage, memory and query costs, with unchanged limits and no newly enabled provider.

Elastic and Chronicle implementation stays paused until this design is reviewed.
