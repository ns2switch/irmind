# ECS source decoding and mapping

This page explains the ECS pipeline for maintainers and contributors. Source decoding and event interpretation remain separate modules.

## Original source records

`parser-ecs` supplies `EcsSourceDecoder` (`ecs-source-v1`). It frames NDJSON with the existing bounded line reader and preserves original field names, JSON scalar types and unmapped attributes. It reads `@timestamp` as an instant with its reported precision. An absent offset requires confirmed ingestion context; the decoder never consults the clock or file modification time.

Each accepted record carries the source hash, source reference, record ordinal and actual line byte offset. Oversized or malformed records contribute to the bounded rejection report. A callback, cancellation or reader failure remains an operation error. The decoder assigns no categories, outcomes or entity roles.

The current SourceRecord limits also apply: 4 MiB, 4,096 nodes and depth 32. The ECS field limit remains 1,024, the source limit 50 GiB and the record limit ten million. Detection still uses a bounded sample and extensions do not prove a format.

## Native mapping

The separate `mapping-ecs` module targets `irmind-common-event-v1`, the agreed ECS 9.5 subset. Native code handles categorization sets, nested versus dotted aliases, typed field validation and occurrence roles. These operations exceed the finite table interpreter. The mapping has no file, network, clock or secret ports.

Categorization follows the [ECS 9.5 event fields](https://github.com/elastic/ecs/blob/v9.5.0/schemas/event.yml). Known category/type keywords become closed sets. Unknown labels remain in the original and generate a mapping diagnostic. Missing outcome stays unknown. Action text never implies a category or outcome. Conflicting dotted and nested representations are unsupported; neither representation silently takes precedence.

The closed common field set validates IPs, ports, integers, hashes, time values, network direction and bounded DNS answers. Unsupported typed values cannot become a broader query or a valid typed value. Empty optional text is absent; zero and other literal values are not treated as empty. Original attributes remain available.

## Identity and roles

Source/destination addresses and actor/target users retain their occurrence roles. The same address in two roles denotes one entity with two occurrences. The [ECS user fields](https://github.com/elastic/ecs/blob/v9.5.0/schemas/user.yml) distinguish the actor, target, effective user and directory domain.

A reported directory domain qualifies user identity with a versioned, length-prefixed namespace over the reported provider, cloud account, host identity, domain and identifier kind (ID or name). When neither host nor cloud account exists, the source hash also qualifies the namespace. The account scope contains its domain-separated digest; it is not a claim that a directory domain is a cloud account. No username/domain case folding or invented realm occurs. Without a reported domain, the namespace also includes the source hash and record ordinal. This keeps the source-record boundary while distinguishing IDs from usernames.

Only reported subject and parent PIDs create typed process observations, scoped to their source record. Names and producer entity IDs remain in context and the search projection. Reported `process.entity_id` stays in the typed context and source attributes; this mapping does not create a process lifetime from it. The [ECS process fields](https://github.com/elastic/ecs/blob/v9.5.0/schemas/process.yml) document PID reuse and producer identifiers. The existing 32-observation cap remains in force.

## Search and custody

The mapping retains the existing ECS search projection and extraction aliases alongside validated typed occurrences. Unmapped attributes remain original data. Partitioning uses the reported host; storage still owns normalization, cardinality bounds and hash-derived paths.

The native descriptor includes this mapping, its shared conversion implementation, the app/domain contracts and resolved dependencies. It does not contain absolute build paths. The V3 pipeline binds the decoder, mapping implementation and source commitments. No envelope, seal, export frame or verification limit changes.

Within the pre-1.0 rollout, the original writer remains selected until decoder coverage is complete. The new source pipeline is used through the optional common writer. Historical readers are removed separately under the pre-1.0 policy.
