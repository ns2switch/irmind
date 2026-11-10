# Declarative source pipelines and process-lifetime table scopes

This design is for maintainers completing source-decoder coverage before removing the legacy ingestion interface. It defines the approved compiler result that keeps detection, decoding and extraction separate, and one bounded table primitive needed for reported process-lifetime identifiers. The compiler result, decoder/extraction pipeline and process-lifetime primitive are implemented alongside this contract.

## Declarative compiler result

The current [DefinitionCompiler](../../crates/app/src/definitions.rs) returns a `LogParser` that produces normalized graph records. That result cannot expose an independent decoder and mapping without a downcast, a second unverified read of the definition, or a hidden mutable side channel. None of those mechanisms should become part of composition.

Replace the result of the existing method with a checked bundle:

```rust
pub struct CompiledDefinition {
    selector: Arc<dyn LogParser>,
    decoder: Arc<dyn SourceDecoder>,
    extraction_mapper: Arc<dyn SourceMapper>,
}

pub trait DefinitionCompiler: Send + Sync {
    fn compile(&self, contents: &str) -> Result<CompiledDefinition, AppError>;
}
```

`CompiledDefinition::try_new` checks the selector/decoder identity agreement, bounded definition identity and digest, target schema and mapping selectors. Accessors return the immutable ports. This changes the compiler port's result type; `SourceDecoder` and `SourceMapper` signatures do not change. There is one compilation path, rather than a second compiler method or an insertion-order compatibility interface.

Application definition use cases continue validating the signed snapshot, exact active bytes and content hash before returning an opaque approved pipeline to composition. Installation still requires the analyst's signed global operation. A compiler result alone is not installation authorization. Unsigned files, changed files, invalid signatures and mismatched hashes retain their existing rejection behavior.

The compiler shares an immutable validated definition between these three roles:

- The selector performs bounded detection and exposes identity and description.
- The decoder reads CSV, JSON/NDJSON or bounded regex framing, original field names and types, source timestamps and real provenance. It does not classify events or construct `SourceRecord` from normalized graph text.
- The extraction mapper interprets the definition's existing field mappings. Initially it emits an unclassified CommonEvent and retains the established search projection and entity extraction. Semantic mappings remain separate replaceable modules.

Parser definitions remain data, never downloaded Rust or scripts. Decoder and mapper execution have no network, clock or secret capability. Regex compilation and matching retain their existing compiled-size and input bounds. Preview uses the same decoder/extraction pair with its ten-row output limit and guard boundary; it does not create a case or call a model.

## Registration and reconstruction

Configured definitions remain variants of their compiled modules, with the existing limit of 64 active definitions. Registration must bind both ports to the same approved definition and owned module namespace, reject duplicate identities, and freeze mapping selection before ingestion. Native modules retain their one-declared-port validation. Data variants do not become a general exception permitting a module to register unrelated decoders or mappings. Empty catalogs remain a valid startup state.

The decoder identity includes the current interpreter and definition digest. The generated extraction mapper's native descriptor commits to its compiled implementation and the same definition digest through a fixed recipe. Recompilation of the approved snapshot must reproduce that descriptor. Existing V3 pipeline/profile/run fields carry these identities; no decoder version, builder field or timestamp context is overloaded with mapping identity. The definition digest already binds its timestamp format and declared default zone; these are not encoded again as free-form per-ingestion context. Existing frame and definition-size limits remain unchanged.

Current-interpreter definition snapshots remain available for replacement/reconstruction within the supported minor version. No retired interpreter or previous-minor reader is added. An unavailable interpreter disables that definition with a clear warning. Signature or hash failure must never be reclassified as an unavailable interpreter. Authentication-only export verification does not execute received definitions; full reconstruction needs the matching compiled implementation, approved definition and originals. No decoded-record cache or remap operation is introduced.

Once every parser has a source decoder, remove the legacy normalized-record methods and definition preview/resolver paths in the same cleanup area. Until then, temporary legacy presentation adapters use the same compiled immutable definition; they are not a source of reconstructed SourceRecords.

## Explicit process-lifetime scope in table interpreter V2

The domain already has [EntityIdentityScope::ProcessLifetime](../../crates/domain/src/common_event/entity.rs). Native mappings can use it. Table mappings currently expose only global, account, host and source-record scopes. Add one closed alternative to the current interpreter, without introducing another interpreter version:

```toml
observation = { kind = "process", role = "subject", scope = { kind = "process_lifetime", path = { host = ["Event", "System", "Computer"], lifetime = ["Event", "EventData", "ProcessGuid"] } } }
```

Both paths use the existing bounded key-path grammar. Both resolved values must be original text values accepted by the domain's identifier constructor. Missing values, nulls, wrong types and invalid identifiers produce the existing unsupported-value diagnostic. There is no implicit fallback, string concatenation, case folding, lookup, expression or generated lifetime ID. `omit_text` still applies to the observed field before creating an observation.

Only process observations accept this scope. Security 4688, auditd and Linux observations use explicit source-record scope, even when a PID, process name or timestamp is available. Only a documented producer lifetime identifier such as Sysmon ProcessGuid may use process-lifetime scope. A reported ProcessGuid can connect observations across records from the same reported host without merging different lifetimes that reuse a PID. Bundled definitions must point to a documented lifetime field, never a PID, timestamp or process name. The generic interpreter validates the representation and the approved definition binding; it does not prove that a producer's reported identifier is truthful or globally unique.

Charge both path traversals and identifier checks to the existing operation budget. Keep the 32-observation cap and selector-overlap rejection. Existing definitions without the new variant retain identical canonical bytes and hashes. The already-supported common-event scope encoding and V3/export V6 envelopes do not change.

## Required tests

- Unsigned, modified and incorrectly signed definitions cannot provide active source pipelines.
- Compiler/selector/decoder/mapper identity or definition-digest disagreement fails before publication.
- A replaced definition rebuilds sources through the matching supported snapshot; an unavailable interpreter is disabled without blocking startup.
- CSV, JSON, NDJSON and regex fixtures retain search/entity extraction, exact timestamps, rejection accounting, cancellation and source provenance.
- Preview and ingestion use the same decoder/mapping; preview stays guarded and never reaches a model.
- Registered variants remain bounded, owned by their module and unambiguous; unrelated native multi-port registrations still fail.
- Two events with the same host and reported lifetime identifier produce the same scoped process identity. Reused PIDs with different lifetimes do not.
- Missing or malformed lifetime/host fields never become a broader scope.
- Existing table-definition goldens remain unchanged, including under `preserve_order`; add goldens for the new scope and native descriptor recipe.

No external production dependency, remote credential, permission, policy ceiling or tool-dispatch path is added by either contract.
