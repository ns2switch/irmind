#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![cfg(all(feature = "parser-json", feature = "parser-linux"))]
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::source_mapping::{MappingCatalog, SourceDecoderSelection};
use irmind_app::{
    AppError, AuditLog, CancellationToken, Clock, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, ParserSelection, Repository, Signer, StreamingEventParser, sha256,
};
use irmind_domain::{
    Actor, ExecutionMode, ParquetArtifact, ParserSelectionMode, ScopePartitionKey,
};
use irmind_infra::{LocalStore, LocalVerifier};
use irmind_mod_parser_json::JsonSourceDecoder;
use irmind_mod_parser_linux::LinuxSourceDecoder;
use std::{collections::BTreeMap, fs, sync::Arc};
struct FixedClock;
impl Clock for FixedClock {
    fn now(&self) -> Result<u64, AppError> {
        Ok(1_792_756_800)
    }
}
struct FixedSigner(SigningKey);
impl Signer for FixedSigner {
    fn actor(&self) -> Actor {
        Actor::Analyst
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, AppError> {
        Ok(self.0.sign(bytes).to_bytes().to_vec())
    }
}
fn engine(store: &Arc<LocalStore>) -> Engine<'static> {
    let signer = Arc::new(FixedSigner(SigningKey::from_bytes(&[37; 32])));
    Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
        ),
        ExecutionMode::Attended,
        Arc::new(FixedClock),
    )
    .unwrap()
}
fn ingest(
    engine: &Engine<'_>,
    storage: &LocalStore,
    id: &irmind_domain::CaseId,
    root: &std::path::Path,
    name: &str,
    bytes: &[u8],
    parser: &dyn StreamingEventParser,
) {
    fs::write(root.join(name), bytes).unwrap();
    let identity = parser.identity();
    let choices = BTreeMap::from([(
        name.into(),
        ParserSelection {
            parser_id: identity.name.into(),
            parser_version: identity.version.into(),
            confidence: 90,
            mode: ParserSelectionMode::Automatic,
            timestamp_context: None,
            cluster_context: None,
            format_sample_sha256: sha256(bytes),
        },
    )]);
    LargeCaseUseCases {
        engine,
        store: storage,
        parser,
    }
    .ingest_local_batch_selected(
        id,
        root,
        &[name.into()],
        false,
        &choices,
        &CancellationToken::new(),
    )
    .unwrap();
}
fn source_store(root: &std::path::Path) -> Arc<LocalStore> {
    let catalog = MappingCatalog::freeze(
        vec![Arc::new(JsonSourceDecoder), Arc::new(LinuxSourceDecoder)],
        vec![
            Arc::new(irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap()),
            Arc::new(irmind_mod_mapping_linux::AuditMapping::new().unwrap()),
        ],
    )
    .unwrap();
    Arc::new(LocalStore::open_mapped(root, Arc::new(catalog)).unwrap())
}

#[test]
fn signed_cloud_and_interleaved_audit_reconstruct_with_their_own_profiles() {
    let data = tempfile::tempdir().unwrap();
    let inputs = tempfile::tempdir().unwrap();
    let store = source_store(data.path());
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic mixed sources", "local only")
        .unwrap();
    let json = SourceDecoderSelection::new(Arc::new(JsonSourceDecoder));
    ingest(&engine, &store, &case.id, inputs.path(), "cloud.json", br#"{"eventTime":"2026-11-01T01:00:00.000001Z","eventName":"AssumeRole","recipientAccountId":"111111111111","awsRegion":"eu-west-1"}"#, &json);
    let audit = b"node=lab-host type=SYSCALL msg=audit(1793494800.1:1): uid=1000 syscall=59\nnode=lab-host type=SYSCALL msg=audit(1793494800.3:2): uid=1000 syscall=59\nnode=lab-host type=EOE msg=audit(1793494800.3:2):\nnode=lab-host type=EOE msg=audit(1793494800.1:1):\n";
    let linux = SourceDecoderSelection::new(Arc::new(LinuxSourceDecoder));
    ingest(
        &engine,
        &store,
        &case.id,
        inputs.path(),
        "audit.log",
        audit,
        &linux,
    );
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(
        LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &json
        }
        .verify_parquet_rebuild(&case.id, inputs.path(), &CancellationToken::new())
        .unwrap(),
        2
    );
    let partitions = entries
        .iter()
        .filter_map(|e| ParquetArtifact::decode(e.kind, &e.payload).ok())
        .collect::<Vec<_>>();
    for key in [ScopePartitionKey::Account, ScopePartitionKey::Host] {
        assert!(partitions.iter().any(|a| matches!(a, ParquetArtifact::V3(v) if v.core().partition.scopes.iter().any(|s| s.key == key))));
    }
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 3);
    assert!(!store.get_case(&case.id).unwrap().sealed);
    engine.verify(&case.id).unwrap();
}

#[test]
fn a_source_alias_cannot_rebind_already_signed_bytes() {
    let data = tempfile::tempdir().unwrap();
    let inputs = tempfile::tempdir().unwrap();
    let store = source_store(data.path());
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic source alias", "local only")
        .unwrap();
    let json = SourceDecoderSelection::new(Arc::new(JsonSourceDecoder));
    let bytes = br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"Login"}"#;
    ingest(
        &engine,
        &store,
        &case.id,
        inputs.path(),
        "original.json",
        bytes,
        &json,
    );
    let before = store.entries(&case.id).unwrap();
    fs::write(inputs.path().join("alias.json"), bytes).unwrap();
    let result = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &json,
    }
    .ingest_local(
        &case.id,
        inputs.path(),
        "alias.json",
        false,
        &CancellationToken::new(),
    );
    assert!(matches!(
        result,
        Err(AppError::Fixed(
            irmind_app::FixedAppError::PolicyMappedSourceAlreadyIndexed
        ))
    ));
    assert_eq!(store.entries(&case.id).unwrap().len(), before.len());
    engine.verify(&case.id).unwrap();
}
