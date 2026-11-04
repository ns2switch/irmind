#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#![cfg(all(feature = "parser-json", feature = "parser-linux"))]
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::modules::{ModuleConfig, ModuleRegistry};
use irmind_app::{
    AppError, AuditLog, CancellationToken, Clock, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, ParserSelection, Repository, Signer, StreamingEventParser, sha256,
};
use irmind_domain::{
    Actor, ExecutionMode, ParquetArtifact, ParserSelectionMode, ScopePartitionKey,
};
use irmind_infra::{LocalStore, LocalVerifier, ParquetStore};
use irmind_mod_parser_json::JsonParser;
use irmind_mod_parser_linux::LinuxParser;
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
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(FixedClock),
    )
    .unwrap()
}
fn ingest(
    engine: &Engine<'_>,
    storage: &ParquetStore,
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
#[test]
fn signed_cloud_and_interleaved_audit_reconstruct_with_their_own_profiles() {
    let data = tempfile::tempdir().unwrap();
    let inputs = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(data.path()).unwrap());
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic mixed parsers", "local only")
        .unwrap();
    let precise = ParquetStore::open_precise(data.path()).unwrap();
    ingest(&engine, &precise, &case.id, inputs.path(), "cloud.json", br#"{"eventTime":"2026-11-01T01:00:00.000001Z","eventName":"AssumeRole","recipientAccountId":"111111111111","awsRegion":"eu-west-1"}"#, &JsonParser);
    let audit = b"node=lab-host type=SYSCALL msg=audit(1793494800.1:1): uid=1000 syscall=59\nnode=lab-host type=SYSCALL msg=audit(1793494800.3:2): uid=1000 syscall=59\nnode=lab-host type=EOE msg=audit(1793494800.3:2):\nnode=lab-host type=EOE msg=audit(1793494800.1:1):\n";
    ingest(
        &engine,
        &precise,
        &case.id,
        inputs.path(),
        "audit.log",
        audit,
        &LinuxParser::default(),
    );
    let entries = store.entries(&case.id).unwrap();
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(JsonParser), &ModuleConfig::default())
        .unwrap();
    registry
        .register(Box::<LinuxParser>::default(), &ModuleConfig::default())
        .unwrap();
    let router = registry.parser_catalog().rebuild_router(&entries).unwrap();
    assert_eq!(
        LargeCaseUseCases {
            engine: &engine,
            store: &precise,
            parser: &router
        }
        .verify_parquet_rebuild(&case.id, inputs.path(), &CancellationToken::new())
        .unwrap(),
        2
    );
    let partitions = entries
        .iter()
        .filter_map(|e| ParquetArtifact::decode(e.kind, &e.payload).ok())
        .collect::<Vec<_>>();
    assert!(partitions.iter().any(|a| matches!(a, ParquetArtifact::V2(v) if v.partition.scopes.iter().any(|s| s.key == ScopePartitionKey::Account))));
    assert!(partitions.iter().any(|a| matches!(a, ParquetArtifact::V2(v) if v.partition.scopes.iter().any(|s| s.key == ScopePartitionKey::Host))));
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 3);
    assert!(!store.get_case(&case.id).unwrap().sealed);
    engine.verify(&case.id).unwrap();
}

#[test]
fn a_source_alias_cannot_bypass_explicit_generation_migration() {
    let data = tempfile::tempdir().unwrap();
    let inputs = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(data.path()).unwrap());
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic generation guard", "local only")
        .unwrap();
    let bytes = br#"{"eventTime":"2026-11-01T00:00:00Z","host":"lab-host"}"#;
    fs::write(inputs.path().join("old.json"), bytes).unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &JsonParser,
    }
    .ingest_local(
        &case.id,
        inputs.path(),
        "old.json",
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let count = store.entries(&case.id).unwrap().len();
    fs::write(inputs.path().join("alias.json"), bytes).unwrap();
    let precise = ParquetStore::open_precise(data.path()).unwrap();
    let choices = BTreeMap::from([(
        "alias.json".into(),
        ParserSelection {
            parser_id: "parser-json".into(),
            parser_version: "json-stream-v2".into(),
            confidence: 90,
            mode: ParserSelectionMode::Automatic,
            timestamp_context: None,
            format_sample_sha256: sha256(bytes),
        },
    )]);
    let result = LargeCaseUseCases {
        engine: &engine,
        store: &precise,
        parser: &JsonParser,
    }
    .ingest_local_batch_selected(
        &case.id,
        inputs.path(),
        &["alias.json".into()],
        false,
        &choices,
        &CancellationToken::new(),
    );
    assert!(matches!(
        result,
        Err(AppError::Fixed(
            irmind_app::FixedAppError::PolicyArtifactVersionRequiresMigration
        ))
    ));
    assert_eq!(store.entries(&case.id).unwrap().len(), count);
    engine.verify(&case.id).unwrap();
}
