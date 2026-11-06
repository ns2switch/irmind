#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::StreamingEventParser as _;
use irmind_app::modules::{ModuleConfig, ModuleRegistry, ParserChoice};
use irmind_app::{
    AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, LargeCaseUseCases,
    ParserSelection, Signer, sha256,
};
use irmind_domain::{Actor, ExecutionMode};
use irmind_infra::{LocalStore, LocalVerifier, ParquetStore, SystemClock};
use irmind_mod_parser_evtx::EvtxParser;
use irmind_security::MandatoryGuard;
use std::{path::Path, sync::Arc};
struct SyntheticSigner(SigningKey);
impl Signer for SyntheticSigner {
    fn actor(&self) -> Actor {
        Actor::Analyst
    }
    fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().to_bytes().to_vec()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, irmind_app::AppError> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }
}

#[test]
fn detected_evtx_signs_v2_sources_and_rebuilds_without_ingesting_private_answers() {
    let root = tempfile::tempdir().unwrap();
    let inputs = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/testkit/fixtures/parser-evtx/source");
    let parser = Arc::new(EvtxParser::new(
        Path::new(env!("CARGO_BIN_EXE_irmind-evtx")),
        root.path(),
    ));
    assert!(
        parser.unavailable_reason().is_none(),
        "{:?}",
        parser.unavailable_reason()
    );
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[19; 32])));
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let case = engine
        .create_case("Synthetic Windows events", "local evidence only")
        .unwrap();
    let parquet = ParquetStore::open_precise(root.path()).unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &parquet,
        parser: parser.as_ref(),
    };
    let mut registry = ModuleRegistry::new();
    let detector = EvtxParser::new(Path::new(env!("CARGO_BIN_EXE_irmind-evtx")), root.path());
    registry
        .register(Box::new(detector), &ModuleConfig::new())
        .unwrap();
    let names = [
        "Security.evtx".to_owned(),
        "System.evtx".to_owned(),
        "Microsoft-Windows-PowerShell.evtx".to_owned(),
        "Microsoft-Windows-Sysmon.evtx".to_owned(),
    ];
    let selections = names
        .iter()
        .map(|name| {
            let bytes = std::fs::read(inputs.join(name)).unwrap();
            let sample = &bytes[..bytes.len().min(65536)];
            assert!(matches!(
                registry.detect_parser(name, sample),
                ParserChoice::Auto(_)
            ));
            (
                name.clone(),
                ParserSelection {
                    parser_id: "parser-evtx".into(),
                    parser_version: parser.streaming_version().into(),
                    confidence: 95,
                    mode: irmind_app::ParserSelectionMode::Automatic,
                    timestamp_context: None,
                    format_sample_sha256: sha256(sample),
                },
            )
        })
        .collect();
    assert_eq!(
        use_cases
            .ingest_local_batch_selected(
                &case.id,
                &inputs,
                &names,
                false,
                &selections,
                &CancellationToken::new()
            )
            .unwrap()
            .len(),
        4
    );
    engine.verify(&case.id).unwrap();
    assert!(
        use_cases
            .verify_parquet(&case.id, &CancellationToken::new())
            .unwrap()
            > 0
    );
    assert!(
        use_cases
            .verify_parquet_rebuild(&case.id, &inputs, &CancellationToken::new())
            .unwrap()
            > 0
    );
    let entries = store.entries(&case.id).unwrap();
    let sources = entries
        .iter()
        .filter(|entry| entry.kind == irmind_app::AuditEventKind::SourceManifestV2)
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 4);
    for entry in sources {
        let manifest = irmind_app::SourceManifestV2::decode(&entry.payload).unwrap();
        assert_eq!(manifest.parser_version, irmind_mod_parser_evtx::VERSION);
        assert!(
            Path::new(&manifest.source.source)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("evtx"))
        );
    }
    assert!(
        !entries
            .iter()
            .any(|entry| entry.payload.contains("ground-truth"))
    );
}
