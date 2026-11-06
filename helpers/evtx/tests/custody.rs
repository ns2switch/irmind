#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod support;
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

fn setup(root: &Path) -> (Engine<'_>, Arc<LocalStore>, Arc<EvtxParser>) {
    let parser = Arc::new(EvtxParser::new(&support::helper_path(), root));
    assert!(
        parser.unavailable_reason().is_none(),
        "{:?}",
        parser.unavailable_reason()
    );
    let store = Arc::new(LocalStore::open(root).unwrap());
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
    (engine, store, parser)
}

#[test]
fn detected_evtx_signs_v2_sources_and_rebuilds_without_ingesting_private_answers() {
    let root = tempfile::tempdir().unwrap();
    let inputs = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/testkit/fixtures/parser-evtx/source");
    let (engine, store, parser) = setup(root.path());
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
    let detector = EvtxParser::new(&support::helper_path(), root.path());
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
    assert_episode_queries(store.as_ref(), &case.id);

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
    assert!(!entries.iter().any(|entry| {
        entry.payload.contains("ground-truth")
            || entry
                .payload
                .contains("IRMind-EVTX-synthetic-evaluator-only")
    }));
}

fn assert_episode_queries(parquet: &LocalStore, case: &irmind_app::CaseId) {
    use irmind_app::EvidenceGraph as _;
    let timeline = parquet.timeline(case, 100).unwrap();
    assert_eq!(timeline.len(), 27);
    assert!(
        timeline
            .iter()
            .any(|event| event.event.contains("logon_success"))
    );
    assert!(
        timeline
            .iter()
            .any(|event| event.event.contains("service_install"))
    );
    for (kind, value) in [
        ("ip", "203.0.113.77"),
        ("host", "synthetic-endpoint"),
        ("user", "synthetic-user"),
    ] {
        let result = parquet.entity_lookup(case, kind, value).unwrap();
        assert!(result.contains(value));
        assert!(
            result.contains("count=27;"),
            "episode entity was lost: {result}"
        );
    }
    assert!(
        parquet
            .text_search(case, "203.0.113.77", 20)
            .unwrap()
            .contains("source=")
    );
    for action in ["logon_success", "service_install"] {
        assert!(
            parquet
                .text_search(case, action, 20)
                .unwrap()
                .contains(action)
        );
    }
    assert!(
        parquet
            .neighbors(case, "ip", "203.0.113.77", 20)
            .unwrap()
            .contains("synthetic-endpoint")
    );
    assert!(
        parquet
            .graph_path(case, ("ip", "203.0.113.77"), ("host", "synthetic-endpoint"))
            .unwrap()
            .contains("synthetic-endpoint")
    );
}

#[test]
fn invalid_later_chunk_rolls_back_every_partial_row_and_manifest() {
    let root = tempfile::tempdir().unwrap();
    let (engine, store, parser) = setup(root.path());
    let case = engine
        .create_case("Synthetic corrupt second chunk", "local evidence only")
        .unwrap();
    let fixture =
        include_bytes!("../../../crates/testkit/fixtures/parser-evtx/source/Security.evtx");
    let mut bytes = fixture.to_vec();
    bytes[16..24].copy_from_slice(&1u64.to_le_bytes());
    bytes[42..44].copy_from_slice(&2u16.to_le_bytes());
    let crc = evtx::checksum_ieee(&bytes[..120]);
    bytes[124..128].copy_from_slice(&crc.to_le_bytes());
    bytes.extend_from_slice(&fixture[4096..]);
    bytes[4096 + 65536 + 6000] ^= 1;
    std::fs::write(root.path().join("synthetic-corrupt.evtx"), &bytes).unwrap();
    let selection = ParserSelection {
        parser_id: "parser-evtx".into(),
        parser_version: parser.streaming_version().into(),
        confidence: 95,
        mode: irmind_app::ParserSelectionMode::Automatic,
        timestamp_context: None,
        format_sample_sha256: sha256(&bytes[..65536]),
    };
    let parquet = ParquetStore::open_precise(root.path()).unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &parquet,
        parser: parser.as_ref(),
    };
    assert!(
        use_cases
            .ingest_local_batch_selected(
                &case.id,
                root.path(),
                &["synthetic-corrupt.evtx".into()],
                false,
                &std::collections::BTreeMap::from([("synthetic-corrupt.evtx".into(), selection)]),
                &CancellationToken::new()
            )
            .is_err()
    );
    assert!(
        !store
            .entries(&case.id)
            .unwrap()
            .iter()
            .any(|entry| matches!(
                entry.kind,
                irmind_app::AuditEventKind::SourceManifestV2
                    | irmind_app::AuditEventKind::ParquetArtifactV2
            ))
    );
    assert_eq!(
        use_cases
            .verify_parquet(&case.id, &CancellationToken::new())
            .unwrap(),
        0
    );
    engine.verify(&case.id).unwrap();
}
