#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
mod support;
use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::modules::{ModuleConfig, ModuleRegistry, ParserChoice};
use irmind_app::{
    AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, LargeCaseUseCases,
    ParserSelection, Signer, sha256,
};
use irmind_app::{SourceDecoder as _, source_mapping::SourceDecoderSelection};
use irmind_domain::{Actor, ExecutionMode};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
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

struct SyntheticClock;
impl irmind_app::Clock for SyntheticClock {
    fn now(&self) -> Result<u64, irmind_app::AppError> {
        Ok(1_793_491_200)
    }
}

fn setup(root: &Path) -> (Engine<'_>, Arc<LocalStore>, Arc<EvtxParser>) {
    setup_with_clock(root, Arc::new(SystemClock))
}

fn setup_with_clock(
    root: &Path,
    clock: Arc<dyn irmind_app::Clock>,
) -> (Engine<'_>, Arc<LocalStore>, Arc<EvtxParser>) {
    std::fs::create_dir_all(root).unwrap();
    let parser = Arc::new(EvtxParser::new(&support::helper_path(), root));
    assert!(
        parser.unavailable_reason().is_none(),
        "{:?}",
        parser.unavailable_reason()
    );
    let catalog =
        irmind_app::source_mapping::MappingCatalog::freeze(vec![parser.clone()], mapping_modules())
            .unwrap();
    let store = Arc::new(LocalStore::open_mapped(root, Arc::new(catalog)).unwrap());
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
            Arc::new(irmind_mod_parser_json::JsonParser),
        ),
        ExecutionMode::Attended,
        clock,
    )
    .unwrap();
    (engine, store, parser)
}

fn mapping_modules() -> Vec<Arc<dyn irmind_app::SourceMapper>> {
    use irmind_mod_mapping_evtx::{
        PowerShellMapping, SecurityMapping, SysmonMapping, SystemMapping,
    };
    let mut mappings: Vec<Arc<dyn irmind_app::SourceMapper>> = SecurityMapping::EVENT_IDS
        .iter()
        .map(|&id| Arc::new(SecurityMapping::new(id).unwrap()) as Arc<dyn irmind_app::SourceMapper>)
        .collect();
    mappings.push(Arc::new(SystemMapping::new().unwrap()));
    mappings.push(Arc::new(PowerShellMapping::new().unwrap()));
    mappings.push(Arc::new(SysmonMapping::new().unwrap()));
    mappings
}

#[test]
fn detected_evtx_signs_mapped_sources_and_rebuilds_without_ingesting_private_answers() {
    let root = tempfile::tempdir().unwrap();
    let inputs = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/testkit/fixtures/mapping-evtx/source");
    let (engine, store, parser) = setup(root.path());
    let case = engine
        .create_case("Synthetic Windows events", "local evidence only")
        .unwrap();
    let selected = SourceDecoderSelection::new(parser.clone());
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &selected,
    };
    let mut registry = ModuleRegistry::new();
    let detector = EvtxParser::new(&support::helper_path(), root.path());
    registry
        .register(Box::new(detector), &ModuleConfig::new())
        .unwrap();
    let names = [
        "security.evtx".to_owned(),
        "system.evtx".to_owned(),
        "powershell.evtx".to_owned(),
        "sysmon.evtx".to_owned(),
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
                    parser_version: parser.identity().version.into(),
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
        assert_eq!(
            manifest.parser_version,
            irmind_mod_parser_evtx::SOURCE_VERSION
        );
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
    assert_eq!(timeline.len(), 25);
    assert!(timeline.iter().all(|event| event.at.starts_with("2026-")));
    for (kind, value) in [
        ("ip", "203.0.113.77"),
        ("host", "synthetic-endpoint"),
        ("user", "alice"),
    ] {
        let result = parquet.entity_lookup(case, kind, value).unwrap();
        assert!(result.contains(value));
        assert!(
            result.contains("observations=") && !result.contains("observations=0;"),
            "episode entity was lost: {result}"
        );
    }
    assert!(
        parquet
            .text_search(case, "203.0.113.77", 20)
            .unwrap()
            .contains("source=")
    );
    let failure = irmind_domain::GraphQueryFilter::from_args(&std::collections::BTreeMap::from([
        ("event_category".into(), "authentication".into()),
        ("event_outcome".into(), "failure".into()),
    ]))
    .unwrap();
    let failed = parquet.timeline_filtered(case, &failure, 100).unwrap();
    assert!(failed.iter().any(|event| event.record_index == 1));
    assert!(failed.iter().all(|event| event.at.starts_with("2026-")));
    for source in [
        "security.evtx",
        "system.evtx",
        "powershell.evtx",
        "sysmon.evtx",
    ] {
        assert!(store_source_has_records(parquet, case, source));
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
    store.set_parallel_worker_limit(std::num::NonZeroU16::new(3));
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
        parser_version: parser.identity().version.into(),
        confidence: 95,
        mode: irmind_app::ParserSelectionMode::Automatic,
        timestamp_context: None,
        format_sample_sha256: sha256(&bytes[..65536]),
    };
    let selected = SourceDecoderSelection::new(parser.clone());
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &selected,
    };
    let error = use_cases
        .ingest_local_batch_selected(
            &case.id,
            root.path(),
            &["synthetic-corrupt.evtx".into()],
            false,
            &std::collections::BTreeMap::from([("synthetic-corrupt.evtx".into(), selection)]),
            &CancellationToken::new(),
        )
        .unwrap_err();
    assert!(
        matches!(&error, irmind_app::AppError::Policy(message) if message.starts_with("EVTX helper exited unsuccessfully") && message.contains("entire file rejected; no partial ingestion")),
        "unexpected corrupt-source rejection: {error:?}"
    );
    assert!(
        !store
            .entries(&case.id)
            .unwrap()
            .iter()
            .any(|entry| matches!(
                entry.kind,
                irmind_app::AuditEventKind::SourceManifestV2
                    | irmind_app::AuditEventKind::ParquetArtifactV3
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

fn store_source_has_records(store: &LocalStore, case: &irmind_app::CaseId, name: &str) -> bool {
    use irmind_app::EvidenceGraph as _;
    let manifest = store
        .entries(case)
        .unwrap()
        .into_iter()
        .find_map(|entry| {
            if entry.kind != irmind_app::AuditEventKind::SourceManifestV2 {
                return None;
            }
            let manifest = irmind_app::SourceManifestV2::decode(&entry.payload).unwrap();
            (manifest.source.source == name).then_some(manifest)
        })
        .unwrap();
    store
        .raw_record(case, manifest.source.sha256.as_str(), 0)
        .unwrap()
        .contains("Event")
}

#[test]
fn helper_workers_preserve_parquet_commitments_and_every_signed_entry() {
    let root = tempfile::tempdir().unwrap();
    let inputs = root.path().join("inputs");
    std::fs::create_dir(&inputs).unwrap();
    let fixture =
        include_bytes!("../../../crates/testkit/fixtures/parser-evtx/source/Security.evtx");
    let mut bytes = fixture[..4096].to_vec();
    bytes[16..24].copy_from_slice(&7u64.to_le_bytes());
    bytes[42..44].copy_from_slice(&8u16.to_le_bytes());
    let crc = evtx::checksum_ieee(&bytes[..120]);
    bytes[124..128].copy_from_slice(&crc.to_le_bytes());
    for _ in 0..8 {
        bytes.extend_from_slice(&fixture[4096..]);
    }
    std::fs::write(inputs.join("collection.evtx"), bytes).unwrap();
    let seed = root.path().join("seed");
    let (engine, store, parser) = setup_with_clock(&seed, Arc::new(SyntheticClock));
    let case = engine
        .create_case("Synthetic worker equivalence", "local only")
        .unwrap();
    drop((engine, store, parser));
    let mut expected = None;
    for workers in [1, 2, 4, 256] {
        let run = root.path().join(format!("workers-{workers}"));
        std::fs::create_dir(&run).unwrap();
        std::fs::copy(seed.join("irmind.db"), run.join("irmind.db")).unwrap();
        let (engine, store, parser) = setup_with_clock(&run, Arc::new(SyntheticClock));
        store.set_parallel_worker_limit(std::num::NonZeroU16::new(workers));
        let selected = SourceDecoderSelection::new(parser);
        let use_cases = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &selected,
        };
        use_cases
            .ingest_local_batch(
                &case.id,
                &inputs,
                &["collection.evtx".into()],
                false,
                &CancellationToken::new(),
            )
            .unwrap();
        engine.verify(&case.id).unwrap();
        assert_eq!(
            use_cases
                .verify_parquet_rebuild(&case.id, &inputs, &CancellationToken::new())
                .unwrap(),
            1
        );
        let entries = store.entries(&case.id).unwrap();
        let inventory = irmind_app::artifact_catalog(&entries).unwrap().active;
        let actual = (
            entries.iter().map(|entry| entry.hash).collect::<Vec<_>>(),
            inventory,
        );
        assert!(!actual.1.is_empty());
        if let Some(expected) = &expected {
            assert_eq!(&actual, expected, "worker cap {workers}");
        } else {
            expected = Some(actual);
        }
    }
}
