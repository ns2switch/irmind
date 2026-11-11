#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
#![cfg(all(feature = "parser-json", feature = "parser-declarative"))]

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CryptoPorts, DefinitionCompiler, Engine, EnginePorts,
    EvidenceGraph, LargeCaseUseCases, ParserDefinitionStore, ParserSelection, Signer,
    modules::{ModuleConfig, ModuleRegistry, ParserChoice},
    sha256,
};
use irmind_domain::{Actor, AuditEventKind, ExecutionMode, ParserSelectionMode, SourceManifestV2};
use irmind_infra::{FileDefinitionStore, LocalStore, LocalVerifier, SystemClock};
use irmind_mod_parser_declarative::{DeclarativeCompiler, DeclarativeModule};
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use std::{fs, sync::Arc};

const DEFINITION: &str = include_str!("../../../docs/examples/parsers/access-csv.toml");
const SAMPLE: &[u8] = b"time,host,user,source_ip,action,outcome\n2026-01-01T00:00:00Z,synthetic-host,alice,203.0.113.77,login,success\n";
struct SyntheticSigner(SigningKey);
impl Signer for SyntheticSigner {
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
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[99; 32])));
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
            Arc::new(MandatoryGuard::new().unwrap()),
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
}

#[test]
fn approved_definitions_are_pinned_signed_and_rebuild_after_replacement_or_removal() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let engine = engine(&store);
    let definitions = FileDefinitionStore::new(root.path());
    let id = engine
        .install_parser_definition(&definitions, &DeclarativeCompiler, DEFINITION)
        .unwrap();
    let approved = engine.approved_definitions().unwrap();
    let (active, statuses) = approved.load_active(&definitions, &DeclarativeCompiler);
    assert_eq!(active.len(), 1);
    assert!(statuses[0].available && statuses[0].active);
    let parser: Arc<dyn irmind_app::LogParser> = Arc::new(
        irmind_app::source_mapping::SourceDecoderSelection::new(
            active[0].compiled().decoder().clone(),
        )
        .with_selector(active[0].compiled().selector().clone())
        .unwrap(),
    );
    let version = parser.identity().version.to_owned();
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(JsonParser), &ModuleConfig::new())
        .unwrap();
    registry
        .register(
            Box::new(DeclarativeModule::new(active).unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    assert!(matches!(
        registry.detect_parser("access.csv", SAMPLE),
        ParserChoice::NeedsAnalyst(_)
    ));
    let registry =
        registry.with_definition_history(approved.clone(), Arc::new(DeclarativeCompiler));
    let mapped_store =
        LocalStore::open_mapped(root.path(), Arc::new(registry.mapping_catalog().unwrap()))
            .unwrap();
    let catalog = registry
        .parser_catalog()
        .with_resolver(approved.resolver(Arc::new(DeclarativeCompiler)));
    let source_root = root.path().join("input");
    fs::create_dir(&source_root).unwrap();
    fs::write(source_root.join("access.csv"), SAMPLE).unwrap();
    let case = engine
        .create_case("Synthetic declarative case", "local evidence only")
        .unwrap();
    let selected = std::collections::BTreeMap::from([(
        "access.csv".into(),
        ParserSelection {
            parser_id: id.clone(),
            parser_version: version.clone(),
            confidence: 65,
            mode: ParserSelectionMode::Forced,
            timestamp_context: parser.timestamp_context().map(str::to_owned),
            format_sample_sha256: sha256(SAMPLE),
        },
    )]);
    LargeCaseUseCases {
        engine: &engine,
        store: &mapped_store,
        parser: parser.as_ref(),
    }
    .ingest_local_batch_selected(
        &case.id,
        &source_root,
        &["access.csv".into()],
        false,
        &selected,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(store.timeline(&case.id, 10).unwrap().len(), 1);
    let entries = store.entries(&case.id).unwrap();
    let manifest = entries
        .iter()
        .find(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        .unwrap();
    let manifest = SourceManifestV2::decode(&manifest.payload).unwrap();
    assert_eq!(manifest.parser_version, version);
    assert_eq!(manifest.parser_id, id);
    assert!(version.ends_with(&irmind_app::hex(&sha256(DEFINITION.as_bytes()))));
    // Replacement is signed. Old case reconstruction still resolves the old exact bytes.
    engine
        .install_parser_definition(
            &definitions,
            &DeclarativeCompiler,
            &DEFINITION.replace(
                "Synthetic comma-separated access events",
                "Revised synthetic comma-separated access events",
            ),
        )
        .unwrap();
    engine
        .deactivate_parser_definition(&definitions, &id)
        .unwrap();
    let history = engine.approved_definitions().unwrap();
    let catalog = catalog.with_resolver(history.resolver(Arc::new(DeclarativeCompiler)));
    let router = catalog.rebuild_router(&entries).unwrap();
    assert_eq!(
        LargeCaseUseCases {
            engine: &engine,
            store: &mapped_store,
            parser: &router
        }
        .verify_parquet_rebuild(&case.id, &source_root, &CancellationToken::new())
        .unwrap(),
        1
    );
    engine.verify(&case.id).unwrap();
    engine.verify_global_operations().unwrap();
    assert_eq!(store.global_operations().unwrap().len(), 3);
}

#[test]
fn unsigned_or_manually_changed_definitions_are_disabled_and_require_explicit_restore() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let engine = engine(&store);
    let definitions = FileDefinitionStore::new(root.path());
    let id = engine
        .install_parser_definition(&definitions, &DeclarativeCompiler, DEFINITION)
        .unwrap();
    definitions
        .write_active(&id, "invalid manual edit")
        .unwrap();
    definitions.write_active("unsigned", DEFINITION).unwrap();
    let approved = engine.approved_definitions().unwrap();
    let (active, statuses) = approved.load_active(&definitions, &DeclarativeCompiler);
    assert!(active.is_empty());
    assert_eq!(statuses.len(), 2);
    assert!(statuses.iter().all(|status| status.warning.is_some()));
    engine.restore_parser_definition(&definitions, &id).unwrap();
    assert_eq!(
        definitions.read_active(&id).unwrap().as_deref(),
        Some(DEFINITION)
    );
    assert_eq!(
        engine
            .approved_definitions()
            .unwrap()
            .load_active(&definitions, &DeclarativeCompiler)
            .0
            .len(),
        1
    );
}

#[test]
fn preview_is_guarded_bounded_and_does_not_create_a_case_or_send_to_a_model() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let engine = engine(&store);
    let preview = engine
        .preview_parser_definition(&DeclarativeCompiler, DEFINITION, SAMPLE)
        .unwrap();
    assert!(preview.contains("1 preview rows"));
    assert!(!preview.contains('\x1b'));
    assert!(store.global_operations().unwrap().is_empty());
    assert!(
        engine
            .preview_parser_definition(
                &DeclarativeCompiler,
                DEFINITION,
                &vec![b'x'; 1024 * 1024 + 1]
            )
            .is_err()
    );
    assert!(DeclarativeCompiler.compile("unknown = true").is_err());
}

struct InterruptedWrite<'a>(&'a FileDefinitionStore);
impl ParserDefinitionStore for InterruptedWrite<'_> {
    fn read_active(&self, id: &str) -> Result<Option<String>, AppError> {
        self.0.read_active(id)
    }
    fn write_active(&self, _: &str, _: &str) -> Result<(), AppError> {
        Err(AppError::Storage(
            "simulated interrupted atomic write".into(),
        ))
    }
    fn archive(&self, hash: &str, contents: &str) -> Result<(), AppError> {
        self.0.archive(hash, contents)
    }
    fn deactivate(&self, id: &str) -> Result<(), AppError> {
        self.0.deactivate(id)
    }
    fn names(&self) -> Result<Vec<String>, AppError> {
        self.0.names()
    }
}

#[test]
fn interrupted_write_stays_disabled_until_the_analyst_restores_signed_bytes() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let engine = engine(&store);
    let definitions = FileDefinitionStore::new(root.path());
    let id = DeclarativeCompiler
        .compile(DEFINITION)
        .unwrap()
        .selector()
        .identity()
        .name
        .to_owned();
    assert!(
        engine
            .install_parser_definition(
                &InterruptedWrite(&definitions),
                &DeclarativeCompiler,
                DEFINITION
            )
            .is_err()
    );
    let approved = engine.approved_definitions().unwrap();
    let (active, statuses) = approved.load_active(&definitions, &DeclarativeCompiler);
    assert!(active.is_empty());
    assert!(statuses[0].warning.is_some());
    assert!(definitions.read_active(&id).unwrap().is_none());
    engine.restore_parser_definition(&definitions, &id).unwrap();
    assert_eq!(
        definitions.read_active(&id).unwrap().as_deref(),
        Some(DEFINITION)
    );
    assert_eq!(store.global_operations().unwrap().len(), 2);
    engine.verify_global_operations().unwrap();
}

#[test]
#[ignore = "manual 1 GiB ingestion measurement; not pull-request CI"]
fn benchmark_declarative_one_gib() {
    use std::io::Write as _;
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("sources");
    fs::create_dir(&source).unwrap();
    let public = include_str!("../../testkit/fixtures/parser-declarative/source/events.ndjson")
        .lines()
        .next()
        .unwrap();
    let line = format!(
        "{},\"padding\":\"{}\"}}\n",
        public.trim_end_matches('}'),
        "x".repeat(800)
    );
    let mut writer =
        std::io::BufWriter::new(fs::File::create(source.join("synthetic.ndjson")).unwrap());
    let mut bytes = 0u64;
    while bytes < 1024 * 1024 * 1024 {
        writer.write_all(line.as_bytes()).unwrap();
        bytes += line.len() as u64;
    }
    writer.flush().unwrap();
    drop(writer);
    let store = Arc::new(LocalStore::open(&root.path().join("data")).unwrap());
    let engine = engine(&store);
    let parser = DeclarativeCompiler
        .compile(include_str!(
            "../../../docs/examples/parsers/nested-ndjson.toml"
        ))
        .unwrap()
        .selector()
        .clone();
    let mut sample = Vec::new();
    {
        use std::io::Read as _;
        fs::File::open(source.join("synthetic.ndjson"))
            .unwrap()
            .take(65536)
            .read_to_end(&mut sample)
            .unwrap();
    }
    let case = engine
        .create_case("Synthetic declarative benchmark", "local evidence only")
        .unwrap();
    let selected = std::collections::BTreeMap::from([(
        "synthetic.ndjson".into(),
        ParserSelection {
            parser_id: parser.identity().name.into(),
            parser_version: parser.identity().version.into(),
            confidence: 70,
            mode: ParserSelectionMode::Forced,
            timestamp_context: parser.timestamp_context().map(str::to_owned),
            format_sample_sha256: sha256(&sample),
        },
    )]);
    let started = std::time::Instant::now();
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: parser.as_ref(),
    }
    .ingest_local_batch_selected(
        &case.id,
        &source,
        &["synthetic.ndjson".into()],
        false,
        &selected,
        &CancellationToken::new(),
    )
    .unwrap();
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "declarative-ndjson: {bytes} bytes in {seconds:.3} s ({:.2} MiB/s)",
        1024.0 / seconds
    );
    engine.verify(&case.id).unwrap();
    assert_eq!(store.timeline(&case.id, 1).unwrap().len(), 1);
}

#[test]
fn unattended_sessions_cannot_approve_definition_changes() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let mut engine = engine(&store);
    engine.mode = ExecutionMode::Unattended;
    assert!(
        engine
            .install_parser_definition(
                &FileDefinitionStore::new(root.path()),
                &DeclarativeCompiler,
                DEFINITION
            )
            .is_err()
    );
    assert!(store.global_operations().unwrap().is_empty());
}

#[test]
fn synthetic_episode_maps_expected_entities_without_ingesting_private_answers() {
    let source = include_bytes!("../../testkit/fixtures/parser-declarative/source/events.ndjson");
    let parser = DeclarativeCompiler
        .compile(include_str!(
            "../../../docs/examples/parsers/nested-ndjson.toml"
        ))
        .unwrap()
        .selector()
        .clone();
    let mut rows = Vec::new();
    let report = parser
        .parse_reader_report(
            "events.ndjson",
            &mut std::io::Cursor::new(source),
            sha256(source),
            &CancellationToken::new(),
            &mut |row| {
                row.inspect(|record| rows.push(record.clone()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(report.accepted, 2);
    // Expected answers are accessed by this evaluator only, after public parsing.
    let answers: serde_json::Value = serde_json::from_str(include_str!(
        "../../testkit/fixtures/parser-declarative/private/ground-truth.json"
    ))
    .unwrap();
    for value in answers["malicious_entities"].as_array().unwrap() {
        assert!(
            rows.iter()
                .flat_map(|row| &row.entities)
                .any(|(_, entity)| Some(entity.as_str()) == value.as_str())
        );
    }
    assert!(
        rows.iter()
            .all(|row| !row.text.contains("PRIVATE-DECLARATIVE-EVALUATOR-ANSWER"))
    );
    assert!(rows[0].at < rows[1].at);
    assert!(rows[0].text.contains(".000001Z"));
}

#[test]
fn authenticated_definition_registers_and_rebuilds_the_mapped_pipeline() {
    let root = tempfile::tempdir().unwrap();
    let base = Arc::new(LocalStore::open(root.path()).unwrap());
    let engine = engine(&base);
    let definitions = FileDefinitionStore::new(root.path());
    let id = engine
        .install_parser_definition(&definitions, &DeclarativeCompiler, DEFINITION)
        .unwrap();
    let approved = engine.approved_definitions().unwrap();
    let (active, statuses) = approved.load_active(&definitions, &DeclarativeCompiler);
    assert!(statuses[0].available);
    let original = active[0].compiled().selector().clone();
    let selector: Arc<dyn irmind_app::LogParser> = Arc::new(
        irmind_app::source_mapping::SourceDecoderSelection::new(
            active[0].compiled().decoder().clone(),
        )
        .with_selector(original)
        .unwrap(),
    );
    let mut registry = ModuleRegistry::new();
    registry
        .register(
            Box::new(DeclarativeModule::new(active).unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    let mappings = registry.mapping_catalog().unwrap();
    assert!(mappings.supports_decoder(&id, selector.identity().version));
    let mapped = LocalStore::open_mapped(root.path(), Arc::new(mappings)).unwrap();
    let source = root.path().join("input");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("access.csv"), SAMPLE).unwrap();
    let case = engine
        .create_case("Synthetic mapped definition", "local evidence only")
        .unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: &mapped,
        parser: selector.as_ref(),
    }
    .ingest_local_batch(
        &case.id,
        &source,
        &["access.csv".into()],
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    assert_eq!(mapped.timeline(&case.id, 10).unwrap().len(), 1);
    engine.verify(&case.id).unwrap();
    let entries = base.entries(&case.id).unwrap();
    let router = registry.parser_catalog().rebuild_router(&entries).unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: &mapped,
        parser: &router,
    }
    .verify_parquet_rebuild(&case.id, &source, &CancellationToken::new())
    .unwrap();
    let descriptor = mapped.entity_lookup(&case.id, "user", "alice").unwrap();
    assert!(descriptor.contains("alice"));
    let ip = mapped
        .entity_lookup(&case.id, "ip", "203.0.113.77")
        .unwrap();
    assert!(ip.contains("203.0.113.77"));
}

#[path = "declarative/history.rs"]
mod history;
