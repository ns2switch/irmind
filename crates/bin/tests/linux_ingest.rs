#![forbid(unsafe_code)]
#![cfg(feature = "parser-linux")]
#![allow(clippy::unwrap_used)]
#[path = "support/current_sources.rs"]
mod current_sources;

use ed25519_dalek::{Signer as _, SigningKey};
use irmind_app::{
    AppError, AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    LargeCaseUseCases, ParserTimeBasis, ParserTimeContext, Signer, modules::ParserSelectionRequest,
};
use irmind_domain::{Actor, AuditEventKind, ExecutionMode, SourceManifestV2};
use irmind_infra::{LocalStore, LocalVerifier, SystemClock};
use std::{collections::BTreeMap, fs, sync::Arc};

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
    let signer = Arc::new(SyntheticSigner(SigningKey::from_bytes(&[45; 32])));
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
            current_sources::event_parser(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap()
}
fn catalog() -> irmind_app::modules::ParserCatalog {
    current_sources::catalog()
}
fn sources() -> [(&'static str, &'static [u8]); 4] {
    [
        (
            "auth.log",
            include_bytes!("../../testkit/fixtures/parser-linux/source/auth.log"),
        ),
        (
            "audit.log",
            include_bytes!("../../testkit/fixtures/parser-linux/source/audit.log"),
        ),
        (
            "journal.jsonl",
            include_bytes!("../../testkit/fixtures/parser-linux/source/journal.jsonl"),
        ),
        (
            "access.log",
            include_bytes!("../../testkit/fixtures/parser-linux/source/access.log"),
        ),
    ]
}
#[test]
#[allow(clippy::too_many_lines)]
fn synthetic_linux_episode_is_detected_signed_queryable_and_reproducible() {
    let root = tempfile::tempdir().unwrap();
    let originals = root.path().join("sources");
    fs::create_dir(&originals).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("case")));
    let engine = engine(&store);
    let case = engine
        .create_case("Synthetic Linux episode", "local")
        .unwrap();
    let catalog = catalog();
    for (name, bytes) in sources() {
        fs::write(originals.join(name), bytes).unwrap();
        let context = (name == "auth.log")
            .then(|| ParserTimeContext::new(2026, 0, true, ParserTimeBasis::Analyst).unwrap());
        let resolved = catalog
            .select_source(ParserSelectionRequest {
                source: name,
                sample: bytes,
                parser_override: None,
                forced: false,
                time_context: context,
            })
            .unwrap();
        assert_eq!(resolved.selection.parser_id, "parser-linux");
        let selected = BTreeMap::from([(name.into(), resolved.selection)]);
        let result = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: resolved.parser.as_ref(),
        }
        .ingest_local_batch_selected(
            &case.id,
            &originals,
            &[name.into()],
            false,
            &selected,
            &CancellationToken::new(),
        );
        assert!(result.is_ok(), "{name}: {result:?}");
    }
    let entries = store.entries(&case.id).unwrap();
    let manifests = entries
        .iter()
        .filter(|entry| entry.kind == AuditEventKind::SourceManifestV2)
        .map(|entry| SourceManifestV2::decode(&entry.payload).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(manifests.len(), 4);
    assert!(
        manifests
            .iter()
            .all(|manifest| manifest.parser_id == "parser-linux" && !manifest.source.copied)
    );
    assert!(
        manifests
            .iter()
            .find(|source| source.source.source == "auth.log")
            .unwrap()
            .timestamp_context
            .as_ref()
            .unwrap()
            .contains("basis=analyst")
    );
    let timeline = store.timeline(&case.id, 100).unwrap();
    assert_eq!(timeline.len(), 11);
    for event in ["sshd", "sudo", "cron_command", "journal_entry", "GET"] {
        assert!(
            timeline
                .iter()
                .any(|row| row.event.split(" [").next() == Some(event)),
            "missing {event}; timeline: {timeline:?}"
        );
    }
    assert!(
        timeline
            .iter()
            .any(|row| row.event.contains("second precision; inferred"))
    );
    assert!(
        timeline
            .iter()
            .any(|row| row.event.contains("microsecond precision"))
    );
    let audit_hash = manifests
        .iter()
        .find(|m| m.source.source == "audit.log")
        .unwrap()
        .source
        .sha256
        .as_str();
    assert!(
        store
            .text_search(&case.id, "EXECVE", 20)
            .unwrap()
            .contains(audit_hash)
    );
    assert!(
        store
            .raw_record(&case.id, audit_hash, 0)
            .unwrap()
            .contains("EXECVE")
    );
    for (kind, value) in [
        ("host", "synthetic-linux"),
        ("user", "synthetic-user"),
        ("ip", "203.0.113.77"),
        ("user", "root"),
    ] {
        assert!(
            store
                .entity_lookup(&case.id, kind, value)
                .unwrap()
                .contains(value)
        );
    }
    assert!(
        store
            .text_search(&case.id, "203.0.113.77", 10)
            .unwrap()
            .contains("sshd")
    );
    let neighbors = store
        .neighbors(&case.id, "host", "synthetic-linux", 20)
        .unwrap();
    assert!(neighbors.contains("203.0.113.77"), "{neighbors}");
    assert!(
        store
            .neighbors(&case.id, "user", "root", 20)
            .unwrap()
            .contains("synthetic-linux")
    );
    assert!(
        store
            .entity_timeline(&case.id, "host", "synthetic-linux", 20)
            .unwrap()
            .contains("sudo")
    );
    let router = catalog.rebuild_router(&entries).unwrap();
    assert_eq!(
        LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &router
        }
        .verify_parquet_rebuild(&case.id, &originals, &CancellationToken::new())
        .unwrap(),
        4
    );
    engine.verify(&case.id).unwrap();
    let marker = "IRMind-Linux-synthetic-evaluator-only";
    assert!(!entries.iter().any(|entry| entry.payload.contains(marker)));
    assert!(!store.graph_summary(&case.id).unwrap().contains(marker));
    assert!(
        !store
            .text_search(&case.id, marker, 10)
            .unwrap()
            .contains(marker)
    );
}

#[test]
fn missing_context_refuses_native_selection_and_has_an_audited_reason() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("case")));
    let engine = engine(&store);
    let case = engine
        .create_case("No implicit source year", "local")
        .unwrap();
    let catalog = catalog();
    let error = catalog
        .select_source(ParserSelectionRequest {
            source: "auth.log",
            sample: sources()[0].1,
            parser_override: None,
            forced: false,
            time_context: None,
        })
        .err()
        .unwrap();
    assert!(matches!(
        engine.annotate_parser_time_error(
            &case.id,
            error,
            &catalog,
            &CancellationToken::new(),
            false
        ),
        AppError::ParserTimeContextRequired { .. }
    ));
    assert_eq!(
        store.entries(&case.id).unwrap().last().unwrap().kind,
        AuditEventKind::ParserSelectionRequired
    );
    assert!(store.timeline(&case.id, 10).unwrap().is_empty());
    engine.verify(&case.id).unwrap();
}

#[path = "linux_ingest/benchmark.rs"]
mod benchmark;

#[test]
#[cfg(feature = "parser-declarative")]
fn custom_http_export_definition_is_bounded_and_needs_analyst_selection() {
    use irmind_app::DefinitionCompiler as _;
    let pipeline = irmind_mod_parser_declarative::DeclarativeCompiler
        .compile(include_str!(
            "../../../docs/examples/parsers/nginx-apache-custom.toml"
        ))
        .unwrap();
    let bytes = br#"{"custom_http":{"time":"2026-11-01T01:00:00Z","host":"synthetic-web","user":"synthetic-user","client":"203.0.113.77","method":"GET","status":"200"}}"#;
    assert_eq!(
        pipeline
            .selector()
            .detect("synthetic.json", bytes)
            .unwrap()
            .value(),
        70
    );
    let mut hosts = vec![];
    let report = irmind_testkit::decode_source(
        pipeline.decoder().as_ref(),
        "synthetic.json",
        &mut &bytes[..],
        irmind_app::sha256(bytes),
        &CancellationToken::new(),
        None,
        &mut |record| {
            record.inspect(|source| {
                let mapped = pipeline.extraction_mapper().map(source).unwrap();
                hosts.extend(
                    mapped
                        .record()
                        .indexed
                        .record
                        .entities
                        .iter()
                        .filter(|(kind, _)| kind == "host")
                        .map(|(_, value)| value.clone()),
                );
            });
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.accepted, 1);
    assert_eq!(hosts, ["synthetic-web"]);
}
