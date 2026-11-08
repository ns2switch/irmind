#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{
    AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, LargeCaseUseCases,
    ParserSelection, SignerBackend,
};
use irmind_domain::{Actor, ExecutionMode, ParquetArtifact, ParserSelectionMode};
use irmind_infra::{LocalExportVerifier, LocalVerifier, SystemClock};
use irmind_mod_keystore_file::FileKeystore;
use irmind_mod_parser_json::JsonParser;
use irmind_security::MandatoryGuard;
use std::{collections::BTreeMap, sync::Arc};

fn setup(root: &Path, legacy: bool) -> (Arc<LocalStore>, Engine<'static>) {
    let store = Arc::new(
        if legacy {
            LocalStore::open(root)
        } else {
            open(root)
        }
        .unwrap(),
    );
    let backend = FileKeystore::ephemeral(root).unwrap();
    let signer = backend.create(Actor::Analyst).unwrap();
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
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    (store, engine)
}

fn ingest(
    store: &LocalStore,
    engine: &Engine<'_>,
    id: &irmind_app::CaseId,
    root: &Path,
    name: &str,
) {
    let bytes = format!(r#"{{"eventTime":"2026-11-01T00:00:00.000001900Z","eventName":"{name}"}}"#)
        .into_bytes();
    std::fs::write(root.join(name), &bytes).unwrap();
    let selected = BTreeMap::from([(
        name.into(),
        ParserSelection {
            parser_id: "parser-json".into(),
            parser_version: "json-stream-v3".into(),
            confidence: 90,
            mode: ParserSelectionMode::Automatic,
            timestamp_context: None,
            format_sample_sha256: irmind_app::sha256(&bytes),
        },
    )]);
    LargeCaseUseCases {
        engine,
        store,
        parser: &JsonParser,
    }
    .ingest_local_batch_selected(
        id,
        root,
        &[name.into()],
        false,
        &selected,
        &CancellationToken::new(),
    )
    .unwrap();
}

fn verify_and_export(
    store: &LocalStore,
    engine: &Engine<'_>,
    id: &irmind_app::CaseId,
    root: &Path,
    version: u32,
    records: usize,
) {
    let cancel = CancellationToken::new();
    let rebuilt = LargeCaseUseCases {
        engine,
        store,
        parser: &JsonParser,
    }
    .verify_parquet_rebuild(id, root, &cancel)
    .unwrap();
    assert_eq!(rebuilt, records);
    engine.verify(id).unwrap();
    engine.seal(id).unwrap();
    let path = root.join("case.irmind");
    let key =
        irmind_app::export_case_v4(engine, store, id, &path, Some(root), false, &cancel).unwrap();
    let checked =
        irmind_app::verify_export_details(&LocalExportVerifier, &path, Some(&key)).unwrap();
    assert_eq!(checked.format_version, version);
}

#[test]
fn default_ingestion_writes_v2_and_exports_v5() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path(), false);
    let id = engine
        .create_case("Synthetic rollout", "local only")
        .unwrap()
        .id;
    ingest(&store, &engine, &id, root.path(), "events.json");
    let catalog = irmind_app::artifact_catalog(&store.entries(&id).unwrap()).unwrap();
    assert_eq!(catalog.active.len(), 3);
    assert!(
        catalog
            .active
            .iter()
            .all(|a| matches!(a, ParquetArtifact::V2(_)))
    );
    verify_and_export(&store, &engine, &id, root.path(), 5, 1);
}

#[test]
fn reopening_keeps_legacy_history_and_exports_the_mixed_case_as_v5() {
    let root = tempfile::tempdir().unwrap();
    let (legacy, engine) = setup(root.path(), true);
    let id = engine
        .create_case("Synthetic mixed case", "local only")
        .unwrap()
        .id;
    ingest(&legacy, &engine, &id, root.path(), "old.json");
    let before = legacy.entries(&id).unwrap();
    let precise = open(root.path()).unwrap();
    assert_eq!(
        before.iter().map(|e| e.hash).collect::<Vec<_>>(),
        precise
            .entries(&id)
            .unwrap()
            .iter()
            .map(|e| e.hash)
            .collect::<Vec<_>>()
    );
    ingest(&precise, &engine, &id, root.path(), "new.json");
    let after = precise.entries(&id).unwrap();
    assert_eq!(
        before.iter().map(|e| e.hash).collect::<Vec<_>>(),
        after[..before.len()]
            .iter()
            .map(|e| e.hash)
            .collect::<Vec<_>>()
    );
    let catalog = irmind_app::artifact_catalog(&after).unwrap();
    assert_eq!(
        catalog
            .active
            .iter()
            .filter(|a| matches!(a, ParquetArtifact::V1(_)))
            .count(),
        3
    );
    assert_eq!(
        catalog
            .active
            .iter()
            .filter(|a| matches!(a, ParquetArtifact::V2(_)))
            .count(),
        3
    );
    verify_and_export(&precise, &engine, &id, root.path(), 5, 2);
}

#[cfg(all(feature = "mapping-json-compat", feature = "mapping-journald-compat"))]
mod experimental;
