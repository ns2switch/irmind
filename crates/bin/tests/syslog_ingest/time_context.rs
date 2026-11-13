use super::*;
use irmind_app::{
    ParserTimeBasis, ParserTimeContext,
    modules::{ParserCatalog, ParserSelectionRequest},
};

fn catalog() -> ParserCatalog {
    current_sources::catalog()
}
fn context(year: u16) -> ParserTimeContext {
    ParserTimeContext::new(year, 60, true, ParserTimeBasis::Analyst).unwrap()
}
const LEGACY: &[u8] = b"<34>Dec 31 23:59:59 synthetic-host sshd[1]: last\n<34>Jan  1 00:00:01 synthetic-host sshd[1]: next\n";

#[test]
#[allow(clippy::too_many_lines)]
fn signed_per_file_contexts_rebuild_independently_and_old_manifests_keep_their_bytes() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("case")));
    let _parser = Arc::new(SyslogParser);
    let engine = engine(&store);
    let case = engine.create_case("Per-ingestion time", "local").unwrap();
    let catalog = catalog();
    for (file, year) in [("a.log", 2025), ("b.log", 2027)] {
        let bytes = [
            LEGACY,
            format!("<34>Jan  2 00:00:00 synthetic-host sshd[1]: {file}\n").as_bytes(),
        ]
        .concat();
        fs::write(sources.join(file), &bytes).unwrap();
        let resolved = catalog
            .select_source(ParserSelectionRequest {
                source: file,
                sample: &bytes,
                parser_override: None,
                forced: false,
                time_context: Some(context(year)),
                cluster_context: None,
            })
            .unwrap();
        let selected = BTreeMap::from([(file.into(), resolved.selection.clone())]);
        let cases = LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: resolved.parser.as_ref(),
        };
        cases
            .ingest_local_batch_selected(
                &case.id,
                &sources,
                &[file.into()],
                false,
                &selected,
                &CancellationToken::new(),
            )
            .unwrap();
    }
    let before = store.entries(&case.id).unwrap();
    let manifests = before
        .iter()
        .filter(|e| e.kind == AuditEventKind::SourceManifestV2)
        .map(|e| irmind_domain::SourceManifestV2::decode(&e.payload).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(manifests.len(), 2);
    for (source, year) in manifests.iter().zip([2025, 2027]) {
        let context = irmind_app::source_mapping::decode_source_time_context(
            source.timestamp_context.as_deref(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(context.year(), year);
        assert_eq!(context.offset_minutes(), 60);
        assert!(context.rollover());
        assert_eq!(context.basis(), ParserTimeBasis::Analyst);
        assert_eq!(source.confidence, 90);
    }
    let router = catalog.rebuild_router(&before).unwrap();
    assert_eq!(
        LargeCaseUseCases {
            engine: &engine,
            store: store.as_ref(),
            parser: &router
        }
        .verify_parquet_rebuild(&case.id, &sources, &CancellationToken::new())
        .unwrap(),
        2
    );
    engine.verify(&case.id).unwrap();
    assert_eq!(
        before
            .iter()
            .map(|entry| (entry.hash, entry.payload.clone()))
            .collect::<Vec<_>>(),
        store
            .entries(&case.id)
            .unwrap()
            .iter()
            .map(|entry| (entry.hash, entry.payload.clone()))
            .collect::<Vec<_>>()
    );
    let times = store.timeline(&case.id, 10).unwrap();
    assert!(times.iter().any(|row| row.at == "2025-12-31T23:00:01Z"));
    assert!(times.iter().any(|row| row.at == "2027-12-31T23:00:01Z"));
}

#[test]
fn missing_context_is_audited_and_late_detection_rolls_back_the_source() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("case")));
    let parser = Arc::new(SyslogParser);
    let source_parser = irmind_mod_parser_syslog::source_log_parser();
    let engine = engine(&store);
    let case = engine.create_case("No inferred defaults", "local").unwrap();
    let catalog = catalog();
    let error = catalog
        .select_source(ParserSelectionRequest {
            source: "a.log",
            sample: LEGACY,
            parser_override: None,
            forced: false,
            time_context: None,
            cluster_context: None,
        })
        .err()
        .unwrap();
    let error = engine.annotate_parser_time_error(
        &case.id,
        error,
        &catalog,
        &CancellationToken::new(),
        false,
    );
    assert!(matches!(error, AppError::ParserTimeContextRequired { .. }));
    assert_eq!(
        store.entries(&case.id).unwrap().last().unwrap().kind,
        AuditEventKind::ParserSelectionRequired
    );
    let mut bytes = b"<34>1 2026-11-01T00:00:00Z synthetic-host app 1 ID - modern\n".repeat(1400);
    bytes.extend_from_slice(LEGACY);
    fs::write(sources.join("mixed.log"), &bytes).unwrap();
    let selected = BTreeMap::from([("mixed.log".into(), selection(&parser, &bytes[..65_536]))]);
    let before = store.entries(&case.id).unwrap().len();
    let error = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: source_parser.as_ref(),
    }
    .ingest_local_batch_selected(
        &case.id,
        &sources,
        &["mixed.log".into()],
        false,
        &selected,
        &CancellationToken::new(),
    )
    .unwrap_err();
    assert!(matches!(error, AppError::ParserTimeContextRequired { .. }));
    assert_eq!(store.entries(&case.id).unwrap().len(), before);
    assert!(store.timeline(&case.id, 10).unwrap().is_empty());
    engine.verify(&case.id).unwrap();
}

#[test]
fn hints_come_only_from_verified_records_of_the_same_host_and_are_not_defaults() {
    let root = tempfile::tempdir().unwrap();
    let sources = root.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("case")));
    let parser = Arc::new(SyslogParser);
    let source_parser = irmind_mod_parser_syslog::source_log_parser();
    let engine = engine(&store);
    let case = engine.create_case("Temporal hints", "local").unwrap();
    let catalog = catalog();
    let bytes = b"<34>1 2028-01-01T00:00:01+02:00 synthetic-host app 1 ID - modern\n";
    fs::write(sources.join("modern.log"), bytes).unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: source_parser.as_ref(),
    }
    .ingest_local_batch_selected(
        &case.id,
        &sources,
        &["modern.log".into()],
        false,
        &BTreeMap::from([("modern.log".into(), selection(&parser, bytes))]),
        &CancellationToken::new(),
    )
    .unwrap();
    let required = parser
        .time_context_requirement("a.log", LEGACY)
        .unwrap()
        .unwrap();
    let hints = engine
        .parser_time_suggestions(&case.id, &required, &catalog, &CancellationToken::new())
        .unwrap();
    assert_eq!(hints.len(), 1);
    assert_eq!(hints[0].context.year(), 2028);
    assert_eq!(hints[0].context.offset_minutes(), 120);
    assert_eq!(
        hints[0].context.basis(),
        ParserTimeBasis::ConfirmedSuggestion
    );
    let other = parser
        .time_context_requirement(
            "other.log",
            b"<34>Nov  1 00:00:00 different-host sshd[1]: other\n",
        )
        .unwrap()
        .unwrap();
    assert!(
        engine
            .parser_time_suggestions(&case.id, &other, &catalog, &CancellationToken::new())
            .unwrap()
            .is_empty()
    );
    assert!(
        catalog
            .select_source(ParserSelectionRequest {
                cluster_context: None,
                source: "a.log",
                sample: LEGACY,
                parser_override: None,
                forced: false,
                time_context: None
            })
            .is_err()
    );
}

#[test]
fn previously_signed_global_settings_can_be_removed_explicitly_without_rewriting_sources() {
    use irmind_app::modules::{ConfigField, ModuleManifest, ModulePort};
    use irmind_app::{ConfigChange, ConfigurationStore};
    let historical = ModuleManifest {
        id: "parser-syslog",
        version: "0.1.0",
        ports: &[ModulePort::EventParser],
        tools: &[],
        config: &[
            ConfigField {
                name: "LEGACY_YEAR",
                required: false,
                secret: false,
            },
            ConfigField {
                name: "LEGACY_UTC_OFFSET_MINUTES",
                required: false,
                secret: false,
            },
        ],
    };
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(current_sources::open(&root.path().join("case")));
    let _parser = Arc::new(SyslogParser);
    let engine = engine(&store);
    let config = irmind_infra::TomlConfigurationStore::new(root.path());
    for (field, value) in [("LEGACY_YEAR", "2026"), ("LEGACY_UTC_OFFSET_MINUTES", "60")] {
        engine
            .apply_configuration_change(
                &config,
                &[&historical],
                ConfigChange::SetValue {
                    module: "parser-syslog".into(),
                    field: field.into(),
                    value: value.into(),
                },
                true,
            )
            .unwrap();
    }
    let signed = store.global_operations().unwrap();
    assert!(
        engine
            .verify_configuration(&config, &[&irmind_mod_parser_syslog::MANIFEST])
            .is_err()
    );
    engine
        .verify_configuration(&config, &[&historical])
        .unwrap();
    for field in ["LEGACY_YEAR", "LEGACY_UTC_OFFSET_MINUTES"] {
        engine
            .apply_configuration_change(
                &config,
                &[&historical],
                ConfigChange::SetValue {
                    module: "parser-syslog".into(),
                    field: field.into(),
                    value: String::new(),
                },
                true,
            )
            .unwrap();
    }
    engine
        .verify_configuration(&config, &[&irmind_mod_parser_syslog::MANIFEST])
        .unwrap();
    assert!(
        config.load().unwrap().modules["parser-syslog"]
            .values
            .is_empty()
    );
    let after = store.global_operations().unwrap();
    assert_eq!(after.len(), signed.len() + 2);
    for (old, new) in signed.iter().zip(&after) {
        assert_eq!(old.hash, new.hash);
        assert_eq!(old.operation, new.operation);
    }
}
