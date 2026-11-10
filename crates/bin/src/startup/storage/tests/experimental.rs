use super::*;
use irmind_app::{
    ConfigChange, ConfigurationStore, PersistentConfig,
    modules::{ModuleConfig, ModuleRegistry, ParserSelectionRequest},
};

fn registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry
        .register(Box::new(JsonParser), &ModuleConfig::new())
        .unwrap();
    registry
        .register(
            Box::new(irmind_mod_parser_linux::LinuxParser::default()),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
        .register(
            Box::new(
                irmind_mod_mapping_json_compat::JsonCompatibilityMapping::generic_only().unwrap(),
            ),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
        .register(
            Box::new(
                irmind_mod_mapping_journald_compat::JournaldCompatibilityMapping::new().unwrap(),
            ),
            &ModuleConfig::new(),
        )
        .unwrap();
    #[cfg(feature = "mapping-ecs")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_ecs::EcsParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_ecs::EcsMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "mapping-ocsf")]
    {
        registry
            .register(
                Box::new(irmind_mod_parser_ocsf::OcsfParser),
                &ModuleConfig::new(),
            )
            .unwrap();
        registry
            .register(
                Box::new(irmind_mod_mapping_ocsf::OcsfMapping::new().unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    #[cfg(feature = "mapping-cloudtrail")]
    registry
        .register(
            Box::new(irmind_mod_mapping_cloudtrail::CloudTrailMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
}

#[test]
fn experimental_enable_is_explicit_signed_and_keeps_default_bytes() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path(), false);
    let config = irmind_infra::TomlConfigurationStore::new(root.path());
    assert!(
        engine
            .apply_configuration_change(
                &config,
                &[],
                ConfigChange::SetExperimentalCommonWriter(true),
                false
            )
            .is_err()
    );
    assert!(store.global_operations().unwrap().is_empty());
    assert!(
        engine
            .apply_configuration_change(
                &config,
                &[],
                ConfigChange::SetExperimentalCommonWriter(true),
                true
            )
            .unwrap()
    );
    assert_eq!(
        config.load().unwrap().experimental_common_writer,
        Some(true)
    );
    let ops = store.global_operations().unwrap();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].actor, Actor::Analyst);
    engine.verify_global_operations().unwrap();
}

#[test]
fn experimental_routes_are_new_ingestion_only_and_export_v6() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path(), false);
    let registry = registry();
    let config = PersistentConfig {
        experimental_common_writer: Some(true),
        ..Default::default()
    };
    let catalog =
        super::super::experimental_parsers(registry.parser_catalog(), &config, &registry).unwrap();
    assert_eq!(
        catalog
            .get_version("parser-json", "json-stream-v3")
            .unwrap()
            .identity()
            .version,
        "json-stream-v3"
    );
    let bytes = br#"{"Records":[{"eventTime":"2026-11-01T00:00:00Z","eventName":"synthetic"}]}"#;
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: "events.json",
            sample: bytes,
            parser_override: None,
            forced: false,
            time_context: None,
        })
        .unwrap();
    assert_eq!(selected.selection.parser_version, "json-source-v1");
    assert_journal_selection(&catalog);
    let store = super::super::experimental(root.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine.create_case("Experimental", "local only").unwrap();
    std::fs::write(root.path().join("events.json"), bytes).unwrap();
    LargeCaseUseCases {
        engine: &engine,
        store: &store,
        parser: selected.parser.as_ref(),
    }
    .ingest_local_batch_selected(
        &case.id,
        root.path(),
        &["events.json".into()],
        false,
        &BTreeMap::from([("events.json".into(), selected.selection)]),
        &CancellationToken::new(),
    )
    .unwrap();
    let entries = store.entries(&case.id).unwrap();
    assert!(
        irmind_app::artifact_catalog(&entries)
            .unwrap()
            .active
            .iter()
            .all(|a| matches!(a, ParquetArtifact::V3(_)))
    );
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let path = root.path().join("mapped.irmind");
    let key =
        irmind_app::CaseExporter::export_case(&store, &case.id, &path, &CancellationToken::new())
            .unwrap();
    assert_eq!(
        irmind_app::verify_export_details(&LocalExportVerifier, &path, Some(&key))
            .unwrap()
            .format_version,
        6
    );
}

fn assert_journal_selection(catalog: &irmind_app::modules::ParserCatalog) {
    let journal =
        br#"{"__REALTIME_TIMESTAMP":"1793491200000001","_HOSTNAME":"synthetic","MESSAGE":"test"}"#;
    let journal_selected = catalog
        .select_source(ParserSelectionRequest {
            source: "journal.json",
            sample: journal,
            parser_override: None,
            forced: false,
            time_context: None,
        })
        .unwrap();
    assert_eq!(journal_selected.selection.parser_version, "linux-source-v1");
}

#[cfg(feature = "mapping-linux")]
#[test]
fn linux_auth_context_is_confirmed_signed_and_reproducible_through_the_mapped_writer() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path(), false);
    let mut registry = registry();
    registry
        .register(
            Box::new(irmind_mod_mapping_linux::SshdMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    let config = PersistentConfig {
        experimental_common_writer: Some(true),
        ..Default::default()
    };
    let catalog =
        super::super::experimental_parsers(registry.parser_catalog(), &config, &registry).unwrap();
    let bytes = b"Dec 31 23:59:59 host-a sshd[42]: Failed password for alice from 203.0.113.77 port 22 ssh2\nJan  1 00:00:00 host-a sshd[42]: Accepted password for alice from 203.0.113.77 port 22 ssh2\n";
    let mut request = ParserSelectionRequest {
        source: "auth.log",
        sample: bytes,
        parser_override: None,
        forced: false,
        time_context: None,
    };
    assert!(matches!(
        catalog.select_source(request),
        Err(AppError::ParserTimeContextRequired { .. })
    ));
    request.time_context = Some(
        irmind_app::ParserTimeContext::new(2026, 0, true, irmind_app::ParserTimeBasis::Analyst)
            .unwrap(),
    );
    let selected = catalog.select_source(request).unwrap();
    assert_eq!(selected.selection.parser_version, "linux-source-v1");
    assert!(selected.selection.timestamp_context.is_some());
    let store = super::super::experimental(root.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine
        .create_case("Synthetic Linux authentication", "local only")
        .unwrap();
    std::fs::write(root.path().join("auth.log"), bytes).unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: &store,
        parser: selected.parser.as_ref(),
    };
    use_cases
        .ingest_local_batch_selected(
            &case.id,
            root.path(),
            &["auth.log".into()],
            false,
            &BTreeMap::from([("auth.log".into(), selected.selection)]),
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(
        use_cases
            .verify_parquet(&case.id, &CancellationToken::new())
            .unwrap()
            > 0
    );
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
            .unwrap(),
        1
    );
    engine.verify(&case.id).unwrap();
}

#[cfg(feature = "mapping-ecs")]
mod ecs;

#[cfg(all(
    feature = "mapping-evtx",
    feature = "mapping-linux",
    feature = "mapping-cloudtrail"
))]
mod evtx;

#[cfg(any(feature = "mapping-ecs", feature = "mapping-evtx"))]
mod profile;

#[cfg(feature = "mapping-dfir")]
mod dfir;
#[cfg(feature = "mapping-ocsf")]
mod ocsf;

#[cfg(feature = "mapping-syslog")]
mod syslog;

#[cfg(feature = "mapping-network")]
mod network;
