use super::*;
use irmind_app::{EvidenceGraph, GraphQueryFilter};
use irmind_mod_mapping_evtx::{PowerShellMapping, SecurityMapping, SysmonMapping, SystemMapping};
use irmind_mod_parser_evtx::EvtxParser;
use std::path::PathBuf;
fn helper() -> PathBuf {
    std::env::var_os("IRMIND_EVTX_HELPER_TEST").map_or_else(
        || {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join(if cfg!(windows) {
                    "irmind-evtx.exe"
                } else {
                    "irmind-evtx"
                })
        },
        PathBuf::from,
    )
}
fn evtx_registry(root: &Path) -> Result<ModuleRegistry, String> {
    let parser = EvtxParser::new(&helper(), root);
    if let Some(reason) = parser.unavailable_reason() {
        return Err(reason.into());
    }
    let mut registry = registry();
    registry
        .register(Box::new(parser), &ModuleConfig::new())
        .unwrap();
    for &event_id in SecurityMapping::EVENT_IDS {
        registry
            .register(
                Box::new(SecurityMapping::new(event_id).unwrap()),
                &ModuleConfig::new(),
            )
            .unwrap();
    }
    registry
        .register(
            Box::new(SystemMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
        .register(
            Box::new(PowerShellMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
        .register(
            Box::new(SysmonMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
        .register(
            Box::new(irmind_mod_mapping_linux::SshdMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    Ok(registry)
}
fn ingest_selected(
    engine: &Engine<'_>,
    store: &LocalStore,
    registry: &ModuleRegistry,
    source_root: &Path,
    case: &irmind_app::CaseId,
    name: &str,
) {
    use std::io::Read as _;
    let mut sample = Vec::new();
    std::fs::File::open(source_root.join(name))
        .unwrap()
        .take(65_536)
        .read_to_end(&mut sample)
        .unwrap();
    let config = PersistentConfig::default();
    let catalog =
        crate::startup::storage::experimental_parsers(registry.parser_catalog(), &config, registry)
            .unwrap();
    let selected = catalog
        .select_source(ParserSelectionRequest {
            source: name,
            sample: &sample,
            parser_override: None,
            forced: false,
            time_context: (name == "auth.log").then(|| {
                irmind_app::ParserTimeContext::new(
                    2026,
                    0,
                    true,
                    irmind_app::ParserTimeBasis::Analyst,
                )
                .unwrap()
            }),
        })
        .unwrap();
    LargeCaseUseCases {
        engine,
        store,
        parser: selected.parser.as_ref(),
    }
    .ingest_local_batch_selected(
        case,
        source_root,
        &[name.into()],
        false,
        &BTreeMap::from([(name.into(), selected.selection)]),
        &CancellationToken::new(),
    )
    .unwrap();
}
#[test]
fn authentication_failure_unifies_windows_linux_and_cloudtrail_with_roles_and_custody() {
    let data = tempfile::tempdir().unwrap();
    let sources = tempfile::tempdir().unwrap();
    let registry = match evtx_registry(data.path()) {
        Ok(registry) => registry,
        Err(reason) => {
            assert!(
                std::env::var_os("GITHUB_ACTIONS").is_none(),
                "EVTX integration requires verified isolation: {reason}"
            );
            eprintln!("EVTX native integration unavailable: {reason}");
            return;
        }
    };
    let (_, engine) = setup(data.path(), false);
    let config = PersistentConfig::default();
    let store = crate::startup::storage::experimental(data.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine
        .create_case("Synthetic cross-source authentication", "local only")
        .unwrap();
    write_sources(sources.path());
    for name in ["windows.evtx", "auth.log", "cloudtrail.json"] {
        ingest_selected(&engine, &store, &registry, sources.path(), &case.id, name);
    }
    let filter = failure_filter(None);
    let timeline = store.timeline_filtered(&case.id, &filter, 10).unwrap();
    assert_eq!(timeline.len(), 3);
    for name in ["windows.evtx", "auth.log", "cloudtrail.json"] {
        let hash = irmind_app::hex(&irmind_app::sha256(
            &std::fs::read(sources.path().join(name)).unwrap(),
        ));
        assert!(
            timeline.iter().any(|row| row.evidence_hash == hash),
            "missing {name}"
        );
    }
    assert_roles(&store, &case.id);
    let parser = irmind_mod_parser_json::source_log_parser();
    assert_eq!(
        LargeCaseUseCases {
            engine: &engine,
            store: &store,
            parser: parser.as_ref()
        }
        .verify_parquet_rebuild(&case.id, sources.path(), &CancellationToken::new())
        .unwrap(),
        3
    );
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let path = data.path().join("authentication.irmind");
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
fn write_sources(root: &Path) {
    std::fs::write(
        root.join("windows.evtx"),
        include_bytes!(
            "../../../../../../testkit/fixtures/mapping-evtx/source/authentication.evtx"
        ),
    )
    .unwrap();
    std::fs::write(root.join("auth.log"), b"Nov  1 12:00:01 endpoint-linux sshd[42]: Failed password for alice from 203.0.113.77 port 22 ssh2\n").unwrap();
    std::fs::write(
        root.join("cloudtrail.json"),
        include_bytes!("../../../../../../testkit/fixtures/common/cloudtrail-console-login.jsonl"),
    )
    .unwrap();
}
fn failure_filter(role: Option<&str>) -> GraphQueryFilter {
    let mut args = BTreeMap::from([
        ("event_category".into(), "authentication".into()),
        ("event_outcome".into(), "failure".into()),
    ]);
    if let Some(role) = role {
        args.insert("entity_role".into(), role.into());
    }
    GraphQueryFilter::from_args(&args).unwrap()
}
fn assert_roles(store: &LocalStore, case: &irmind_app::CaseId) {
    let source = store
        .entity_lookup_filtered(case, &failure_filter(Some("source")), "ip", "203.0.113.77")
        .unwrap();
    assert!(source.contains("observations=3"), "{source}");
    let target = store
        .entity_lookup_filtered(case, &failure_filter(Some("target")), "user", "alice")
        .unwrap();
    assert!(target.contains("observations=2"), "{target}");
    let actor = store
        .entity_lookup_filtered(case, &failure_filter(Some("actor")), "user", "alice")
        .unwrap();
    assert!(actor.contains("observations=1"), "{actor}");
    let operator = store
        .entity_lookup_filtered(case, &failure_filter(Some("actor")), "user", "operator")
        .unwrap();
    assert!(operator.contains("observations=1"), "{operator}");
}

#[test]
fn unavailable_evtx_does_not_block_other_experimental_decoders() {
    let data = tempfile::tempdir().unwrap();
    let mut registry = registry();
    registry
        .register(
            Box::new(EvtxParser::new(
                &data.path().join("missing-helper"),
                data.path(),
            )),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
        .mark_parser_unavailable("parser-evtx", "verified isolation unavailable".into())
        .unwrap();
    let config = PersistentConfig::default();
    let catalog = crate::startup::storage::experimental_parsers(
        registry.parser_catalog(),
        &config,
        &registry,
    )
    .unwrap();
    assert!(catalog.get("parser-evtx").is_err());
    let bytes =
        include_bytes!("../../../../../../testkit/fixtures/common/cloudtrail-console-login.jsonl");
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
}
