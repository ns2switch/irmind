use super::*;
use irmind_app::EvidenceGraph;

#[test]
fn syslog_ingestion_signs_confirmed_calendar_and_rebuilds_gzip_without_fake_offsets() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path(), false);
    let mut registry = registry();
    registry
        .register(
            Box::new(irmind_mod_parser_syslog::SyslogParser),
            &ModuleConfig::new(),
        )
        .unwrap();
    registry
        .register(
            Box::new(irmind_mod_mapping_syslog::SyslogExtractionMapping::new().unwrap()),
            &ModuleConfig::new(),
        )
        .unwrap();
    let config = PersistentConfig::default();
    let catalog =
        super::super::super::experimental_parsers(registry.parser_catalog(), &config, &registry)
            .unwrap();
    let store = super::super::super::experimental(root.path(), &config, &registry)
        .unwrap()
        .unwrap();
    let case = engine
        .create_case("Synthetic syslog calendar", "local only")
        .unwrap();
    for (path, bytes, time_context) in fixtures() {
        std::fs::write(root.path().join(path), &bytes).unwrap();
        let selected = catalog
            .select_source(ParserSelectionRequest {
                source: path,
                sample: &bytes,
                parser_override: Some("parser-syslog"),
                forced: true,
                time_context,
            })
            .unwrap();
        assert_eq!(selected.selection.parser_version, "syslog-source-v1");
        LargeCaseUseCases {
            engine: &engine,
            store: &store,
            parser: selected.parser.as_ref(),
        }
        .ingest_local_batch_selected(
            &case.id,
            root.path(),
            &[path.into()],
            false,
            &BTreeMap::from([(path.into(), selected.selection)]),
            &CancellationToken::new(),
        )
        .unwrap();
    }
    assert_eq!(store.timeline(&case.id, 100).unwrap().len(), 4);
    let parser = catalog.get("parser-syslog").unwrap();
    assert_eq!(
        LargeCaseUseCases {
            engine: &engine,
            store: &store,
            parser: parser.as_ref()
        }
        .verify_parquet_rebuild(&case.id, root.path(), &CancellationToken::new())
        .unwrap(),
        3
    );
    engine.verify(&case.id).unwrap();
}

type Fixture = (&'static str, Vec<u8>, Option<irmind_app::ParserTimeContext>);
fn fixtures() -> [Fixture; 3] {
    let modern = b"<34>1 2026-11-01T00:00:00.123456789Z host app 42 - - synthetic message\n";
    let classic =
        b"<34>Dec 31 23:59:59 host app[42]: before\n<34>Jan  1 00:00:01 host app[42]: after\n";
    let zip = include_bytes!(
        "../../../../../../testkit/fixtures/parser-syslog/source/source-modern.log.gz"
    )
    .to_vec();
    [
        ("modern.log", modern.to_vec(), None),
        (
            "classic.log",
            classic.to_vec(),
            Some(
                irmind_app::ParserTimeContext::new(
                    2026,
                    0,
                    true,
                    irmind_app::ParserTimeBasis::Analyst,
                )
                .unwrap(),
            ),
        ),
        ("modern.log.gz", zip, None),
    ]
}
