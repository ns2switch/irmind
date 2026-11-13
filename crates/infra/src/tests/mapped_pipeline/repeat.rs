use super::*;

#[test]
fn repeated_source_bytes_leave_the_existing_mapped_chain_and_graph_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture(root.path());
    let case = engine
        .create_case("Synthetic repeated acquisition", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let bytes = br#"{"eventTime":"2026-11-01T00:00:00Z","sourceIPAddress":"203.0.113.77"}"#;
    let cancel = CancellationToken::new();
    fs::write(root.path().join("first.json"), bytes).unwrap();
    ingest(&large, &case.id, root.path(), "first.json", bytes, &cancel).unwrap();
    let before = store.last_entry(&case.id).unwrap().unwrap();
    for name in ["first.json", "same-bytes.json"] {
        if name != "first.json" {
            fs::write(root.path().join(name), bytes).unwrap();
        }
        let result = ingest(&large, &case.id, root.path(), name, bytes, &cancel);
        if name == "first.json" {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(AppError::Fixed(
                    irmind_app::FixedAppError::PolicyMappedSourceAlreadyIndexed
                ))
            ));
        }
        let after = store.last_entry(&case.id).unwrap().unwrap();
        assert_eq!((after.seq, after.hash), (before.seq, before.hash));
        engine.verify(&case.id).unwrap();
        assert!(
            store
                .entity_lookup(&case.id, "ip", "203.0.113.77")
                .unwrap()
                .contains("observations=1")
        );
    }
}
fn ingest(
    large: &LargeCaseUseCases<'_, '_>,
    id: &CaseId,
    root: &Path,
    name: &str,
    bytes: &[u8],
    cancel: &CancellationToken,
) -> Result<Vec<(String, irmind_domain::EvidenceHash)>, AppError> {
    let selection = ParserSelection {
        parser_id: "parser-json".into(),
        parser_version: "json-source-v1".into(),
        confidence: 90,
        mode: ParserSelectionMode::Automatic,
        timestamp_context: None,
        cluster_context: None,
        format_sample_sha256: sha256(bytes),
    };
    large.ingest_local_batch_selected(
        id,
        root,
        &[name.into()],
        true,
        &BTreeMap::from([(name.into(), selection)]),
        cancel,
    )
}
