use super::*;

#[test]
fn graph_errors_never_include_source_values_or_paths() {
    let error = storage(duckdb::Error::InvalidParameterName(
        "SECRET evidence path".into(),
    ));
    assert!(!error.to_string().contains("SECRET"));
}

#[test]
fn rebuild_cancellation_between_sources_rolls_back_batch() {
    let root = tempfile::tempdir().unwrap();
    let graph = GraphStore::new(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let cancel = irmind_app::CancellationToken::new();
    let sources = vec![("a".to_owned(), 0), ("b".to_owned(), 0)];
    let mut parsed = 0;
    let result = graph.rebuild(&id, &sources, &cancel, |_| {
        parsed += 1;
        cancel.cancel();
        Ok(Vec::new())
    });
    assert!(matches!(result, Err(AppError::Cancelled)));
    assert_eq!(parsed, 1);
    let count: i64 = graph
        .connect(&id)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM indexed", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn failed_streaming_index_rolls_back_terms_and_records() {
    let root = tempfile::tempdir().unwrap();
    let graph = GraphStore::new(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let input = br#"{"Records":[{"eventName":"first"},{"eventName":]}"#;
    let result = graph.index_from_parser(
        &id,
        &"a".repeat(64),
        "cloudtrail.json",
        input,
        &irmind_mod_parser_json::JsonParser,
        &irmind_app::CancellationToken::new(),
    );
    assert!(result.is_err());
    let words = (0..2_050)
        .map(|index| format!("term{index:04}"))
        .collect::<Vec<_>>()
        .join(" ");
    let too_many_terms = format!("{{\"message\":\"{words}\"}}");
    assert!(matches!(
        graph.index_from_parser(
            &id,
            &"b".repeat(64),
            "events.json",
            too_many_terms.as_bytes(),
            &irmind_mod_parser_json::JsonParser,
            &irmind_app::CancellationToken::new(),
        ),
        Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::TooManyGraphSearchTerms
        )))
    ));
    let db = graph.connect(&id).unwrap();
    for table in [
        "indexed",
        "events",
        "record_texts",
        "record_terms",
        "fts_indexed",
    ] {
        let count: i64 = db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must roll back");
    }
}
