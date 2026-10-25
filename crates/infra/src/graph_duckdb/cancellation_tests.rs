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
