use super::*;

struct BatchParser {
    cancel_after: Option<usize>,
}

impl irmind_app::EventParser for BatchParser {
    fn version(&self) -> &'static str {
        "synthetic-batch-test"
    }

    fn parse_each(
        &self,
        _source: &str,
        _bytes: &[u8],
        cancel: &irmind_app::CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        for index in 0..2_050 {
            if self.cancel_after == Some(index) {
                cancel.cancel();
            }
            emit(Tainted::from_external(
                GraphRecord {
                    index,
                    at: "2026-10-27T12:00:00Z".into(),
                    event: "Synthetic".into(),
                    text: format!("synthetic event {index}"),
                    entities: vec![("host".into(), "demo-host".into())],
                    relations: Vec::new(),
                },
                irmind_domain::Provenance::new(
                    [1; 32],
                    Some(index as u64),
                    irmind_domain::SourceKind::File,
                ),
            ))?;
        }
        Ok(2_050)
    }
}

#[test]
fn appender_batches_commit_complete_nodes_and_cancelled_batches_rollback() {
    let root = tempfile::tempdir().unwrap();
    let graph = GraphStore::new(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let cancelled = irmind_app::CancellationToken::new();
    let hash = "a".repeat(64);
    assert!(matches!(
        graph.index_from_parser(
            &id,
            &hash,
            "synthetic.json",
            &[],
            &BatchParser {
                cancel_after: Some(2_048),
            },
            &cancelled,
        ),
        Err(AppError::Cancelled)
    ));
    let db = graph.connect(&id).unwrap();
    for table in ["indexed", "events", "record_terms", "observations", "nodes"] {
        let count: i64 = db
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} must roll back");
    }
    drop(db);
    assert_eq!(
        graph
            .index_from_parser(
                &id,
                &hash,
                "synthetic.json",
                &[],
                &BatchParser { cancel_after: None },
                &irmind_app::CancellationToken::new(),
            )
            .unwrap(),
        2_050
    );
    let db = graph.connect(&id).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT count FROM nodes WHERE kind='host' AND value='demo-host'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2_050);
}

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

#[test]
fn graph_verification_rejects_duplicate_search_terms() {
    let root = tempfile::tempdir().unwrap();
    let graph = GraphStore::new(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let hash = "a".repeat(64);
    let bytes = br#"{"eventName":"Synthetic","message":"unique-term"}"#;
    let parser = irmind_mod_parser_json::JsonParser;
    let cancel = irmind_app::CancellationToken::new();
    graph
        .index_from_parser(&id, &hash, "synthetic.json", bytes, &parser, &cancel)
        .unwrap();
    graph
        .connect(&id)
        .unwrap()
        .execute(
            "INSERT INTO record_terms SELECT term,hash,record_index FROM record_terms LIMIT 1",
            [],
        )
        .unwrap();
    assert!(
        graph
            .verify(&id, &[(hash, 1)], &cancel, |_| {
                irmind_app::EventParser::parse(&parser, "verify", bytes)
            })
            .is_err()
    );
}

#[test]
fn graph_verification_rejects_duplicate_record_rows() {
    let root = tempfile::tempdir().unwrap();
    let graph = GraphStore::new(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let hash = "b".repeat(64);
    let bytes = br#"{"eventTime":"2026-10-27T12:00:00Z","eventName":"Synthetic"}"#;
    let parser = irmind_mod_parser_json::JsonParser;
    let cancel = irmind_app::CancellationToken::new();
    graph
        .index_from_parser(&id, &hash, "synthetic.json", bytes, &parser, &cancel)
        .unwrap();
    graph
        .connect(&id)
        .unwrap()
        .execute("INSERT INTO events SELECT * FROM events LIMIT 1", [])
        .unwrap();
    assert!(
        graph
            .verify(&id, &[(hash, 1)], &cancel, |_| {
                irmind_app::EventParser::parse(&parser, "verify", bytes)
            })
            .is_err()
    );
}

#[test]
fn active_reader_keeps_its_database_handle_during_cache_eviction() {
    let root = tempfile::tempdir().unwrap();
    let graph = GraphStore::new(root.path()).unwrap();
    let active_id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let active = graph.connect(&active_id).unwrap();
    for index in 2..=10 {
        let id = CaseId::parse(&format!("{index:08}-1111-1111-1111-111111111111")).unwrap();
        drop(graph.connect(&id).unwrap());
    }
    assert!(graph.writers.lock().unwrap().contains_key(&active_id));
    let count: i64 = active
        .query_row("SELECT COUNT(*) FROM indexed", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn bulk_term_batches_verify_before_secondary_indexes_are_built() {
    let root = tempfile::tempdir().unwrap();
    let graph = GraphStore::new(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let hash = "c".repeat(64);
    let words = (0..1_000)
        .map(|index| format!("term{index:04}"))
        .collect::<Vec<_>>()
        .join(" ");
    let records = (0..20)
        .map(|_| format!("{{\"eventName\":\"Synthetic\",\"message\":\"{words}\"}}"))
        .collect::<Vec<_>>()
        .join(",");
    let bytes = format!("{{\"Records\":[{records}]}}");
    let parser = irmind_mod_parser_json::JsonParser;
    let cancel = irmind_app::CancellationToken::new();
    assert_eq!(
        graph
            .index_from_parser(
                &id,
                &hash,
                "synthetic.json",
                bytes.as_bytes(),
                &parser,
                &cancel
            )
            .unwrap(),
        20
    );
    assert!(
        graph
            .text_search(&id, "term0001", 5)
            .unwrap()
            .contains("source=")
    );
    assert!(graph.summary(&id).unwrap().contains("20 indexed records"));
    assert!(graph.has_record(&id, &hash, 0).unwrap());
    let db = graph.connect_inner(&id, false).unwrap();
    let secondary_indexes: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM duckdb_indexes() WHERE index_name IN ('events_time','observations_entity')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(secondary_indexes, 0);
    let terms: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM record_terms WHERE term LIKE 'term%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(terms, 20_000);
    drop(db);
    assert_eq!(
        graph
            .verify(&id, &[(hash, 20)], &cancel, |_| {
                irmind_app::EventParser::parse(&parser, "verify", bytes.as_bytes())
            })
            .unwrap(),
        20
    );
    let db = graph.connect(&id).unwrap();
    let secondary_indexes: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM duckdb_indexes() WHERE index_name IN ('events_time','observations_entity')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(secondary_indexes, 2);
}

#[test]
fn ingestion_keeps_indexes_while_another_reader_is_active() {
    let root = tempfile::tempdir().unwrap();
    let graph = GraphStore::new(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let parser = irmind_mod_parser_json::JsonParser;
    let cancel = irmind_app::CancellationToken::new();
    let bytes = br#"{"eventTime":"2026-10-27T12:00:00Z","eventName":"Synthetic"}"#;
    let first_hash = "d".repeat(64);
    let second_hash = "e".repeat(64);
    graph
        .index_from_parser(&id, &first_hash, "first.json", bytes, &parser, &cancel)
        .unwrap();
    let active = graph.connect(&id).unwrap();
    graph
        .index_from_parser(&id, &second_hash, "second.json", bytes, &parser, &cancel)
        .unwrap();
    drop(active);
    assert_eq!(
        graph
            .verify(&id, &[(first_hash, 1), (second_hash, 1)], &cancel, |_| {
                irmind_app::EventParser::parse(&parser, "verify", bytes)
            })
            .unwrap(),
        2
    );
}

#[test]
fn failed_ingestion_restores_existing_secondary_indexes() {
    let root = tempfile::tempdir().unwrap();
    let graph = GraphStore::new(root.path()).unwrap();
    let id = CaseId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let parser = irmind_mod_parser_json::JsonParser;
    let cancel = irmind_app::CancellationToken::new();
    let first = br#"{"eventTime":"2026-10-27T12:00:00Z","eventName":"Safe"}"#;
    graph
        .index_from_parser(&id, &"a".repeat(64), "first.json", first, &parser, &cancel)
        .unwrap();
    drop(graph.connect(&id).unwrap());
    let malformed = br#"{"Records":[{"eventName":"first"},{"eventName":}]}"#;
    assert!(
        graph
            .index_from_parser(
                &id,
                &"b".repeat(64),
                "second.json",
                malformed,
                &parser,
                &cancel,
            )
            .is_err()
    );
    let db = graph.connect_inner(&id, false).unwrap();
    let indexes: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM duckdb_indexes() WHERE index_name IN ('events_time','observations_entity')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(indexes, 2);
    let source_count: i64 = db
        .query_row("SELECT COUNT(*) FROM indexed", [], |row| row.get(0))
        .unwrap();
    assert_eq!(source_count, 1);
}
