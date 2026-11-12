use super::*;
use irmind_app::source_mapping::{SourceInput, SourceRecordV1};
use irmind_app::{ParseReport, ParserIdentity, RejectedSource, SourceFailureReason};
use irmind_domain::Tainted;

struct FaultDecoder;
impl irmind_app::SourceDecoder for FaultDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        JsonSourceDecoder.identity()
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        match input.metadata.source.reference() {
            "a-limit.json" => Err(AppError::Fixed(irmind_app::FixedAppError::SourceLimit)),
            "b-hash.json" => Err(AppError::EvidenceMismatch("0".repeat(64))),
            "c-cancel.json" => Err(AppError::Cancelled),
            _ => JsonSourceDecoder.decode_reader(input, emit),
        }
    }
}

#[test]
fn typed_source_limit_hash_and_source_cancellation_are_signed_rejections() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) = fixture_decoder(root.path(), Arc::new(FaultDecoder));
    let case = engine
        .create_case("Source classifications", "local only")
        .unwrap();
    let paths = [
        "a-limit.json",
        "b-hash.json",
        "c-cancel.json",
        "healthy.json",
    ]
    .map(String::from);
    for (i, name) in paths.iter().enumerate() {
        fs::write(
            root.path().join(name),
            format!(r#"{{"eventTime":"2026-11-01T00:00:00Z","eventName":"Event{i}"}}"#),
        )
        .unwrap();
    }
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let token = CancellationToken::new();
    let accepted = large
        .ingest_local_batch(&case.id, root.path(), &paths, false, &token)
        .unwrap();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].0, "healthy.json");
    assert!(!token.is_cancelled());
    let reasons = store
        .entries(&case.id)
        .unwrap()
        .iter()
        .filter_map(|entry| RejectedSource::from_audit(entry).unwrap())
        .map(|source| source.reason())
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        [
            SourceFailureReason::Limit,
            SourceFailureReason::Hash,
            SourceFailureReason::Cancelled
        ]
    );
    engine.verify(&case.id).unwrap();
}

struct SpoolProbe(PathBuf);
impl irmind_app::SourceDecoder for SpoolProbe {
    fn identity(&self) -> ParserIdentity<'_> {
        JsonSourceDecoder.identity()
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        JsonSourceDecoder.decode_reader(input, &mut |record| {
            assert!(!has_normalized_spool(&self.0));
            emit(record)
        })
    }
}
fn has_normalized_spool(root: &Path) -> bool {
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .any(|entry| {
            if entry.file_type().unwrap().is_dir() {
                has_normalized_spool(&entry.path())
            } else {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("irmind-normalized-")
            }
        })
}
#[test]
fn chronological_mapped_sources_never_create_normalized_record_spools() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine, catalog) =
        fixture_decoder(root.path(), Arc::new(SpoolProbe(root.path().to_path_buf())));
    let case = engine
        .create_case("Direct chronological stream", "local only")
        .unwrap();
    let paths = (0..4)
        .map(|i| {
            let name = format!("source-{i}.json");
            let rows = (0..30)
                .map(|second| {
                    format!(
                        r#"{{"eventTime":"2026-11-01T00:00:{second:02}Z","eventName":"Source{i}"}}"#
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(root.path().join(&name), rows).unwrap();
            name
        })
        .collect::<Vec<_>>();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    assert_eq!(
        large
            .ingest_local_batch(
                &case.id,
                root.path(),
                &paths,
                false,
                &CancellationToken::new()
            )
            .unwrap()
            .len(),
        4
    );
    engine.verify(&case.id).unwrap();
}

struct CancelParent(CancellationToken);
impl irmind_app::SourceDecoder for CancelParent {
    fn identity(&self) -> ParserIdentity<'_> {
        JsonSourceDecoder.identity()
    }
    fn decode_reader(
        &self,
        _: SourceInput<'_>,
        _: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.0.cancel();
        Err(AppError::Fixed(irmind_app::FixedAppError::SourceFormat))
    }
}
#[test]
fn parent_cancellation_during_a_source_failure_stays_an_operation_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let token = CancellationToken::new();
    let (store, engine, catalog) =
        fixture_decoder(root.path(), Arc::new(CancelParent(token.clone())));
    let case = engine
        .create_case("Cancelled source failure", "local only")
        .unwrap();
    fs::write(root.path().join("input.json"), b"{bad").unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let large = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    assert!(matches!(
        large.ingest_local_batch(&case.id, root.path(), &["input.json".into()], false, &token),
        Err(AppError::Cancelled)
    ));
    assert_eq!(store.entries(&case.id).unwrap().len(), 1);
    assert!(
        irmind_app::artifact_catalog(&store.entries(&case.id).unwrap())
            .unwrap()
            .all
            .is_empty()
    );
}

struct ReplaceDisordered(PathBuf);
impl irmind_app::SourceDecoder for ReplaceDisordered {
    fn identity(&self) -> ParserIdentity<'_> {
        JsonSourceDecoder.identity()
    }

    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let replace = input.metadata.source.reference() == "b.ndjson";
        let cancel = input.metadata.cancel;
        let result = JsonSourceDecoder.decode_reader(input, emit);
        if replace && !cancel.is_cancelled() && matches!(result, Err(AppError::Cancelled)) {
            fs::write(
                &self.0,
                br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"SyntheticReplacement"}"#,
            )
            .unwrap();
        }
        result
    }
}

#[test]
fn fallback_rejects_a_disordered_source_changed_after_the_order_probe() {
    let root = tempfile::tempdir().unwrap();
    let paths = ["a.ndjson".into(), "b.ndjson".into()];
    fs::write(
        root.path().join("a.ndjson"),
        br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"SyntheticOrdered"}"#,
    )
    .unwrap();
    let mutable = root.path().join("b.ndjson");
    // Fill every bounded preparation window so the fake decoder observes the
    // probe's callback error and actually replaces the source before retry.
    let late = r#"{"eventTime":"2026-11-01T00:00:01Z","eventName":"SyntheticLate"}"#;
    let early = r#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"SyntheticEarly"}"#;
    fs::write(
        &mutable,
        format!("{late}\n{}", format!("{early}\n").repeat(2048)),
    )
    .unwrap();
    let (store, engine, catalog) =
        fixture_decoder(root.path(), Arc::new(ReplaceDisordered(mutable.clone())));
    let case = engine
        .create_case("Source order retry", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let token = CancellationToken::new();
    let accepted = use_cases
        .ingest_local_batch(&case.id, root.path(), &paths, false, &token)
        .unwrap();
    assert!(
        fs::read_to_string(&mutable)
            .unwrap()
            .contains("SyntheticReplacement")
    );
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].0, "a.ndjson");
    let entries = store.entries(&case.id).unwrap();
    let rejected = entries
        .iter()
        .filter_map(|entry| RejectedSource::from_audit(entry).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].reason(), SourceFailureReason::Hash);
    engine.verify(&case.id).unwrap();
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, root.path(), &token)
            .unwrap(),
        1
    );
}

struct CountSourceReads(Arc<std::sync::Mutex<BTreeMap<String, usize>>>);
impl irmind_app::SourceDecoder for CountSourceReads {
    fn identity(&self) -> ParserIdentity<'_> {
        JsonSourceDecoder.identity()
    }

    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        *self
            .0
            .lock()
            .unwrap()
            .entry(input.metadata.source.reference().into())
            .or_default() += 1;
        JsonSourceDecoder.decode_reader(input, emit)
    }
}

#[test]
fn a_short_disordered_prefix_spills_without_redecoding_the_source() {
    let root = tempfile::tempdir().unwrap();
    let paths = ["a.ndjson".to_string(), "b.ndjson".to_string()];
    for (name, first_second) in paths.iter().zip([2, 3]) {
        fs::write(
            root.path().join(name),
            format!(
                r#"{{"eventTime":"2026-11-01T00:00:0{first_second}Z","eventName":"SyntheticLater"}}
{{"eventTime":"2026-11-01T00:00:01Z","eventName":"SyntheticEarlier"}}"#
            ),
        )
        .unwrap();
    }
    let calls = Arc::new(std::sync::Mutex::new(BTreeMap::new()));
    let (store, engine, catalog) =
        fixture_decoder(root.path(), Arc::new(CountSourceReads(calls.clone())));
    store.set_parallel_worker_limit(std::num::NonZeroU16::new(1));
    let case = engine
        .create_case("Bounded prefix spill", "local only")
        .unwrap();
    let parser = catalog
        .decoder_selection("parser-json", "json-source-v1")
        .unwrap();
    let use_cases = LargeCaseUseCases {
        engine: &engine,
        store: store.as_ref(),
        parser: &parser,
    };
    let token = CancellationToken::new();
    assert_eq!(
        use_cases
            .ingest_local_batch(&case.id, root.path(), &paths, false, &token)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        *calls.lock().unwrap(),
        BTreeMap::from([("a.ndjson".into(), 2), ("b.ndjson".into(), 1)])
    );
    engine.verify(&case.id).unwrap();
    assert_eq!(
        use_cases
            .verify_parquet_rebuild(&case.id, root.path(), &token)
            .unwrap(),
        2
    );
}
