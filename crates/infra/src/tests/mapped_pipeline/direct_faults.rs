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
