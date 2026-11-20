use super::*;
use irmind_app::{
    ParseReport, ParserIdentity, SourceDecoder, SourceMapper, SourceParser,
    source_mapping::{
        MappingCatalog, MappingDiagnostic, MappingError, MappingManifest, MappingOutput,
        MappingProvenance, SourceInput, SourceSelector,
    },
};
use irmind_domain::{
    COMMON_EVENT_V1, DecodeAnnotationsV1, EventOrigin, MappingIdentityV1, Provenance,
    SourceFormatV1, SourceRecordV1, SourceValue, Tainted,
};
use std::{collections::BTreeMap, sync::Arc};

fn capture() -> Vec<u8> {
    hex::decode(
        include_str!("../../../../../docs/development/source-query-format-vectors/capture.hex")
            .trim(),
    )
    .unwrap()
}

fn case() -> CaseId {
    CaseId::parse("11111111-1111-4111-8111-111111111111").unwrap()
}

#[test]
fn query_capture_open_checks_link_count_on_the_open_handle() {
    let root = tempfile::tempdir().unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let case = case();
    let bytes = capture();
    let hash = EvidenceHash::from_bytes(irmind_app::sha256(&bytes));
    let directory = store.case_dir(&case).unwrap().join("queries");
    fs::create_dir(&directory).unwrap();
    let capture = directory.join(format!("{}.sqc", hash.as_str()));
    fs::write(&capture, &bytes).unwrap();
    let cancel = CancellationToken::new();
    let size = bytes.len() as u64;
    let mut opened = store
        .open_query_capture(&case, &hash, size, &cancel)
        .unwrap();
    let alias = directory.join("alias");
    fs::hard_link(&capture, &alias).unwrap();
    assert!(!irmind_fs::regular_file_has_single_link(&opened).unwrap());
    assert!(
        store
            .open_query_capture(&case, &hash, size, &cancel)
            .is_err()
    );
    assert_eq!(
        store
            .clean_orphan_query_captures(&case, &BTreeSet::new())
            .unwrap(),
        0
    );
    drop(opened);
    fs::remove_file(alias).unwrap();
    opened = store
        .open_query_capture(&case, &hash, size, &cancel)
        .unwrap();
    let mut recovered = Vec::new();
    opened.read_to_end(&mut recovered).unwrap();
    assert_eq!(bytes, recovered);
    assert!(
        store
            .open_query_capture(&case, &hash, size + 1, &cancel)
            .is_err()
    );
    cancel.cancel();
    assert!(matches!(
        store.open_query_capture(&case, &hash, size, &cancel),
        Err(AppError::Cancelled)
    ));
}

#[test]
fn cleanup_recognizes_only_exact_capture_names_and_preserves_the_inventory() {
    let root = tempfile::tempdir().unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let case = case();
    let directory = store.case_dir(&case).unwrap().join("queries");
    fs::create_dir(&directory).unwrap();
    let retained_hash = EvidenceHash::from_bytes([0xab; 32]);
    let kept = directory.join(format!("{}.sqc", retained_hash.as_str()));
    let orphan = directory.join(format!("{}.sqc", "cd".repeat(32)));
    let uppercase = directory.join(format!("{}.sqc", "EF".repeat(32)));
    let short = directory.join(format!("{}.sqc", "a".repeat(63)));
    let other = directory.join("notes.txt");
    let folder = directory.join(format!("{}.sqc", "24".repeat(32)));
    for path in [&kept, &orphan, &uppercase, &short, &other] {
        fs::write(path, b"synthetic capture").unwrap();
    }
    fs::create_dir(&folder).unwrap();
    #[cfg(unix)]
    let symbolic = {
        let path = directory.join(format!("{}.sqc", "56".repeat(32)));
        std::os::unix::fs::symlink(&kept, &path).unwrap();
        path
    };
    assert_eq!(
        store
            .clean_orphan_query_captures(&case, &BTreeSet::from([retained_hash]))
            .unwrap(),
        1
    );
    assert!(!orphan.exists());
    for path in [&kept, &uppercase, &short, &other, &folder] {
        assert!(path.exists());
    }
    #[cfg(unix)]
    assert!(symbolic.is_symlink());
}

#[test]
fn staging_checks_the_result_against_the_capture_and_removes_invalid_copies() {
    let root = tempfile::tempdir().unwrap();
    let store = ParquetStore::open(root.path()).unwrap();
    let case = case();
    let cancel = CancellationToken::new();
    let result = SourceQueryResultV1::decode(include_bytes!(
        "../../../../../docs/development/source-query-format-vectors/result.json"
    ))
    .unwrap();
    let mut bytes = capture();
    let mut source = store
        .create_object_spool(&case, bytes.len() as u64)
        .unwrap();
    source.write_all(&bytes).unwrap();
    let spool = source.path().parent().unwrap();
    let valid = store
        .stage_query_capture(&case, File::open(source.path()).unwrap(), &result, &cancel)
        .unwrap();
    assert_eq!(fs::read(valid.path()).unwrap(), bytes);
    drop(valid);
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(source.path(), &bytes).unwrap();
    assert!(
        store
            .stage_query_capture(&case, File::open(source.path()).unwrap(), &result, &cancel)
            .is_err()
    );
    assert_eq!(fs::read_dir(spool).unwrap().count(), 1);
}

struct TestDecoder;
impl SourceDecoder for TestDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "query-athena-cloudtrail",
            version: "1",
        }
    }

    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        io::copy(input.reader, &mut io::sink()).map_err(storage)?;
        let id = self.identity();
        for ordinal in 0..2 {
            let origin = EventOrigin::try_new(
                EvidenceHash::from_bytes(input.metadata.evidence_hash),
                ordinal,
                None,
                id.name,
                id.version,
            )
            .unwrap();
            let source = SourceRecordV1::try_from_source(
                origin,
                input.metadata.source.clone(),
                None,
                SourceFormatV1::try_new("synthetic-query", "1", BTreeMap::new()).unwrap(),
                SourceValue::object(vec![(
                    "event".into(),
                    SourceValue::Text("synthetic".into()),
                )])
                .unwrap(),
                DecodeAnnotationsV1::default(),
            )
            .unwrap();
            emit(Tainted::from_external(
                source,
                Provenance::new(
                    input.metadata.evidence_hash,
                    Some(ordinal),
                    input.metadata.source.kind(),
                ),
            ))?;
        }
        Ok(ParseReport {
            accepted: 2,
            rejected: 0,
            samples: vec![],
        })
    }
}

struct TestMapping(MappingManifest);
impl SourceMapper for TestMapping {
    fn manifest(&self) -> &MappingManifest {
        &self.0
    }

    fn map(&self, source: &SourceRecordV1) -> Result<MappingOutput, MappingError> {
        MappingOutput::unclassified(source, MappingDiagnostic::Unclassified)
    }
}

#[test]
fn prepared_capture_publishes_atomically_with_the_mapped_group() {
    let root = tempfile::tempdir().unwrap();
    let case = case();
    let cancel = CancellationToken::new();
    let decoder = TestDecoder.identity();
    let (catalog, result) = synthetic_catalog_and_result(decoder);
    let selected = catalog
        .decoder_selection(decoder.name, decoder.version)
        .unwrap();
    let logical = result.capture_path();
    let parser = SourceParser::new(&selected, &logical);
    let store = ParquetStore::open_mapped(root.path(), catalog).unwrap();
    let mut spool = store
        .create_object_spool(&case, result.capture_identity().1)
        .unwrap();
    spool.write_all(&capture()).unwrap();
    let paths = [spool.path().file_name().unwrap().to_str().unwrap().into()];
    let request = MappedIngestRequest {
        case_id: &case,
        source_root: spool.path().parent().unwrap(),
        relative_paths: &paths,
        copy_original: true,
        parser: &parser,
        committed_artifacts: irmind_app::mapped_ingest::CommittedArtifacts::Slice(&[]),
        limits: irmind_app::PartitionLimits::default(),
    };
    let target = store.owned_case_path(&case).join(&logical);
    let mut prepared = store
        .prepare_source_query_capture(&request, &result, &cancel)
        .unwrap();
    let acquired = &prepared.metadata().sources[0];
    assert_eq!(acquired.manifest.source, logical);
    assert!(acquired.manifest.copied);
    let manifest = irmind_domain::SourceManifestV2 {
        source: acquired.manifest.clone(),
        parser_id: decoder.name.into(),
        parser_version: decoder.version.into(),
        confidence: 0,
        selection: irmind_domain::ParserSelectionMode::Analyst,
        timestamp_context: Some("normalized-utc".into()),
        cluster_context: None,
        rejected_records: 0,
        rejected_sample: vec![],
    };
    let bound = prepared.metadata().bind(&[manifest]).unwrap();
    assert_eq!(
        bound.inputs[0].reference().kind(),
        irmind_domain::SourceKind::ToolResult
    );
    assert_eq!(
        bound.inputs[0].reference().acquisition().unwrap().as_str(),
        result.content_id().unwrap()
    );
    let artifact = store
        .owned_case_path(&case)
        .join(&bound.artifacts[0].core().path);
    assert!(!target.exists());
    prepared.publish(&cancel).unwrap();
    assert!(target.exists() && artifact.exists());
    drop(prepared);
    assert!(!target.exists() && !artifact.exists());

    let mut prepared = store
        .prepare_source_query_capture(&request, &result, &cancel)
        .unwrap();
    prepared.publish(&cancel).unwrap();
    prepared.retain_committed();
    drop(prepared);
    assert!(target.exists() && artifact.exists());
    result
        .verify_capture(&verify_query_capture(File::open(target).unwrap(), &cancel).unwrap())
        .unwrap();
}

fn synthetic_catalog_and_result(
    decoder: ParserIdentity<'_>,
) -> (Arc<MappingCatalog>, SourceQueryResultV1) {
    let mapping_bytes = b"synthetic mapping";
    let digest = EvidenceHash::from_bytes(irmind_app::sha256(mapping_bytes));
    let mapping = MappingIdentityV1::try_new(
        "synthetic-cloudtrail-extraction",
        "1",
        COMMON_EVENT_V1,
        digest.clone(),
    )
    .unwrap();
    let result_wire =
        include_str!("../../../../../docs/development/source-query-format-vectors/result.json")
            .replace(
                "a799cf54941b7079db5e92f8c94431a4607e70890796d12fbfd4092402b33383",
                digest.as_str(),
            );
    let result = SourceQueryResultV1::decode(result_wire.as_bytes()).unwrap();
    let selector = SourceSelector::try_new(
        decoder.name,
        BTreeSet::from(["1".into()]),
        None,
        BTreeMap::new(),
        vec![],
    )
    .unwrap();
    let mapper = TestMapping(
        MappingManifest::try_new(
            mapping,
            vec![selector],
            MappingProvenance::NativeBuild {
                manifest: mapping_bytes.to_vec(),
            },
            true,
        )
        .unwrap(),
    );
    let catalog = Arc::new(
        MappingCatalog::freeze(vec![Arc::new(TestDecoder)], vec![Arc::new(mapper)]).unwrap(),
    );
    (catalog, result)
}
