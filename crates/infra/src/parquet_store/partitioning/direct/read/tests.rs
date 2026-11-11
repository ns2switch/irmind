#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{PartitionLimits, StreamingEventParser, mapped_ingest::CommittedArtifacts};

#[test]
fn a_changed_normalized_spool_cannot_publish_mapped_artifacts() {
    let inputs = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        inputs.path().join("events.json"),
        br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"Read"}"#,
    )
    .unwrap();
    let store = crate::parquet_store::fixtures::store(data.path());
    let case = irmind_domain::CaseId::parse("00000000-0000-0000-0000-000000000019").unwrap();
    let paths = ["events.json".into()];
    let parser = crate::parquet_store::fixtures::parser();
    let cancel = CancellationToken::new();
    let input = store
        .staging_inputs(&case, inputs.path(), &paths)
        .unwrap()
        .remove(0);
    let source = store
        .stage_source(&case, input, &parser, false, &cancel)
        .unwrap();
    let request = MappedIngestRequest {
        case_id: &case,
        source_root: inputs.path(),
        relative_paths: &paths,
        copy_original: false,
        parser: &parser,
        committed_artifacts: CommittedArtifacts::Slice(&[]),
        limits: PartitionLimits::default(),
    };
    let mut writing = DirectWriting::new(
        source.manifest.sha256.clone(),
        parser.identity(),
        BTreeMap::new(),
        None,
    );
    let mut allocation = super::super::super::Allocator::from_signed(&[], request.limits).unwrap();
    replay(
        &store,
        &request,
        &source,
        &mut writing,
        &mut allocation,
        &cancel,
    )
    .unwrap();
    drop(writing);
    source.spool.as_file().set_len(0).unwrap();
    let mut writing = DirectWriting::new(
        source.manifest.sha256.clone(),
        parser.identity(),
        BTreeMap::new(),
        None,
    );
    assert!(
        replay(
            &store,
            &request,
            &source,
            &mut writing,
            &mut allocation,
            &cancel
        )
        .is_err()
    );
    drop(writing);
    drop(source);
    assert_eq!(
        std::fs::read_dir(store.spool_dir(&case).unwrap())
            .unwrap()
            .count(),
        0
    );
}
