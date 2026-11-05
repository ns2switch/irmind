use super::*;
use crate::parquet_store::ParquetStore;
use irmind_app::{
    CancellationToken, GraphRecord, LargeCaseStore, LocalBatchRequest, ParseReport,
    StreamingEventParser,
};
use irmind_domain::{CaseId, Tainted};
use irmind_mod_parser_json::JsonParser;
use std::fmt::Write as _;
use std::io::Read;

pub(super) struct Delayed {
    pub(super) reverse: bool,
    pub(super) fail: bool,
}
impl StreamingEventParser for Delayed {
    fn streaming_version(&self) -> &'static str {
        "json-stream-v2"
    }
    fn parser_name(&self) -> &'static str {
        "parser-json"
    }
    fn partition_profile(&self, _: &GraphRecord) -> PartitionProfile {
        PartitionProfile::EndpointHost
    }
    fn parse_reader(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Ok(self
            .parse_reader_report(source, reader, hash, cancel, emit)?
            .accepted)
    }
    fn parse_reader_report(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if source.starts_with('a') != self.reverse {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let result = JsonParser.parse_reader_report(source, reader, hash, cancel, emit)?;
        if self.fail {
            return Err(AppError::Cancelled);
        }
        Ok(result)
    }
}
pub(super) fn id() -> CaseId {
    CaseId::parse("00000000-0000-0000-0000-000000000017").unwrap()
}
fn batch(
    store: &ParquetStore,
    root: &std::path::Path,
    paths: &[String],
    parser: &dyn StreamingEventParser,
    committed: &[ParquetArtifact],
) -> Result<Vec<irmind_app::PreparedSource>, AppError> {
    store.prepare_local_batch(
        LocalBatchRequest {
            case_id: &id(),
            source_root: root,
            relative_paths: paths,
            copy_original: false,
            parser,
            committed_artifacts: committed,
            limits: PartitionLimits {
                host: 1,
                ..PartitionLimits::default()
            },
        },
        &CancellationToken::new(),
    )
}
#[test]
fn worker_order_and_unsigned_retries_do_not_change_allocations() {
    let sources = tempfile::tempdir().unwrap();
    std::fs::write(
        sources.path().join("a.json"),
        br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"First","host":"host-a"}"#,
    )
    .unwrap();
    std::fs::write(
        sources.path().join("b.json"),
        br#"{"eventTime":"2026-11-01T00:00:00Z","eventName":"Second","host":"host-b"}"#,
    )
    .unwrap();
    let paths = ["a.json".into(), "b.json".into()];
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let store_a = ParquetStore::open_precise(a.path()).unwrap();
    let store_b = ParquetStore::open_precise(b.path()).unwrap();
    let first = batch(
        &store_a,
        sources.path(),
        &paths,
        &Delayed {
            reverse: false,
            fail: false,
        },
        &[],
    )
    .unwrap();
    let second = batch(
        &store_b,
        sources.path(),
        &paths,
        &Delayed {
            reverse: true,
            fail: false,
        },
        &[],
    )
    .unwrap();
    for (a, b) in first.iter().zip(&second) {
        assert_eq!(a.manifest, b.manifest);
        assert_eq!(a.artifacts, b.artifacts);
    }
    let v = first[1]
        .artifacts
        .iter()
        .find_map(|a| {
            if let ParquetArtifact::V2(v) = a {
                Some(v)
            } else {
                None
            }
        })
        .unwrap();
    assert_eq!(
        v.partition.scopes[0].value,
        Value::Overflow(Reason::Cardinality)
    );
    assert_retry_is_clean(&store_a, sources.path(), &paths, &first);
}

#[test]
fn revisiting_evicted_buckets_publishes_one_artifact_per_family() {
    let source = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut bytes = String::new();
    for i in 0..40 {
        writeln!(bytes, "{{\"eventTime\":\"2026-11-01T00:00:00Z\",\"eventName\":\"Read\",\"host\":\"host-{}\"}}", i % 20).unwrap();
    }

    std::fs::write(source.path().join("events.json"), bytes).unwrap();
    let mut store = ParquetStore::open_precise(root.path()).unwrap();
    let profile = std::sync::Arc::new(crate::parquet_store::ParquetProfile::default());
    store.attach_profile(profile.clone());
    let prepared = store
        .prepare_local_batch(
            LocalBatchRequest {
                case_id: &id(),
                source_root: source.path(),
                relative_paths: &["events.json".into()],
                copy_original: false,
                parser: &Delayed {
                    reverse: false,
                    fail: false,
                },
                committed_artifacts: &[],
                limits: PartitionLimits::default(),
            },
            &CancellationToken::new(),
        )
        .unwrap();
    assert!(profile.temporary_disk_peak() > 0);
    let [stage, _, replay, source_verify, publish] = profile.partition_snapshot();
    assert!(
        [stage, replay, source_verify, publish]
            .iter()
            .all(|d| !d.is_zero())
    );
    assert_eq!(prepared[0].records, 40);
    assert_eq!(prepared[0].artifacts.len(), 60);
    for a in &prepared[0].artifacts {
        store
            .verify_artifact(&id(), a, &CancellationToken::new())
            .unwrap();
    }
    assert_eq!(
        std::fs::read_dir(store.spool_dir(&id()).unwrap())
            .unwrap()
            .count(),
        0
    );
}

fn assert_retry_is_clean(
    store: &ParquetStore,
    sources: &std::path::Path,
    paths: &[String],
    expected: &[irmind_app::PreparedSource],
) {
    assert!(
        batch(
            store,
            sources,
            paths,
            &Delayed {
                reverse: false,
                fail: true
            },
            &[]
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read_dir(store.spool_dir(&id()).unwrap())
            .unwrap()
            .count(),
        0
    );
    let retry = batch(
        store,
        sources,
        paths,
        &Delayed {
            reverse: true,
            fail: false,
        },
        &[],
    )
    .unwrap();
    assert_eq!(expected[0].artifacts, retry[0].artifacts);
    assert_eq!(expected[1].artifacts, retry[1].artifacts);
}
