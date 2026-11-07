#![allow(clippy::unwrap_used)]
use super::super::staging::Input;
use super::*;
use irmind_app::{LargeCaseStore as _, PartitionLimits, StreamingEventParser};
use irmind_domain::{CaseId, ParquetArtifact};
use irmind_mod_parser_json::JsonParser;
use std::fmt::Write as _;
use std::path::Path;

fn case() -> CaseId {
    CaseId::parse("00000000-0000-0000-0000-000000000021").unwrap()
}

fn request<'a>(root: &'a Path, id: &'a CaseId, paths: &'a [String]) -> LocalBatchRequest<'a> {
    LocalBatchRequest {
        case_id: id,
        source_root: root,
        relative_paths: paths,
        copy_original: false,
        parser: &JsonParser,
        committed_artifacts: &[],
        limits: PartitionLimits {
            host: 1,
            ..PartitionLimits::default()
        },
    }
}

fn input_rows(disorder: bool) -> String {
    let mut text = String::new();
    for index in 0..12_000 {
        // Late disorder exercises rollback after multiple Parquet flushes.
        let second = if disorder && index == 11_999 {
            0
        } else {
            index + 1
        };
        let host = if index == 11_999 {
            "host-early"
        } else {
            "host-late"
        };
        writeln!(text, "{{\"eventTime\":\"2026-11-01T{:02}:{:02}:{:02}Z\",\"host\":\"{host}\",\"eventName\":\"Read\",\"message\":\"{}\"}}", second / 3600, second % 3600 / 60, second % 60, "synthetic ".repeat(80)).unwrap();
    }
    text
}

fn staged_reference(store: &ParquetStore, request: &LocalBatchRequest<'_>) -> Vec<PreparedSource> {
    let cancel = CancellationToken::new();
    let mut allocation = Allocator::from_signed(&[], request.limits).unwrap();
    let inputs = store
        .staging_inputs(request.case_id, request.source_root, request.relative_paths)
        .unwrap();
    inputs
        .into_iter()
        .map(|input: Input| {
            let mut staged = store
                .stage_source(request.case_id, input, request.parser, false, &cancel)
                .unwrap();
            store
                .sort_staged_sources(request.case_id, std::slice::from_mut(&mut staged), &cancel)
                .unwrap();
            let bytes = staged.spool.as_file().metadata().unwrap().len();
            store
                .write_partition_source(request, staged, &mut allocation, &cancel, bytes)
                .unwrap()
        })
        .collect()
}

#[test]
fn direct_and_late_disordered_writes_match_the_staged_reference_byte_for_byte() {
    for disorder in [false, true] {
        let sources = tempfile::tempdir().unwrap();
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::write(sources.path().join("events.json"), input_rows(disorder)).unwrap();
        let paths = ["events.json".into()];
        let id = case();
        let req = request(sources.path(), &id, &paths);
        let direct = ParquetStore::open_precise(a.path()).unwrap();
        let reference = ParquetStore::open_precise(b.path()).unwrap();
        let actual = direct
            .prepare_local_batch(req, &CancellationToken::new())
            .unwrap();
        let expected = staged_reference(&reference, &request(sources.path(), &id, &paths));
        assert_eq!(actual[0].manifest, expected[0].manifest);
        assert_eq!(
            actual[0].parse_report.accepted,
            expected[0].parse_report.accepted
        );
        assert_eq!(
            actual[0].parse_report.rejected,
            expected[0].parse_report.rejected
        );
        assert_eq!(
            actual[0].parse_report.samples,
            expected[0].parse_report.samples
        );
        assert_eq!(actual[0].artifacts, expected[0].artifacts);
        for artifact in &actual[0].artifacts {
            assert_eq!(
                std::fs::read(direct.case_dir(&id).unwrap().join(artifact.path())).unwrap(),
                std::fs::read(reference.case_dir(&id).unwrap().join(artifact.path())).unwrap()
            );
            direct
                .verify_artifact(&id, artifact, &CancellationToken::new())
                .unwrap();
        }
        assert_no_temporary_files(&direct.case_dir(&id).unwrap());
        assert!(
            actual[0]
                .artifacts
                .iter()
                .all(|a| matches!(a, ParquetArtifact::V2(_)))
        );
    }
}

#[test]
fn ordered_source_does_not_create_a_normalized_spool() {
    let sources = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let id = case();
    std::fs::write(sources.path().join("events.json"), input_rows(false)).unwrap();
    let store = ParquetStore::open_precise(data.path()).unwrap();
    let parser = ObserveSpool {
        spool: store.spool_dir(&id).unwrap(),
    };
    let paths = ["events.json".into()];
    let mut req = request(sources.path(), &id, &paths);
    req.parser = &parser;
    store
        .prepare_local_batch(req, &CancellationToken::new())
        .unwrap();
    assert_no_temporary_files(&store.case_dir(&id).unwrap());
}

struct ObserveSpool {
    spool: std::path::PathBuf,
}
impl StreamingEventParser for ObserveSpool {
    fn streaming_version(&self) -> &'static str {
        JsonParser.streaming_version()
    }
    fn parser_name(&self) -> &'static str {
        JsonParser.parser_name()
    }
    fn parse_reader(
        &self,
        name: &str,
        reader: &mut dyn std::io::Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(
            irmind_domain::Tainted<irmind_app::GraphRecord>,
        ) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        JsonParser.parse_reader(name, reader, hash, cancel, &mut |row| {
            assert_eq!(std::fs::read_dir(&self.spool).unwrap().count(), 0);
            emit(row)
        })
    }
}

fn assert_no_temporary_files(root: &Path) {
    for entry in std::fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            assert_no_temporary_files(&entry.path());
        } else {
            assert!(!entry.file_name().to_string_lossy().ends_with(".tmp"));
        }
    }
}

#[test]
fn late_errors_and_cancellation_unblock_every_worker_and_remove_provisional_files() {
    let sources = tempfile::tempdir().unwrap();
    let text = input_rows(false);
    let paths = (0..4)
        .map(|i| format!("source-{i}.json"))
        .collect::<Vec<_>>();
    for path in &paths {
        std::fs::write(sources.path().join(path), &text).unwrap();
    }
    for cancel in [false, true] {
        let data = tempfile::tempdir().unwrap();
        let store = ParquetStore::open_precise(data.path()).unwrap();
        let id = case();
        let parser = LateFailure {
            cancel,
            only_last: false,
        };
        let mut req = request(sources.path(), &id, &paths);
        req.parser = &parser;
        let result = store.prepare_local_batch(req, &CancellationToken::new());
        assert!(result.is_err());
        if cancel {
            assert!(matches!(result, Err(AppError::Cancelled)));
        }
        assert_no_temporary_files(&store.case_dir(&id).unwrap());
        assert_eq!(
            std::fs::read_dir(store.spool_dir(&id).unwrap())
                .unwrap()
                .count(),
            0
        );
    }
}

struct LateFailure {
    cancel: bool,
    only_last: bool,
}
impl StreamingEventParser for LateFailure {
    fn streaming_version(&self) -> &'static str {
        JsonParser.streaming_version()
    }
    fn parser_name(&self) -> &'static str {
        JsonParser.parser_name()
    }
    fn parse_reader(
        &self,
        name: &str,
        reader: &mut dyn std::io::Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(
            irmind_domain::Tainted<irmind_app::GraphRecord>,
        ) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if self.only_last && name != "source-3.json" {
            return JsonParser.parse_reader(name, reader, hash, cancel, emit);
        }
        let mut count = 0;
        JsonParser.parse_reader(name, reader, hash, cancel, &mut |row| {
            emit(row)?;
            count += 1;
            if count == 9_000 {
                if self.cancel {
                    cancel.cancel();
                    return Err(AppError::Cancelled);
                }
                return Err(AppError::Policy("synthetic parser failure".into()));
            }
            Ok(())
        })
    }
}

#[test]
fn a_failure_in_the_last_source_discards_every_earlier_provisional_artifact() {
    let inputs = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let store = ParquetStore::open_precise(data.path()).unwrap();
    let text = input_rows(false);
    let paths = (0..4)
        .map(|i| format!("source-{i}.json"))
        .collect::<Vec<_>>();
    for path in &paths {
        std::fs::write(inputs.path().join(path), &text).unwrap();
    }
    let id = case();
    let parser = LateFailure {
        cancel: false,
        only_last: true,
    };
    let mut req = request(inputs.path(), &id, &paths);
    req.parser = &parser;
    assert!(
        store
            .prepare_local_batch(req, &CancellationToken::new())
            .is_err()
    );
    assert_eq!(regular_files(&store.case_dir(&id).unwrap()), 0);
}

fn regular_files(root: &Path) -> usize {
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                regular_files(&entry.path())
            } else {
                1
            }
        })
        .sum()
}

mod restart;

mod serial;
