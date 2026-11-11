#![allow(clippy::unwrap_used)]
use super::*;
use irmind_app::{
    LargeCaseStore, MappedIngestRequest, SourceDecoder,
    source_mapping::{SourceDecoderSelection, SourceInput, SourceRecordV1},
};
use irmind_mod_parser_json::JsonSourceDecoder;
use std::{path::Path, sync::Arc};
fn case() -> irmind_domain::CaseId {
    irmind_domain::CaseId::parse("00000000-0000-0000-0000-000000000021").unwrap()
}
fn selection() -> &'static SourceDecoderSelection {
    static SELECTED: std::sync::OnceLock<SourceDecoderSelection> = std::sync::OnceLock::new();
    SELECTED.get_or_init(|| SourceDecoderSelection::new(Arc::new(JsonSourceDecoder)))
}
fn request<'a>(
    root: &'a Path,
    id: &'a irmind_domain::CaseId,
    paths: &'a [String],
) -> MappedIngestRequest<'a> {
    MappedIngestRequest {
        case_id: id,
        source_root: root,
        relative_paths: paths,
        copy_original: false,
        parser: selection(),
        committed_artifacts: irmind_app::mapped_ingest::CommittedArtifacts::Slice(&[]),
        limits: irmind_app::PartitionLimits::default(),
    }
}
fn store(root: &Path, decoder: Arc<dyn SourceDecoder>) -> ParquetStore {
    let catalog = irmind_app::source_mapping::MappingCatalog::freeze(
        vec![decoder],
        vec![Arc::new(
            irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap(),
        )],
    )
    .unwrap();
    ParquetStore::open_mapped(root, Arc::new(catalog)).unwrap()
}
fn input_rows(disorder: bool) -> String {
    use std::fmt::Write as _;
    let mut rows = String::new();
    for n in 0..12_000 {
        let second = if disorder && n == 9000 { "00" } else { "01" };
        writeln!(
            rows,
            "{{\"eventTime\":\"2026-11-01T00:00:{second}Z\",\"eventName\":\"Read\",\"id\":{n}}}"
        )
        .unwrap();
    }
    rows
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
