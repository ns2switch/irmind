#![allow(clippy::unwrap_used)]
use super::*;
use std::{io::Seek, sync::Arc};
#[test]
fn default_decoder_keeps_historical_allowance_and_rewinds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.json");
    let bytes = b"{}";
    std::fs::write(&path, bytes).unwrap();
    let mut file = File::open(&path).unwrap();
    file.seek(SeekFrom::Start(1)).unwrap();
    let store = crate::parquet_store::fixtures::store(dir.path());
    let (size, budget) = store
        .normalized_allowance(
            &mut file,
            &crate::parquet_store::fixtures::parser(),
            "source.json",
            &CancellationToken::new(),
        )
        .unwrap();
    assert_eq!(size, bytes.len() as u64);
    assert_eq!(budget, size * 16 + MAX_STAGED_ROW);
    assert_eq!(file.stream_position().unwrap(), 0);
    assert!(check_space(budget - 1, budget).is_err());
    assert!(check_space(budget, budget).is_ok());
    assert!(standard_allowance(u64::MAX).is_err());
}
#[test]
fn compact_decoder_uses_approved_allowance_and_cancellation_rewinds_without_spooling() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("flows.log");
    let bytes = include_bytes!("../../../../../testkit/fixtures/parser-vpc-flow/source/custom.log");
    std::fs::write(&path, bytes).unwrap();
    let catalog = irmind_app::source_mapping::MappingCatalog::freeze(
        vec![Arc::new(irmind_mod_parser_vpc_flow::VpcFlowSourceDecoder)],
        vec![Arc::new(
            irmind_mod_mapping_cloud_flow::CloudFlowMapping::aws().unwrap(),
        )],
    )
    .unwrap();
    let store = ParquetStore::open_mapped(dir.path(), Arc::new(catalog)).unwrap();
    let mut file = File::open(&path).unwrap();
    let parser = irmind_mod_parser_vpc_flow::VpcFlowParser;
    let (_, budget) = store
        .normalized_allowance(&mut file, &parser, "flows.log", &CancellationToken::new())
        .unwrap();
    assert_eq!(budget, bytes.len() as u64 * 32 + MAX_STAGED_ROW);
    assert_eq!(file.stream_position().unwrap(), 0);
    let before = std::fs::read_dir(dir.path()).unwrap().count();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        store.normalized_allowance(&mut file, &parser, "flows.log", &cancel),
        Err(AppError::Cancelled)
    ));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), before);
}

#[test]
fn only_source_format_and_source_limits_allow_exclusion_retries() -> Result<(), AppError> {
    for (error, reason) in [
        (
            irmind_app::FixedAppError::SourceFormat,
            irmind_app::SourceFailureReason::Format,
        ),
        (
            irmind_app::FixedAppError::SourceLimit,
            irmind_app::SourceFailureReason::Limit,
        ),
    ] {
        match source_preflight_result(Err(AppError::Fixed(error)), "flows.gz") {
            Err(AppError::SourceFailure(rejected)) => {
                assert_eq!(rejected.source(), "flows.gz");
                assert_eq!(rejected.reason(), reason);
            }
            _ => return Err(AppError::Storage("source error was not classified".into())),
        }
    }
    assert!(matches!(
        source_preflight_result(Err(AppError::Cancelled), "flows.gz"),
        Err(AppError::Cancelled)
    ));
    assert!(matches!(
        source_preflight_result(Err(no_space()), "flows.gz"),
        Err(AppError::Fixed(
            irmind_app::FixedAppError::StorageNormalizedStagingSpace
        ))
    ));
    Ok(())
}
