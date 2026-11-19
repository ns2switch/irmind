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
    assert_eq!(budget.normalized_bytes, size * 16 + MAX_STAGED_ROW);
    assert_eq!(budget.decoded_byte_ceiling, None);
    assert_eq!(file.stream_position().unwrap(), 0);
    assert!(matches!(
        check_space(budget.normalized_bytes - 1, budget.normalized_bytes),
        Err(AppError::Fixed(irmind_app::FixedAppError::StorageCaseStagingCapacity {
            required, available
        })) if required == budget.normalized_bytes && available == required - 1
    ));
    assert!(check_space(budget.normalized_bytes, budget.normalized_bytes).is_ok());
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
    assert_eq!(
        budget.normalized_bytes,
        bytes.len() as u64 * 32 + MAX_STAGED_ROW
    );
    assert_eq!(budget.decoded_byte_ceiling, None);
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

#[test]
fn decoded_json_reservation_is_restricted_to_the_current_fdr_decoder() {
    let budget =
        NormalizedSourceBudget::try_new(1024, NormalizedExpansionProfile::DecodedJson16).unwrap();
    let fdr = irmind_app::ParserIdentity {
        name: "parser-fdr",
        version: "fdr-source-v1",
    };
    let reservation = reserve_profile(fdr, budget).unwrap();
    assert_eq!(reservation.decoded_byte_ceiling, Some(1024));
    assert_eq!(reservation.normalized_bytes, 1024 * 16 + MAX_STAGED_ROW);
    for name in [
        "parser-json",
        "parser-vpc-flow",
        "parser-alb",
        "parser-s3-access",
    ] {
        assert!(reserve_profile(irmind_app::ParserIdentity { name, ..fdr }, budget).is_err());
    }
    assert!(
        reserve_profile(
            irmind_app::ParserIdentity {
                version: "fdr-source-v2",
                ..fdr
            },
            budget
        )
        .is_err()
    );
}
