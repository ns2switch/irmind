use super::*;
use parquet::file::reader::{FileReader, SerializedFileReader};
pub(super) fn check(store: &LocalStore, case: &CaseId, root: &Path, expected: u64) {
    let entries = store.entries(case).unwrap();
    let catalog = irmind_app::artifact_catalog(&entries).unwrap();
    let count: u64 = catalog
        .active
        .iter()
        .filter(|a| a.schema_version().starts_with("irmind-events-"))
        .map(|a| {
            let file =
                fs::File::open(root.join("parquet").join(case.as_str()).join(a.path())).unwrap();
            u64::try_from(
                SerializedFileReader::new(file)
                    .unwrap()
                    .metadata()
                    .file_metadata()
                    .num_rows(),
            )
            .unwrap()
        })
        .sum();
    assert_eq!(count, expected);
    let mut schema_bytes = BTreeMap::<String, u64>::new();
    for artifact in &catalog.active {
        *schema_bytes
            .entry(artifact.schema_version().into())
            .or_default() += artifact.size();
    }
    println!(
        "PIPELINE_LAYOUT {}",
        serde_json::json!({
            "files":catalog.active.len(), "by_schema_bytes":schema_bytes,
            "active_bytes":catalog.active.iter().map(irmind_domain::ParquetArtifact::size).sum::<u64>()
        })
    );
    let manifests: Vec<_> = entries
        .iter()
        .filter(|e| e.kind == irmind_domain::AuditEventKind::SourceManifestV2)
        .map(|e| irmind_domain::SourceManifestV2::decode(&e.payload).unwrap())
        .collect();
    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0].rejected_records, 0);
    println!(
        "PIPELINE_SOURCE sha256={}",
        manifests[0].source.sha256.as_str()
    );
}
pub(super) fn print(
    label: &str,
    mapped: bool,
    repetition: u32,
    input: &sources::Input,
    elapsed: std::time::Duration,
    profile: &ParquetProfile,
    mapping: &mapped::Timings,
) {
    let [hash, conversion, row, parquet, _, _] = profile.snapshot();
    let [validation_mapping, projection, commitment] = profile.mapping_snapshot();
    let [decoder, pure_mapping] = mapping.snapshot();
    let partition = profile.partition_snapshot().map(|d| d.as_secs_f64());
    println!(
        "PIPELINE_PRODUCTION {}",
        serde_json::json!({
            "source":label,"mapped":mapped,"repetition":repetition,"bytes":input.bytes,"records":input.records,"accepted_records":input.records,"rejected_records":0,
            "elapsed_seconds":elapsed.as_secs_f64(), "phase_coverage":if mapped { "V3 production decoder, mapper, adapter, writer and custody" } else { "V2 wall, hash, partition and custody; typed phases do not apply" }, "hash_seconds":hash.as_secs_f64(),
            "conversion_inclusive_seconds":conversion.as_secs_f64(), "row_seconds":mapped.then_some(row.as_secs_f64()),
            "parquet_seconds":mapped.then_some(parquet.as_secs_f64()), "decoder_exclusive_seconds":decoder.as_secs_f64(),
            "mapper_seconds":pure_mapping.as_secs_f64(),
            "validation_selection_commit_spool_seconds":validation_mapping.saturating_sub(pure_mapping).as_secs_f64(),
            "projection_seconds":projection.as_secs_f64(),"commitment_finalize_seconds":commitment.as_secs_f64(),
            "partition_inclusive_seconds":partition,
        })
    );
}
