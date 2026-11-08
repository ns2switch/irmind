use super::{
    AppError, EvidenceHash, ParquetArtifact, Path, StagedArtifact, fs, invalid_source, storage,
};
use irmind_domain::ParquetArtifactV1;
use std::collections::BTreeSet;

pub(super) fn validate_sources(
    sources: &[ParquetArtifact],
) -> Result<(Vec<ParquetArtifact>, Vec<EvidenceHash>), AppError> {
    if !(2..=128).contains(&sources.len()) {
        return Err(AppError::Policy(
            "Parquet compaction requires 2–128 sources".into(),
        ));
    }
    if matches!(&sources[0], ParquetArtifact::V3(_)) {
        return Ok((sources.to_vec(), super::mapped::validate(sources)?));
    }
    let first = &sources[0];
    let mut hashes = BTreeSet::new();
    for source in sources {
        source.validate().map_err(|_| invalid_source())?;
        let allowed = match source {
            ParquetArtifact::V1(v) => {
                v.parser_version == "json-stream-v3"
                    && matches!(
                        v.schema_version.as_str(),
                        "irmind-events-v2"
                            | "irmind-entities-v1"
                            | "irmind-entities-v2"
                            | "irmind-coobservations-v1"
                    )
            }
            ParquetArtifact::V3(_) => false,
            ParquetArtifact::V2(v) => {
                super::super::partitioning::supported_builder(&v.builder_version)
                    && v.superseded_hashes.is_empty()
            }
        };
        if !allowed
            || source.compaction_key() != first.compaction_key()
            || source.source_hashes().len() != 1
            || !hashes.insert(source.source_hashes()[0].clone())
        {
            return Err(invalid_source());
        }
    }
    Ok((sources.to_vec(), hashes.into_iter().collect()))
}

pub(super) fn stage(
    case_dir: &Path,
    sources: &[ParquetArtifact],
    hashes: Vec<EvidenceHash>,
) -> Result<StagedArtifact, AppError> {
    let first = sources.first().ok_or_else(invalid_source)?;
    if matches!(first, ParquetArtifact::V3(_)) {
        return super::mapped::stage(case_dir, sources);
    }
    let (part, digest_input) = match first {
        ParquetArtifact::V1(v) => (
            format!(
                "date={}/account={}/region={}",
                v.partition_date, v.partition_account, v.partition_region
            ),
            format!(
                "irmind-parquet-compact-v1\n{}\n{}",
                v.schema_version,
                hashes
                    .iter()
                    .map(EvidenceHash::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            )
            .into_bytes(),
        ),
        ParquetArtifact::V3(_) => return Err(invalid_source()),
        ParquetArtifact::V2(v) => {
            let mut bytes = first.compaction_key();
            for h in &hashes {
                bytes.extend_from_slice(h.as_str().as_bytes());
            }
            (
                v.partition
                    .path_prefix()
                    .map_err(|_| invalid_source())?
                    .trim_end_matches('/')
                    .into(),
                bytes,
            )
        }
    };
    let name = format!(
        "bundle-{}.parquet",
        irmind_app::hex(&irmind_app::sha256(&digest_input))
    );
    let path = format!("{part}/{name}");
    let dir = case_dir.join(part);
    fs::create_dir_all(&dir).map_err(storage)?;
    irmind_fs::private_dir(&dir).map_err(storage)?;
    let temporary = dir.join(format!(".{name}.{}.tmp", rand::random::<u64>()));
    let zero = EvidenceHash::parse(&"0".repeat(64)).map_err(|_| invalid_source())?;
    let manifest = match first {
        ParquetArtifact::V1(v) => ParquetArtifactV1 {
            path,
            size: 0,
            sha256: zero,
            parser_version: format!("{}+compact-v1", v.parser_version),
            schema_version: v.schema_version.clone(),
            partition_date: v.partition_date.clone(),
            partition_account: v.partition_account.clone(),
            partition_region: v.partition_region.clone(),
            source_hashes: hashes,
        }
        .into(),
        ParquetArtifact::V3(_) => return Err(invalid_source()),
        ParquetArtifact::V2(v) => {
            let mut next = v.clone();
            next.path = path;
            next.size = 0;
            next.sha256 = zero;
            next.source_hashes = hashes;
            next.into()
        }
    };
    Ok(StagedArtifact {
        temporary,
        manifest,
    })
}
