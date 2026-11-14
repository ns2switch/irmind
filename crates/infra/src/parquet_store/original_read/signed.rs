use super::{AppError, EvidenceHash, unavailable};
use irmind_app::SignedEntry;
use irmind_domain::{
    AuditEventKind, MappingProfileRecordV1, MappingProfileV1, ParquetArtifact, SourceManifestV2,
    SourceRecordSetV1,
};

pub(super) struct SignedSource {
    pub manifest: SourceManifestV2,
    pub set: SourceRecordSetV1,
    pub profile: MappingProfileV1,
}

pub(super) fn select(
    entries: &[SignedEntry],
    artifacts: &[ParquetArtifact],
    hash: &EvidenceHash,
) -> Result<SignedSource, AppError> {
    let bindings = artifacts
        .iter()
        .flat_map(|a| {
            let ParquetArtifact::V3(a) = a;
            a.bindings()
        })
        .filter(|b| b.input().source() == hash)
        .collect::<Vec<_>>();
    let first = bindings
        .first()
        .ok_or_else(|| unavailable("Original source has no signed active input set"))?;
    if bindings
        .iter()
        .any(|b| b.input().set() != first.input().set())
    {
        return Err(unavailable(
            "Original source pointer is ambiguous across decoded input sets",
        ));
    }
    let mut set = None;
    let mut profile = None;
    for entry in entries {
        match entry.kind {
            AuditEventKind::SourceRecordSetV1 => {
                let value = SourceRecordSetV1::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))?;
                if &value
                    .identity()
                    .map_err(|_| AppError::InvalidChain(entry.seq))?
                    == first.input().set()
                {
                    set = Some(value);
                }
            }
            AuditEventKind::MappingProfileV1 => {
                if let MappingProfileRecordV1::Profile(value) =
                    MappingProfileRecordV1::decode(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?
                    && &value
                        .identity()
                        .map_err(|_| AppError::InvalidChain(entry.seq))?
                        == first.profile()
                {
                    profile = Some(value);
                }
            }
            _ => {}
        }
    }
    let set = set.ok_or_else(|| unavailable("Signed decoded input set is missing"))?;
    let manifest = find_manifest(entries, &set)?;
    let value = SignedSource {
        manifest,
        set,
        profile: profile.ok_or_else(|| unavailable("Signed mapping profile is missing"))?,
    };
    value
        .set
        .validate_manifest(&value.manifest)
        .map_err(|_| unavailable("Signed original source links disagree"))?;
    if value.set.source() != hash
        || value.set.records() != first.input().records()
        || value.set.decoder() != first.decoder()
    {
        return Err(unavailable("Signed original decoder binding disagrees"));
    }
    Ok(value)
}

fn find_manifest(
    entries: &[SignedEntry],
    set: &SourceRecordSetV1,
) -> Result<SourceManifestV2, AppError> {
    for entry in entries
        .iter()
        .filter(|e| e.kind == AuditEventKind::SourceManifestV2)
    {
        let manifest = SourceManifestV2::decode(&entry.payload)
            .map_err(|_| AppError::InvalidChain(entry.seq))?;
        if set.validate_manifest(&manifest).is_ok() {
            return Ok(manifest);
        }
    }
    Err(unavailable(
        "The manifest linked by the signed decoded input set is missing",
    ))
}
