use super::{DomainError, MappingBindingV1, ParquetArtifactV3, invalid, wire};
use crate::{EvidenceHash, SetCommitment};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) fn artifacts(
    values: &[ParquetArtifactV3],
    tag: &[u8],
) -> Result<SetCommitment, DomainError> {
    if values.is_empty() || values.len() > 10_000_000 {
        return Err(invalid());
    }
    let mut ordered = values.iter().collect::<Vec<_>>();
    ordered.sort_by(|a, b| a.core().path.cmp(&b.core().path));
    let mut digest = begin(tag, values.len());
    let mut previous = None;
    let mut identities = BTreeSet::new();
    for value in ordered {
        if previous == Some(value.core().path.as_str()) || !identities.insert(value.identity()?) {
            return Err(invalid());
        }
        previous = Some(value.core().path.as_str());
        let canonical = wire::decode(&value.encode()?, super::artifact::TAG, wire::MAX_ARTIFACT)?;
        field(&mut digest, &canonical);
    }
    Ok(finish(digest, values.len()))
}

pub(super) fn bindings(
    values: &[MappingBindingV1],
    tag: &[u8],
) -> Result<SetCommitment, DomainError> {
    super::binding::validate_bindings(values)?;
    let mut digest = begin(tag, values.len());
    for value in values {
        let mut bytes = Vec::new();
        value.write(&mut bytes);
        field(&mut digest, &bytes);
    }
    Ok(finish(digest, values.len()))
}
fn begin(tag: &[u8], count: usize) -> Sha256 {
    let mut digest = Sha256::new();
    digest.update(tag);
    digest.update((count as u64).to_be_bytes());
    digest
}
fn field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}
fn finish(digest: Sha256, count: usize) -> SetCommitment {
    SetCommitment {
        count: count as u64,
        sha256: EvidenceHash::from_bytes(digest.finalize().into()),
    }
}
