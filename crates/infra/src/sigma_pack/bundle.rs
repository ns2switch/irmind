//! Decode the approved data-only package without extracting rule files.
use super::{LocalSigmaPack, check_cancel, invalid, validate_manifest_rule};
use irmind_app::{AppError, CancellationToken, v10_proofs::SigmaPackManifestV1};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const DOMAIN: &[u8] = b"irmind-sigma-package-v1\0";
const MAX_METADATA: usize = 8 * 1024;
const MAX_MANIFEST: usize = 64 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigmaPackageMetadata {
    pub format_version: u8,
    pub name: String,
    pub version: String,
    pub license: String,
    pub attribution: String,
}

impl SigmaPackageMetadata {
    pub fn decode_proof(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.is_empty() || bytes.len() > MAX_METADATA {
            return Err(invalid());
        }
        let metadata: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if !valid_metadata(&metadata)
            || serde_json::to_vec(&metadata).map_err(|_| invalid())? != bytes
        {
            return Err(invalid());
        }
        Ok(metadata)
    }
}

pub struct SigmaPackageBundle {
    pub metadata: SigmaPackageMetadata,
    pub metadata_sha256: [u8; 32],
    pub manifest_sha256: [u8; 32],
    pub asset_sha256: [u8; 32],
    pub pack: LocalSigmaPack,
}

/// Validate framing, canonical metadata and every exact rule in a local bundle.
/// Its license declaration is data for the installation preview and catalog review.
pub fn inspect_sigma_package_bundle(
    input: &[u8],
    cancel: &CancellationToken,
) -> Result<SigmaPackageBundle, AppError> {
    check_cancel(cancel)?;
    let mut body = input.strip_prefix(DOMAIN).ok_or_else(invalid)?;
    let metadata_bytes = frame(&mut body, MAX_METADATA)?;
    let metadata = SigmaPackageMetadata::decode_proof(metadata_bytes)?;
    let manifest_bytes = frame(&mut body, MAX_MANIFEST)?;
    let manifest = SigmaPackManifestV1::decode(manifest_bytes).map_err(|_| invalid())?;
    let mut paths = BTreeSet::new();
    let mut rules = Vec::with_capacity(manifest.0.len());
    for entry in &manifest.0 {
        check_cancel(cancel)?;
        if entry.path.split('/').count() > super::MAX_DEPTH
            || !paths.insert(entry.path.to_lowercase())
        {
            return Err(invalid());
        }
        let length = usize::try_from(entry.size).map_err(|_| invalid())?;
        let (rule, rest) = body.split_at_checked(length).ok_or_else(invalid)?;
        validate_manifest_rule(entry, rule)?;
        rules.push(rule.to_vec());
        body = rest;
    }
    if !body.is_empty() {
        return Err(invalid());
    }
    check_cancel(cancel)?;
    Ok(SigmaPackageBundle {
        metadata,
        metadata_sha256: irmind_app::sha256(metadata_bytes),
        manifest_sha256: irmind_app::sha256(manifest_bytes),
        asset_sha256: irmind_app::sha256(input),
        pack: LocalSigmaPack { manifest, rules },
    })
}

/// Open the catalog asset with the exact hash and metadata committed by the
/// verified index. The caller still needs attended Analyst admission.
pub fn inspect_sigma_catalog_asset(
    index: &irmind_app::catalog::SigmaCatalogIndex,
    name: &str,
    input: &[u8],
    cancel: &CancellationToken,
) -> Result<SigmaPackageBundle, AppError> {
    use irmind_app::catalog::{CatalogError, SigmaCatalogSource};

    let entry = index
        .entries()
        .iter()
        .find(|entry| entry.name == name)
        .ok_or(CatalogError::InvalidData)?;
    let SigmaCatalogSource::CatalogAsset { bytes, sha256, .. } = &entry.source else {
        return Err(CatalogError::InvalidData.into());
    };
    check_cancel(cancel)?;
    if input.len() as u64 != *bytes || irmind_app::sha256(input) != *sha256.as_bytes() {
        return Err(CatalogError::AssetMismatch.into());
    }
    let bundle = inspect_sigma_package_bundle(input, cancel)?;
    if bundle.metadata.name != entry.name
        || bundle.metadata.version != entry.version
        || bundle.metadata.license != entry.license
        || bundle.manifest_sha256 != *entry.manifest_sha256.as_bytes()
    {
        return Err(CatalogError::AssetMismatch.into());
    }
    Ok(bundle)
}

/// Authenticate a reviewed selection without storing or expanding unselected rules.
pub fn inspect_sigmahq_catalog_reference(
    index: &irmind_app::catalog::SigmaCatalogIndex,
    name: &str,
    archive: &[u8],
    selection: &[u8],
    cancel: &CancellationToken,
) -> Result<SigmaPackageBundle, AppError> {
    use irmind_app::catalog::{CatalogError, SigmaCatalogSource};

    let entry = index
        .entries()
        .iter()
        .find(|entry| entry.name == name)
        .ok_or(CatalogError::InvalidData)?;
    let SigmaCatalogSource::SigmahqArchive {
        bytes,
        sha256,
        attribution,
        selection_bytes,
        ..
    } = &entry.source
    else {
        return Err(CatalogError::InvalidData.into());
    };
    if selection.len() as u64 != *selection_bytes
        || irmind_app::sha256(selection) != *entry.manifest_sha256.as_bytes()
        || archive.len() as u64 != *bytes
    {
        return Err(CatalogError::AssetMismatch.into());
    }
    let manifest = SigmaPackManifestV1::decode(selection).map_err(|_| invalid())?;
    let pack = super::inspect_sigmahq_archive(archive, *sha256.as_bytes(), &manifest, cancel)?;
    let metadata = SigmaPackageMetadata {
        format_version: 1,
        name: entry.name.clone(),
        version: entry.version.clone(),
        license: entry.license.clone(),
        attribution: attribution.clone(),
    };
    let canonical = serde_json::to_vec(&metadata).map_err(|_| invalid())?;
    if canonical.len() > MAX_METADATA || !valid_metadata(&metadata) {
        return Err(invalid());
    }
    Ok(SigmaPackageBundle {
        metadata,
        metadata_sha256: irmind_app::sha256(&canonical),
        asset_sha256: *sha256.as_bytes(),
        manifest_sha256: *entry.manifest_sha256.as_bytes(),
        pack,
    })
}

fn frame<'a>(body: &mut &'a [u8], limit: usize) -> Result<&'a [u8], AppError> {
    let (header, rest) = body.split_first_chunk::<8>().ok_or_else(invalid)?;
    let length = usize::try_from(u64::from_be_bytes(*header)).map_err(|_| invalid())?;
    if length == 0 || length > limit {
        return Err(invalid());
    }
    let (frame, rest) = rest.split_at_checked(length).ok_or_else(invalid)?;
    *body = rest;
    Ok(frame)
}

fn valid_metadata(metadata: &SigmaPackageMetadata) -> bool {
    metadata.format_version == 1
        && irmind_app::v10_proofs::valid_sigma_package_identity(&metadata.name, &metadata.version)
        && irmind_app::v10_proofs::valid_sigma_license_expression(&metadata.license)
        && metadata.attribution.len() <= 4096
        && !metadata.attribution.chars().any(char::is_control)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn approved_package_vector_and_trailing_byte() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../docs/development/sigma-package-vectors/wire.json"
        ))
        .unwrap();
        let bytes = |name: &str| hex::decode(vectors[name]["bytes_hex"].as_str().unwrap()).unwrap();
        let cancel = CancellationToken::new();
        let raw = bytes("package");
        let bundle = inspect_sigma_package_bundle(&raw, &cancel).unwrap();
        assert_eq!(bundle.metadata.name, "synthetic");
        assert_eq!(bundle.pack.rules.len(), 1);
        assert!(
            inspect_sigma_package_bundle(&bytes("invalid_trailing_package_byte"), &cancel).is_err()
        );
        let mut bad_rule = raw;
        let last = bad_rule.last_mut().unwrap();
        *last ^= 1;
        assert!(inspect_sigma_package_bundle(&bad_rule, &cancel).is_err());
    }
}
