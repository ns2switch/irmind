//! Sigma authentication shares release keys with skills and uses a distinct domain.
use super::{CATALOG_REPOSITORY, CatalogDigest, CatalogError, limits, schema::asset_name, version};
use crate::{
    Verifier,
    v10_proofs::{valid_sigma_license_expression, valid_sigma_package_identity},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const INDEX: &[u8] = b"irmind-sigma-catalog-index-v1\0";
const PROOF: &[u8] = b"irmind-sigma-catalog-proof-v1\0";
const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
const MAX_BUNDLE: u64 = 2 * MAX_ARCHIVE + 8192 + 64;
const SIGMAHQ: &str = "https://github.com/SigmaHQ/sigma/releases/download/";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Index {
    format_version: u8,
    catalog: String,
    key_id: CatalogDigest,
    release_tag: String,
    release_commit: String,
    release_sequence: u64,
    entries: Vec<SigmaCatalogEntry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigmaCatalogEntry {
    pub name: String,
    pub version: String,
    pub minimum_irmind_version: String,
    pub license: String,
    pub manifest_sha256: CatalogDigest,
    pub source: SigmaCatalogSource,
    pub coverage: Vec<[Option<String>; 3]>,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SigmaCatalogSource {
    CatalogAsset {
        asset: String,
        bytes: u64,
        sha256: CatalogDigest,
    },
    SigmahqArchive {
        url: String,
        bytes: u64,
        sha256: CatalogDigest,
        attribution: String,
        selection_asset: String,
        selection_bytes: u64,
    },
}

/// Verified publisher metadata. The analyst still admits the exact package.
pub struct SigmaCatalogIndex {
    index: Index,
    proof: Vec<u8>,
}

impl SigmaCatalogIndex {
    pub fn authenticate(
        raw: &[u8],
        signature: &[u8],
        expected_tag: &str,
        release_keys: &[[u8; 32]],
        verifier: &dyn Verifier,
    ) -> Result<Self, CatalogError> {
        if release_keys.is_empty() {
            return Err(CatalogError::Unavailable);
        }
        if release_keys.len() > 8 || signature.len() != 64 {
            return Err(CatalogError::InvalidData);
        }
        limits::check(raw)?;
        let index: Index = serde_json::from_slice(raw).map_err(|_| CatalogError::InvalidData)?;
        let mut matching = release_keys
            .iter()
            .filter(|key| crate::sha256(*key) == *index.key_id.as_bytes());
        let key = matching.next().ok_or(CatalogError::UntrustedKey)?;
        if matching.next().is_some() {
            return Err(CatalogError::InvalidData);
        }
        let mut preimage = INDEX.to_vec();
        preimage.extend((raw.len() as u64).to_be_bytes());
        preimage.extend(raw);
        verifier
            .verify(key, &preimage, signature)
            .map_err(|_| CatalogError::InvalidSignature)?;
        if index.release_tag != expected_tag {
            return Err(CatalogError::ReleaseMismatch);
        }
        index.validate()?;
        if serde_json::to_vec(&index).map_err(|_| CatalogError::InvalidData)? != raw {
            return Err(CatalogError::InvalidData);
        }
        let mut proof = PROOF.to_vec();
        proof.extend((raw.len() as u64).to_be_bytes());
        proof.extend(raw);
        proof.extend(signature);
        Ok(Self { index, proof })
    }

    /// Verify a retained kind-7 object against a signed proof commitment.
    pub fn authenticate_proof(
        proof: &[u8],
        expected_digest: [u8; 32],
        expected_tag: &str,
        release_keys: &[[u8; 32]],
        verifier: &dyn Verifier,
    ) -> Result<Self, CatalogError> {
        let (index, signature) = split_proof(proof, expected_digest)?;
        Self::authenticate(index, signature, expected_tag, release_keys, verifier)
    }

    /// Check every earlier release bound by authenticated global operations.
    pub fn check_release_history(
        &self,
        history: impl IntoIterator<Item = SigmaCatalogReleaseStamp>,
    ) -> Result<(), CatalogError> {
        let stamp = self.release_stamp();
        for previous in history {
            if (stamp.tag == previous.tag || stamp.sequence == previous.sequence)
                && stamp != previous
                || stamp.sequence < previous.sequence
            {
                return Err(CatalogError::ReleaseMismatch);
            }
        }
        Ok(())
    }

    pub fn release_stamp(&self) -> SigmaCatalogReleaseStamp {
        SigmaCatalogReleaseStamp {
            tag: self.index.release_tag.clone(),
            sequence: self.index.release_sequence,
            proof: crate::sha256(&self.proof),
        }
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
    pub fn entries(&self) -> &[SigmaCatalogEntry] {
        &self.index.entries
    }
    pub fn sequence(&self) -> u64 {
        self.index.release_sequence
    }
    pub fn tag(&self) -> &str {
        &self.index.release_tag
    }
    pub fn commit(&self) -> &str {
        &self.index.release_commit
    }
}

#[derive(Eq, PartialEq)]
pub struct SigmaCatalogReleaseStamp {
    tag: String,
    sequence: u64,
    proof: [u8; 32],
}

impl SigmaCatalogReleaseStamp {
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Recover the rollback floor from an already authenticated installation.
    /// The receipt binds the bytes even after this publisher key is retired.
    /// This stamp cannot authorize an installation or a publisher claim.
    pub fn from_signed_installation(
        proof: &[u8],
        expected_digest: [u8; 32],
    ) -> Result<Self, CatalogError> {
        let (raw, _) = split_proof(proof, expected_digest)?;
        limits::check(raw)?;
        let index: Index = serde_json::from_slice(raw).map_err(|_| CatalogError::InvalidData)?;
        index.validate()?;
        if serde_json::to_vec(&index).map_err(|_| CatalogError::InvalidData)? != raw {
            return Err(CatalogError::InvalidData);
        }
        Ok(Self {
            tag: index.release_tag,
            sequence: index.release_sequence,
            proof: expected_digest,
        })
    }
}

fn split_proof(proof: &[u8], expected_digest: [u8; 32]) -> Result<(&[u8], &[u8]), CatalogError> {
    if proof.len() > PROOF.len() + 8 + super::MAX_CATALOG_INDEX_BYTES + 64
        || crate::sha256(proof) != expected_digest
    {
        return Err(CatalogError::InvalidData);
    }
    let body = proof.strip_prefix(PROOF).ok_or(CatalogError::InvalidData)?;
    let (size, body) = body
        .split_first_chunk::<8>()
        .ok_or(CatalogError::InvalidData)?;
    let length =
        usize::try_from(u64::from_be_bytes(*size)).map_err(|_| CatalogError::InvalidData)?;
    let (index, signature) = body
        .split_at_checked(length)
        .ok_or(CatalogError::InvalidData)?;
    if signature.len() != 64 {
        return Err(CatalogError::InvalidData);
    }
    Ok((index, signature))
}

impl Index {
    fn validate(&self) -> Result<(), CatalogError> {
        if self.format_version != 1
            || self.catalog != CATALOG_REPOSITORY
            || self.release_sequence == 0
            || self.release_commit.len() != 40
            || !self
                .release_commit
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            || self.entries.len() > 1024
            || self
                .entries
                .windows(2)
                .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(CatalogError::InvalidData);
        }
        version::release_tag(&self.release_tag)?;
        let mut assets = BTreeSet::new();
        for entry in &self.entries {
            let asset = entry.validate()?;
            if !assets.insert(asset.to_ascii_lowercase()) {
                return Err(CatalogError::InvalidData);
            }
        }
        Ok(())
    }
}

impl SigmaCatalogEntry {
    pub fn supports_irmind(&self, running: &str) -> Result<bool, CatalogError> {
        let running = version::Version::parse(running)?;
        let minimum = version::Version::parse(&self.minimum_irmind_version)?;
        Ok(!running.compare(&minimum).is_lt())
    }

    fn validate(&self) -> Result<&str, CatalogError> {
        if !valid_sigma_package_identity(&self.name, &self.version)
            || super::version::Version::parse(&self.minimum_irmind_version).is_err()
            || !valid_sigma_license_expression(&self.license)
            || self.coverage.len() > 128
            || self.coverage.windows(2).any(|pair| pair[0] >= pair[1])
            || self.coverage.iter().any(|fields| {
                fields.iter().all(Option::is_none)
                    || fields.iter().flatten().any(|s| {
                        s.is_empty()
                            || s.len() > 128
                            || !s.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')
                            })
                    })
            })
        {
            return Err(CatalogError::InvalidData);
        }
        let asset = match &self.source {
            SigmaCatalogSource::CatalogAsset { asset, bytes, .. }
                if (1..=MAX_BUNDLE).contains(bytes) =>
            {
                asset
            }
            SigmaCatalogSource::SigmahqArchive {
                url,
                bytes,
                attribution,
                selection_asset,
                selection_bytes,
                ..
            } if self.license == "DRL-1.1"
                && (1..=MAX_ARCHIVE).contains(bytes)
                && (1..=MAX_ARCHIVE).contains(selection_bytes)
                && (1..=4096).contains(&attribution.len())
                && !attribution.chars().any(char::is_control)
                && official_archive(url) =>
            {
                selection_asset
            }
            _ => return Err(CatalogError::InvalidData),
        };
        if !asset_name(asset)
            || matches!(
                asset.to_ascii_lowercase().as_str(),
                "sigma-index.json" | "sigma-index.ed25519"
            )
        {
            return Err(CatalogError::InvalidData);
        }
        Ok(asset)
    }
}

fn official_archive(url: &str) -> bool {
    url.strip_prefix(SIGMAHQ)
        .and_then(|suffix| suffix.split_once('/'))
        .is_some_and(|(tag, asset)| {
            (1..=64).contains(&tag.len())
                && tag.as_bytes()[0].is_ascii_alphanumeric()
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
                && asset_name(asset)
                && std::path::Path::new(asset)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
        })
}
