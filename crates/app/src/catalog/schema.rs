use super::{CATALOG_REPOSITORY, CatalogDigest, CatalogError, limits, version};
use irmind_domain::{SkillName, SkillVersion};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogIndex {
    format_version: u8,
    catalog: String,
    key_id: CatalogDigest,
    release_tag: String,
    release_commit: String,
    release_sequence: u64,
    entries: Vec<CatalogEntry>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    name: String,
    version: String,
    package_sha256: CatalogDigest,
    asset: String,
    asset_sha256: CatalogDigest,
    asset_bytes: u64,
    minimum_irmind_version: String,
    target_schema: String,
    interpreter: String,
    sources: Vec<String>,
    mappings: Vec<String>,
    coverage: CatalogCoverage,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogCoverage {
    status: CatalogCoverageStatus,
    description: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CatalogCoverageStatus {
    Complete,
    Partial,
    Unavailable,
}

impl CatalogIndex {
    /// Bounded structure only; this does not authenticate any catalog claim.
    pub fn decode_untrusted(bytes: &[u8]) -> Result<Self, CatalogError> {
        limits::check(bytes)?;
        let index: Self = serde_json::from_slice(bytes).map_err(|_| CatalogError::InvalidData)?;
        index.validate()?;
        if serde_json::to_vec(&index).map_err(|_| CatalogError::InvalidData)? != bytes {
            return Err(CatalogError::InvalidData);
        }
        Ok(index)
    }
    fn validate(&self) -> Result<(), CatalogError> {
        if self.format_version != 1
            || self.catalog != CATALOG_REPOSITORY
            || self.release_sequence == 0
            || self.release_commit.len() != 40
            || !self
                .release_commit
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || self.entries.len() > 1024
            || self.entries.windows(2).any(|e| e[0].name >= e[1].name)
        {
            return Err(CatalogError::InvalidData);
        }
        version::release_tag(&self.release_tag)?;
        let mut assets = std::collections::BTreeSet::new();
        for entry in &self.entries {
            entry.validate()?;
            if !assets.insert(entry.asset.to_ascii_lowercase()) {
                return Err(CatalogError::InvalidData);
            }
        }
        Ok(())
    }
    pub const fn key_id(&self) -> CatalogDigest {
        self.key_id
    }
    pub fn tag(&self) -> &str {
        &self.release_tag
    }
    pub fn commit(&self) -> &str {
        &self.release_commit
    }
    pub const fn sequence(&self) -> u64 {
        self.release_sequence
    }
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }
}
impl CatalogEntry {
    fn validate(&self) -> Result<(), CatalogError> {
        SkillName::parse(&self.name).map_err(|_| CatalogError::InvalidData)?;
        SkillVersion::parse(&self.version).map_err(|_| CatalogError::InvalidData)?;
        version::Version::parse(&self.minimum_irmind_version)?;
        if self.asset_bytes == 0
            || self.asset_bytes > 1024 * 1024
            || !asset_name(&self.asset)
            || self.target_schema != irmind_domain::COMMON_EVENT_V1
            || self.interpreter != "irmind-skill-interpreter-v1"
            || self.coverage.description.len() > 512
        {
            return Err(CatalogError::InvalidData);
        }
        identifiers(&self.sources)?;
        identifiers(&self.mappings)
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub const fn package_hash(&self) -> CatalogDigest {
        self.package_sha256
    }
    pub fn asset(&self) -> &str {
        &self.asset
    }
    pub const fn asset_hash(&self) -> CatalogDigest {
        self.asset_sha256
    }
    pub const fn asset_bytes(&self) -> u64 {
        self.asset_bytes
    }
    pub fn sources(&self) -> &[String] {
        &self.sources
    }
    pub fn mappings(&self) -> &[String] {
        &self.mappings
    }
    pub const fn coverage(&self) -> &CatalogCoverage {
        &self.coverage
    }
    pub fn supports_version(&self, running: &str) -> Result<bool, CatalogError> {
        Ok(version::Version::parse(running)?
            .compare(&version::Version::parse(&self.minimum_irmind_version)?)
            != std::cmp::Ordering::Less)
    }
    pub fn identity(&self) -> Result<CatalogDigest, CatalogError> {
        let mut bytes = b"irmind-skill-catalog-entry-v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|_| CatalogError::InvalidData)?);
        Ok(CatalogDigest::from_bytes(crate::sha256(&bytes)))
    }
}
impl CatalogCoverage {
    pub const fn status(&self) -> CatalogCoverageStatus {
        self.status
    }
    /// Untrusted publisher text; guard and escape it before presentation.
    pub fn untrusted_description(&self) -> &str {
        &self.description
    }
}
fn identifiers(values: &[String]) -> Result<(), CatalogError> {
    if values.len() > 32
        || values.windows(2).any(|v| v[0] >= v[1])
        || values.iter().any(|v| {
            v.len() > 64
                || !v.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                || !v.bytes().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_')
                })
        })
    {
        return Err(CatalogError::InvalidData);
    }
    Ok(())
}
pub(super) fn asset_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('.')
        || value.ends_with('.')
        || value.contains("..")
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix)
                .is_some_and(|suffix| suffix.len() == 1 && suffix.as_bytes()[0].is_ascii_digit())
        })
}
