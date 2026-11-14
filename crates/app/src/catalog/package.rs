use super::{CatalogAsset, CatalogError, limits};
use crate::{AppError, CompiledSkill, SkillCompiler};
use irmind_domain::{SkillPackage, SkillResource};
use serde::{Deserialize, Serialize};

/// Bounded untrusted transport data; not an installed or admitted skill.
pub struct BoundedPackageBytes(Vec<u8>);
impl BoundedPackageBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > 1024 * 1024 {
            return Err(CatalogError::InvalidData);
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Package {
    format_version: u8,
    files: Vec<Resource>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    path: String,
    contents: String,
}

impl CatalogAsset {
    /// Reuses the existing compiler. `ContentGuard` and Analyst admission are
    /// still required; successful compilation grants no runtime permission.
    pub fn compile(
        &self,
        raw: &BoundedPackageBytes,
        running_version: &str,
        compiler: &dyn SkillCompiler,
    ) -> Result<CompiledSkill, AppError> {
        self.check_bytes(raw.as_bytes())?;
        if !self.entry().supports_version(running_version)? {
            return Err(CatalogError::InvalidData.into());
        }
        limits::check(raw.as_bytes())?;
        let wire: Package =
            serde_json::from_slice(raw.as_bytes()).map_err(|_| CatalogError::InvalidData)?;
        if wire.format_version != 1
            || wire.files.len() > 17
            || wire
                .files
                .windows(2)
                .any(|pair| pair[0].path >= pair[1].path)
            || serde_json::to_vec(&wire).map_err(|_| CatalogError::InvalidData)? != raw.as_bytes()
        {
            return Err(CatalogError::InvalidData.into());
        }
        let resources = wire
            .files
            .into_iter()
            .map(|file| SkillResource::new(&file.path, file.contents.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;
        let package = SkillPackage::new(resources)?;
        if package.hash().as_bytes() != self.entry().package_hash().as_bytes() {
            return Err(CatalogError::AssetMismatch.into());
        }
        let skill = compiler.compile(package)?;
        if skill.metadata().name().as_str() != self.entry().name()
            || skill.metadata().version().as_str() != self.entry().version()
            || !skill
                .metadata()
                .sources()
                .iter()
                .map(String::as_str)
                .eq(self.entry().sources().iter().map(String::as_str))
        {
            return Err(CatalogError::InvalidData.into());
        }
        Ok(skill)
    }
}
