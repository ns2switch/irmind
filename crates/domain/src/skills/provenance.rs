//! Methodology provenance is deliberately separate from evidence provenance.
use super::{SkillDigest, SkillError, SkillName, SkillPackage, SkillResourcePath, SkillVersion};
use std::ops::Range;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillResourceProvenance {
    pub name: SkillName,
    pub version: SkillVersion,
    pub package: SkillDigest,
    pub resource: SkillResourcePath,
    pub range: Range<usize>,
}

pub struct TaintedSkillResource<'a> {
    text: &'a str,
    provenance: SkillResourceProvenance,
}
impl<'a> TaintedSkillResource<'a> {
    pub fn new(
        name: SkillName,
        version: SkillVersion,
        package: &'a SkillPackage,
        path: &str,
        range: Range<usize>,
    ) -> Result<Self, SkillError> {
        let resource = SkillResourcePath::parse(path)?;
        let file = package
            .resources()
            .get(&resource)
            .ok_or(SkillError::InvalidPath)?;
        let text = file
            .untrusted_text()
            .get(range.clone())
            .ok_or(SkillError::InvalidText)?;
        Ok(Self {
            text,
            provenance: SkillResourceProvenance {
                name,
                version,
                package: *package.hash(),
                resource,
                range,
            },
        })
    }
    pub const fn untrusted_text(&self) -> &str {
        self.text
    }
    pub const fn provenance(&self) -> &SkillResourceProvenance {
        &self.provenance
    }
}
impl std::fmt::Debug for TaintedSkillResource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaintedSkillResource")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}
