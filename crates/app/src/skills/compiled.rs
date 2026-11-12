use irmind_domain::{SkillError, SkillMetadata, SkillPackage};

/// Compiled, still-untrusted data; this value is not an installation approval.
pub struct CompiledSkill {
    metadata: SkillMetadata,
    package: SkillPackage,
    body_offset: usize,
}

impl CompiledSkill {
    pub fn new(
        metadata: SkillMetadata,
        package: SkillPackage,
        body_offset: usize,
    ) -> Result<Self, SkillError> {
        let source = package
            .resources()
            .values()
            .find(|resource| resource.path().as_str() == "SKILL.md")
            .ok_or(SkillError::MissingMethodology)?
            .untrusted_text();
        if body_offset >= source.len()
            || !source.is_char_boundary(body_offset)
            || source[body_offset..].trim().is_empty()
        {
            return Err(SkillError::MissingMethodology);
        }
        Ok(Self {
            metadata,
            package,
            body_offset,
        })
    }

    pub const fn metadata(&self) -> &SkillMetadata {
        &self.metadata
    }
    pub const fn package(&self) -> &SkillPackage {
        &self.package
    }
    pub const fn body_offset(&self) -> usize {
        self.body_offset
    }
}

impl std::fmt::Debug for CompiledSkill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledSkill")
            .field("metadata", &self.metadata)
            .field("package", &self.package)
            .finish_non_exhaustive()
    }
}
