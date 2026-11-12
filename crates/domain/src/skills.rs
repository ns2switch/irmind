//! Bounded, untrusted skill data. Validation grants no tool or content authority.

mod metadata;
mod package;
mod provenance;
pub use provenance::{SkillResourceProvenance, TaintedSkillResource};

pub use metadata::{SkillMetadata, SkillMetadataInput, SkillName, SkillVersion};
pub use package::{SkillDigest, SkillPackage, SkillResource, SkillResourcePath};

pub const SKILL_FORMAT_V1: &str = "irmind-skill-v1";
pub const MAX_SKILL_BYTES: usize = 32 * 1024;
pub const MAX_SKILL_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_SKILL_PACKAGE_BYTES: usize = 128 * 1024;
pub const MAX_SKILL_RESOURCES: usize = 16;
pub const MAX_SKILL_RESOURCE_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkillError {
    InvalidMetadata,
    UnsupportedFormat,
    UnsupportedSchema,
    UnsupportedLicense,
    UnknownTool,
    InvalidPath,
    DuplicatePath,
    InvalidText,
    InvalidFrontmatter,
    UnsupportedResource,
    LimitExceeded,
    MissingMethodology,
}

impl std::fmt::Display for SkillError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidMetadata => "Skill metadata is invalid",
            Self::UnsupportedFormat => "Skill format is not supported",
            Self::UnsupportedSchema => "Skill target schema is not supported",
            Self::UnsupportedLicense => "Skill license requires distribution review",
            Self::UnknownTool => "Skill declares an unknown tool",
            Self::InvalidPath => "Skill resource path is invalid",
            Self::DuplicatePath => "Skill package contains duplicate resource paths",
            Self::InvalidText => "Skill text is invalid or contains disallowed controls",
            Self::InvalidFrontmatter => "Skill TOML frontmatter is invalid",
            Self::UnsupportedResource => "Skill resource format is not supported",
            Self::LimitExceeded => "Skill exceeds a package or field limit",
            Self::MissingMethodology => "Skill package must contain SKILL.md",
        })
    }
}

impl std::error::Error for SkillError {}

pub(super) fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
        && value.trim() == value
        && valid_text(value)
}

pub(super) fn valid_identifier(value: &str) -> bool {
    value.len() <= 64
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

pub(super) fn valid_text(value: &str) -> bool {
    value.chars().all(|c| {
        (!c.is_control() || matches!(c, '\n' | '\r' | '\t'))
            && !matches!(c, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
    }) && value
        .as_bytes()
        .iter()
        .enumerate()
        .all(|(index, c)| *c != b'\r' || value.as_bytes().get(index + 1) == Some(&b'\n'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
