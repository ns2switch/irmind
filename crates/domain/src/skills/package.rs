use super::{
    MAX_SKILL_BYTES, MAX_SKILL_PACKAGE_BYTES, MAX_SKILL_RESOURCE_BYTES, MAX_SKILL_RESOURCES,
    SkillError, valid_text,
};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Methodology identity, deliberately distinct from an evidence hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkillDigest([u8; 32]);

impl SkillDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkillResourcePath(String);

impl SkillResourcePath {
    pub fn parse(value: &str) -> Result<Self, SkillError> {
        if value == "SKILL.md" {
            return Ok(Self(value.into()));
        }
        let (directory, file) = value.split_once('/').ok_or(SkillError::InvalidPath)?;
        if value.len() > 160
            || !value.is_ascii()
            || !matches!(directory, "queries" | "rules" | "references")
            || file.is_empty()
            || file.starts_with('.')
            || file.ends_with('.')
            || file.ends_with(' ')
            || file.contains("..")
            || file.contains('/')
            || !file
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
            || reserved_windows_name(file)
        {
            return Err(SkillError::InvalidPath);
        }
        let extension = file
            .rsplit_once('.')
            .ok_or(SkillError::UnsupportedResource)?
            .1;
        if !matches!(extension, "json" | "toml" | "md" | "csv" | "yaml" | "yml") {
            return Err(SkillError::UnsupportedResource);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn reserved_windows_name(file: &str) -> bool {
    let stem = file
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
            })
        })
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillResource {
    path: SkillResourcePath,
    text: String,
}

impl SkillResource {
    pub fn new(path: &str, contents: &[u8]) -> Result<Self, SkillError> {
        let path = SkillResourcePath::parse(path)?;
        let maximum = if path.as_str() == "SKILL.md" {
            MAX_SKILL_BYTES
        } else {
            MAX_SKILL_RESOURCE_BYTES
        };
        if contents.len() > maximum {
            return Err(SkillError::LimitExceeded);
        }
        let text = std::str::from_utf8(contents).map_err(|_| SkillError::InvalidText)?;
        if !valid_text(text) {
            return Err(SkillError::InvalidText);
        }
        Ok(Self {
            path,
            text: text.into(),
        })
    }

    pub const fn path(&self) -> &SkillResourcePath {
        &self.path
    }

    /// Original untrusted text; presentation/model callers must use `ContentGuard`.
    pub fn untrusted_text(&self) -> &str {
        &self.text
    }
}

impl std::fmt::Debug for SkillResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillResource")
            .field("bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

/// An immutable inventory, not an approved installation or an evidence item.
#[derive(Clone, Eq, PartialEq)]
pub struct SkillPackage {
    resources: BTreeMap<SkillResourcePath, SkillResource>,
    bytes: usize,
    hash: SkillDigest,
}

impl SkillPackage {
    pub fn new(resources: impl IntoIterator<Item = SkillResource>) -> Result<Self, SkillError> {
        let mut files = BTreeMap::new();
        let mut folded = BTreeSet::new();
        let mut bytes = 0usize;
        for resource in resources {
            if files.len() > MAX_SKILL_RESOURCES {
                return Err(SkillError::LimitExceeded);
            }
            bytes = bytes
                .checked_add(resource.text.len())
                .ok_or(SkillError::LimitExceeded)?;
            if bytes > MAX_SKILL_PACKAGE_BYTES {
                return Err(SkillError::LimitExceeded);
            }
            if !folded.insert(resource.path.as_str().to_ascii_lowercase()) {
                return Err(SkillError::DuplicatePath);
            }
            files.insert(resource.path.clone(), resource);
        }
        if !files.keys().any(|path| path.as_str() == "SKILL.md") {
            return Err(SkillError::MissingMethodology);
        }
        let mut package = Self {
            resources: files,
            bytes,
            hash: SkillDigest([0; 32]),
        };
        package.hash = SkillDigest(Sha256::digest(package.canonical_inventory()).into());
        Ok(package)
    }

    pub const fn hash(&self) -> &SkillDigest {
        &self.hash
    }

    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    pub const fn resources(&self) -> &BTreeMap<SkillResourcePath, SkillResource> {
        &self.resources
    }

    /// Canonical package commitment; this is not an evidence or case frame.
    pub fn canonical_inventory(&self) -> Vec<u8> {
        let mut out = b"irmind-skill-package-v1\0".to_vec();
        out.extend_from_slice(&(self.resources.len() as u64).to_be_bytes());
        for (path, resource) in &self.resources {
            crate::canonical::put(&mut out, path.as_str().as_bytes());
            out.extend_from_slice(&(resource.text.len() as u64).to_be_bytes());
            out.extend_from_slice(&Sha256::digest(resource.text.as_bytes()));
        }
        out
    }
}

impl std::fmt::Debug for SkillPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillPackage")
            .field("files", &self.resources.len())
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}
