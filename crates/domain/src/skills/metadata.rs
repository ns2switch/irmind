use super::{SKILL_FORMAT_V1, SkillError, valid_identifier, valid_label};
use crate::{COMMON_EVENT_V1, EventCategory};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkillName(String);

impl SkillName {
    pub fn parse(value: &str) -> Result<Self, SkillError> {
        if value.len() > 48
            || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            || value.ends_with('-')
            || value.contains("--")
            || !value
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        {
            return Err(SkillError::InvalidMetadata);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct SkillVersion(String);

impl SkillVersion {
    pub fn parse(value: &str) -> Result<Self, SkillError> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'+'))
        {
            return Err(SkillError::InvalidMetadata);
        }
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Unvalidated input. No text in this structure is safe for direct presentation.
pub struct SkillMetadataInput {
    pub format: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub author: String,
    pub license: String,
    pub target_schema: String,
    pub tools: Vec<String>,
    pub sources: Vec<String>,
    pub categories: Vec<String>,
    pub invocable: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SkillMetadata {
    name: SkillName,
    version: SkillVersion,
    description: String,
    author: String,
    license: String,
    tools: BTreeSet<String>,
    sources: BTreeSet<String>,
    categories: BTreeSet<EventCategory>,
    invocable: bool,
}

impl SkillMetadata {
    pub fn new(input: SkillMetadataInput) -> Result<Self, SkillError> {
        validate_header(&input)?;
        let categories = categories(input.categories)?;
        Ok(Self {
            name: SkillName::parse(&input.name)?,
            version: SkillVersion::parse(&input.version)?,
            description: input.description,
            author: input.author,
            license: input.license,
            tools: identifiers(input.tools)?,
            sources: identifiers(input.sources)?,
            categories,
            invocable: input.invocable,
        })
    }

    pub const fn name(&self) -> &SkillName {
        &self.name
    }
    pub const fn version(&self) -> &SkillVersion {
        &self.version
    }
    pub fn description(&self) -> &str {
        &self.description
    }
    pub fn author(&self) -> &str {
        &self.author
    }
    pub fn license(&self) -> &str {
        &self.license
    }
    pub const fn target_schema(&self) -> &'static str {
        COMMON_EVENT_V1
    }
    pub const fn tools(&self) -> &BTreeSet<String> {
        &self.tools
    }
    pub const fn sources(&self) -> &BTreeSet<String> {
        &self.sources
    }
    pub const fn categories(&self) -> &BTreeSet<EventCategory> {
        &self.categories
    }
    pub const fn invocable(&self) -> bool {
        self.invocable
    }
}

impl std::fmt::Debug for SkillMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkillMetadata")
            .field("name", &self.name)
            .field("tools", &self.tools.len())
            .field("sources", &self.sources.len())
            .finish_non_exhaustive()
    }
}

fn validate_header(input: &SkillMetadataInput) -> Result<(), SkillError> {
    if input.format != SKILL_FORMAT_V1 {
        return Err(SkillError::UnsupportedFormat);
    }
    if input.target_schema != COMMON_EVENT_V1 {
        return Err(SkillError::UnsupportedSchema);
    }
    if !matches!(
        input.license.as_str(),
        "MIT" | "Apache-2.0" | "MIT OR Apache-2.0"
    ) {
        return Err(SkillError::UnsupportedLicense);
    }
    if !valid_label(&input.description, 256)
        || !valid_label(&input.author, 128)
        || (input.sources.is_empty() && input.categories.is_empty())
    {
        return Err(SkillError::InvalidMetadata);
    }
    Ok(())
}

fn identifiers(values: Vec<String>) -> Result<BTreeSet<String>, SkillError> {
    if values.len() > 32 {
        return Err(SkillError::LimitExceeded);
    }
    let mut result = BTreeSet::new();
    for value in values {
        if !valid_identifier(&value) || !result.insert(value) {
            return Err(SkillError::InvalidMetadata);
        }
    }
    Ok(result)
}

fn categories(values: Vec<String>) -> Result<BTreeSet<EventCategory>, SkillError> {
    if values.len() > EventCategory::ALL.len() {
        return Err(SkillError::LimitExceeded);
    }
    let mut result = BTreeSet::new();
    for value in values {
        let category = EventCategory::parse(&value).map_err(|_| SkillError::InvalidMetadata)?;
        if !result.insert(category) {
            return Err(SkillError::InvalidMetadata);
        }
    }
    Ok(result)
}
