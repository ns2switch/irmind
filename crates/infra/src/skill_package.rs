//! Pure decoding of bounded package bytes. This module installs and executes nothing.

use irmind_domain::{
    MAX_SKILL_HEADER_BYTES, SkillError, SkillMetadata, SkillMetadataInput, SkillPackage,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    format: String,
    name: String,
    description: String,
    version: String,
    author: String,
    license: String,
    target_schema: String,
    tools: Vec<String>,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    categories: Vec<String>,
    invocable: bool,
}

/// Parsed, still-untrusted bytes. It carries no installation or execution authority.
pub struct DecodedSkillPackage {
    metadata: SkillMetadata,
    package: SkillPackage,
    body_offset: usize,
}

impl DecodedSkillPackage {
    pub const fn metadata(&self) -> &SkillMetadata {
        &self.metadata
    }

    pub const fn package(&self) -> &SkillPackage {
        &self.package
    }

    /// Byte offset of the original Markdown body, for later skill-resource provenance.
    pub const fn body_offset(&self) -> usize {
        self.body_offset
    }
}

impl std::fmt::Debug for DecodedSkillPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecodedSkillPackage")
            .field("metadata", &self.metadata)
            .field("package", &self.package)
            .finish_non_exhaustive()
    }
}

pub fn decode_skill_package(package: SkillPackage) -> Result<DecodedSkillPackage, SkillError> {
    let document = package
        .resources()
        .values()
        .find(|resource| resource.path().as_str() == "SKILL.md")
        .ok_or(SkillError::MissingMethodology)?
        .untrusted_text();
    let (header, body_offset) = frontmatter(document)?;
    let metadata: Metadata = toml::from_str(header).map_err(|_| SkillError::InvalidFrontmatter)?;
    let metadata = convert_metadata(metadata)?;
    let tools = irmind_app::tool_catalog::catalog();
    for tool in metadata.tools() {
        if !tools.iter().any(|known| known.name == tool) {
            return Err(SkillError::UnknownTool);
        }
    }
    check_fences(&document[body_offset..])?;
    for resource in package.resources().values() {
        if resource.path().as_str() != "SKILL.md" {
            validate_resource(resource.path().as_str(), resource.untrusted_text())?;
        }
    }
    Ok(DecodedSkillPackage {
        metadata,
        package,
        body_offset,
    })
}

fn frontmatter(document: &str) -> Result<(&str, usize), SkillError> {
    let first = document.find('\n').ok_or(SkillError::InvalidFrontmatter)?;
    if document[..first].trim_end_matches('\r') != "+++" {
        return Err(SkillError::InvalidFrontmatter);
    }
    let start = first + 1;
    let mut offset = start;
    for line in document[start..].split_inclusive('\n') {
        let line_end = offset + line.len();
        if line.trim_end_matches(['\r', '\n']) == "+++" {
            if offset - start > MAX_SKILL_HEADER_BYTES {
                return Err(SkillError::LimitExceeded);
            }
            if document[line_end..].trim().is_empty() {
                return Err(SkillError::MissingMethodology);
            }
            return Ok((&document[start..offset], line_end));
        }
        offset = line_end;
        if offset - start > MAX_SKILL_HEADER_BYTES {
            return Err(SkillError::LimitExceeded);
        }
    }
    Err(SkillError::InvalidFrontmatter)
}

fn convert_metadata(metadata: Metadata) -> Result<SkillMetadata, SkillError> {
    SkillMetadata::new(SkillMetadataInput {
        format: metadata.format,
        name: metadata.name,
        description: metadata.description,
        version: metadata.version,
        author: metadata.author,
        license: metadata.license,
        target_schema: metadata.target_schema,
        tools: metadata.tools,
        sources: metadata.sources,
        categories: metadata.categories,
        invocable: metadata.invocable,
    })
}

fn check_fences(markdown: &str) -> Result<(), SkillError> {
    let mut open: Option<(&str, usize)> = None;
    for line in markdown.lines() {
        let line = line.trim_start();
        let Some(marker) = ["`", "~"]
            .into_iter()
            .find(|marker| line.starts_with(marker))
        else {
            continue;
        };
        let count = line
            .bytes()
            .take_while(|byte| *byte == marker.as_bytes()[0])
            .count();
        if count < 3 {
            continue;
        }
        let tail = line[count..].trim();
        if let Some((current, length)) = open {
            if marker == current && count >= length && tail.is_empty() {
                open = None;
            }
        } else if matches!(
            tail,
            "" | "json" | "jsonl" | "toml" | "csv" | "yaml" | "yml" | "text" | "markdown" | "md"
        ) {
            open = Some((marker, count));
        } else {
            return Err(SkillError::UnsupportedResource);
        }
    }
    if open.is_some() {
        Err(SkillError::UnsupportedResource)
    } else {
        Ok(())
    }
}

fn validate_resource(path: &str, text: &str) -> Result<(), SkillError> {
    match path.rsplit_once('.').map(|(_, suffix)| suffix) {
        Some("md") => check_fences(text),
        Some("json") => serde_json::from_str::<serde_json::Value>(text)
            .map(|_| ())
            .map_err(|_| SkillError::UnsupportedResource),
        Some("toml") => toml::from_str::<toml::Value>(text)
            .map(|_| ())
            .map_err(|_| SkillError::UnsupportedResource),
        // CSV references and reference-only YAML rules are never interpreted here.
        Some("csv" | "yaml" | "yml") => Ok(()),
        _ => Err(SkillError::UnsupportedResource),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
