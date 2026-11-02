use crate::{AppError, Regex, error};
use regex::RegexBuilder;
use serde::Deserialize;
use std::collections::BTreeMap;

pub(crate) const MAX_DEFINITION_BYTES: usize = 64 * 1024;
pub(crate) const MAX_RECORD_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_DEPTH: usize = 32;
pub(crate) const MAX_FIELDS: usize = 1024;
pub(crate) const MAX_RECORDS: usize = 10_000_000;
pub(crate) const SAMPLE_BYTES: usize = 64 * 1024;
const FIELDS: &[&str] = &[
    "time",
    "host",
    "user",
    "process",
    "command_line",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "action",
    "outcome",
    "account",
    "region",
];

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Format {
    Csv,
    Json,
    Ndjson,
    Regex,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Definition {
    pub version: u8,
    pub name: String,
    pub description: String,
    pub input: Input,
    pub detect: Detection,
    pub mapping: BTreeMap<String, String>,
    pub timestamp: Timestamp,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub format: Format,
    pub delimiter: Option<String>,
    #[serde(default = "yes")]
    pub header: bool,
    pub pattern: Option<String>,
}

const fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Detection {
    #[serde(default)]
    pub header: Vec<String>,
    #[serde(default)]
    pub required_fields: Vec<String>,
    pub pattern: Option<String>,
    #[serde(default = "confidence")]
    pub confidence: u8,
}

const fn confidence() -> u8 {
    70
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Timestamp {
    pub format: String,
    pub default_timezone: String,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Limits {
    pub record_bytes: usize,
    pub depth: usize,
    pub fields: usize,
    pub records: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            record_bytes: MAX_RECORD_BYTES,
            depth: MAX_DEPTH,
            fields: MAX_FIELDS,
            records: MAX_RECORDS,
        }
    }
}

impl Definition {
    pub(crate) fn decode(text: &str) -> Result<Self, AppError> {
        if text.len() > MAX_DEFINITION_BYTES {
            return Err(error("declarative definition exceeds 64 KiB"));
        }
        let definition: Self =
            toml::from_str(text).map_err(|_| error("invalid declarative TOML or unknown field"))?;
        definition.validate()?;
        Ok(definition)
    }

    fn validate(&self) -> Result<(), AppError> {
        if self.version != 1 {
            return Err(error("unsupported declarative definition version"));
        }
        if self.name.is_empty()
            || self.name.len() > 45
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(error(
                "definition name requires 1–45 lowercase letters, digits or hyphens",
            ));
        }
        if self.description.is_empty()
            || self.description.len() > 256
            || self.description.chars().any(char::is_control)
        {
            return Err(error("definition description is missing or too long"));
        }
        if !(1..=70).contains(&self.detect.confidence) {
            return Err(error("declarative confidence must be between 1 and 70"));
        }
        self.validate_mapping()?;
        self.validate_detection()?;
        self.validate_limits()
    }

    fn validate_mapping(&self) -> Result<(), AppError> {
        if !self.mapping.contains_key("time")
            || self.mapping.is_empty()
            || self.mapping.len() > FIELDS.len()
            || self.mapping.iter().any(|(field, path)| {
                !FIELDS.contains(&field.as_str()) || path.is_empty() || path.len() > 256
            })
        {
            return Err(error("invalid declarative field mapping; time is required"));
        }
        if matches!(self.input.format, Format::Json | Format::Ndjson)
            && self.mapping.values().any(|path| !valid_pointer(path))
        {
            return Err(error("JSON mappings require bounded JSON Pointer paths"));
        }
        if self.timestamp.format.is_empty()
            || self.timestamp.format.len() > 128
            || self.timestamp.default_timezone.len() > 6
        {
            return Err(error("invalid declarative timestamp configuration"));
        }
        self.delimiter()?;
        Ok(())
    }

    fn validate_detection(&self) -> Result<(), AppError> {
        let choices = usize::from(!self.detect.header.is_empty())
            + usize::from(!self.detect.required_fields.is_empty())
            + usize::from(self.detect.pattern.is_some());
        if choices != 1
            || self.detect.header.len() > MAX_FIELDS
            || self.detect.required_fields.len() > 64
            || self
                .detect
                .header
                .iter()
                .any(|name| name.is_empty() || name.len() > 256)
        {
            return Err(error("definition needs exactly one bounded detection rule"));
        }
        if !self.detect.header.is_empty()
            && (self.input.format != Format::Csv || !self.input.header)
        {
            return Err(error("header detection requires CSV with a header"));
        }
        if !self.detect.required_fields.is_empty()
            && (!matches!(self.input.format, Format::Json | Format::Ndjson)
                || self
                    .detect
                    .required_fields
                    .iter()
                    .any(|path| !valid_pointer(path)))
        {
            return Err(error(
                "required-field detection requires JSON Pointer paths",
            ));
        }
        if self.input.format == Format::Regex && self.input.pattern.is_none() {
            return Err(error("regex input requires a pattern"));
        }
        Ok(())
    }

    fn validate_limits(&self) -> Result<(), AppError> {
        let limits = &self.limits;
        if limits.record_bytes == 0
            || limits.record_bytes > MAX_RECORD_BYTES
            || limits.depth == 0
            || limits.depth > MAX_DEPTH
            || limits.fields == 0
            || limits.fields > MAX_FIELDS
            || limits.records == 0
            || limits.records > MAX_RECORDS
        {
            return Err(error("definition limits exceed fixed parser ceilings"));
        }
        Ok(())
    }

    pub(crate) fn delimiter(&self) -> Result<u8, AppError> {
        let delimiter = self.input.delimiter.as_deref().unwrap_or(",");
        if delimiter.len() != 1
            || !delimiter.is_ascii()
            || matches!(delimiter.as_bytes()[0], b'\r' | b'\n' | b'\0' | b'"')
        {
            return Err(error("CSV delimiter must be one supported ASCII character"));
        }
        Ok(delimiter.as_bytes()[0])
    }
}

fn valid_pointer(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 256
        && !path.chars().any(char::is_control)
        && path
            .split('~')
            .skip(1)
            .all(|tail| tail.starts_with('0') || tail.starts_with('1'))
}

pub(crate) fn compile_regex(pattern: Option<&str>) -> Result<Option<Regex>, AppError> {
    pattern
        .map(|pattern| {
            if pattern.is_empty() || pattern.len() > 4096 {
                return Err(error("regex pattern exceeds its size limit"));
            }
            RegexBuilder::new(pattern)
                .size_limit(1024 * 1024)
                .dfa_size_limit(1024 * 1024)
                .build()
                .map_err(|_| error("invalid or oversized linear-time regex"))
        })
        .transpose()
}
