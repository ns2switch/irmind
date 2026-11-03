#![forbid(unsafe_code)]

use irmind_app::{
    AppError, CancellationToken, EventParser, GraphRecord, LogParser, ParseReport,
    ParserConfidence, ParserIdentity, StreamingEventParser,
    modules::{ConfigField, Module, ModuleConfig, ModuleManifest, ModulePort, ModuleRegistry},
};
use irmind_domain::Tainted;
use std::io::{Cursor, Read};

mod gzip;
mod input;
mod record;
mod timestamp;
pub use timestamp::LegacyTimestamp;

pub struct SyslogParser {
    legacy: Option<LegacyTimestamp>,
    context: Option<String>,
    version: String,
}

impl SyslogParser {
    #[must_use]
    pub fn new(legacy: Option<LegacyTimestamp>) -> Self {
        let context = legacy.map(|value| {
            format!(
                "rfc3164;year={};offset_minutes={};basis=analyst;inferred=true",
                value.year(),
                value.offset_minutes(),
            )
        });
        let version = legacy.map_or_else(
            || "syslog-v1".into(),
            |value| {
                format!(
                    "syslog-v1:year={};offset={}",
                    value.year(),
                    value.offset_minutes()
                )
            },
        );
        Self {
            legacy,
            context,
            version,
        }
    }

    pub fn from_version(version: &str) -> Result<Self, AppError> {
        if version.len() > 128 {
            return Err(invalid());
        }
        if version == "syslog-v1" {
            return Ok(Self::new(None));
        }
        let (year, offset) = version
            .strip_prefix("syslog-v1:year=")
            .and_then(|value| value.split_once(";offset="))
            .ok_or_else(invalid)?;
        let parser = Self::new(Some(LegacyTimestamp::new(
            year.parse().map_err(|_| invalid())?,
            offset.parse().map_err(|_| invalid())?,
        )?));
        if parser.version != version {
            return Err(invalid());
        }
        Ok(parser)
    }
}

impl Default for SyslogParser {
    fn default() -> Self {
        Self::new(None)
    }
}

pub static MANIFEST: ModuleManifest = ModuleManifest {
    id: "parser-syslog",
    version: "0.1.0",
    ports: &[ModulePort::EventParser],
    tools: &[],
    config: &[
        ConfigField {
            name: "LEGACY_YEAR",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "LEGACY_UTC_OFFSET_MINUTES",
            required: false,
            secret: false,
        },
    ],
};

impl Module for SyslogParser {
    fn manifest(&self) -> &'static ModuleManifest {
        &MANIFEST
    }
    fn register(
        self: Box<Self>,
        registry: &mut ModuleRegistry,
        config: &ModuleConfig,
    ) -> Result<(), AppError> {
        let context = match (
            config.value("LEGACY_YEAR"),
            config.value("LEGACY_UTC_OFFSET_MINUTES"),
        ) {
            (None, None) => self.legacy,
            (Some(year), Some(offset)) => Some(LegacyTimestamp::new(
                year.parse().map_err(|_| invalid())?,
                offset.parse().map_err(|_| invalid())?,
            )?),
            _ => return Err(invalid()),
        };
        registry.add_parser(Box::new(Self::new(context)))
    }
}

impl LogParser for SyslogParser {
    fn detect(&self, _source_name: &str, sample: &[u8]) -> Option<ParserConfidence> {
        let sample = &sample[..sample.len().min(64 * 1024)];
        let expanded;
        let sample = if sample.starts_with(&[0x1f, 0x8b]) {
            expanded = gzip::sample(sample);
            &expanded[..]
        } else {
            sample
        };
        let first = sample.split(|byte| *byte == b'\n').next()?;
        let text = std::str::from_utf8(first).ok()?.trim_end_matches('\r');
        record::detect(text).and_then(|score| ParserConfidence::new(score).ok())
    }
}

impl EventParser for SyslogParser {
    fn version(&self) -> &'static str {
        "syslog-v1"
    }
    fn parse_each(
        &self,
        source: &str,
        bytes: &[u8],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        if bytes.len() > 50 * 1024 * 1024 {
            return Err(limit());
        }
        self.parse_reader(
            source,
            &mut Cursor::new(bytes),
            irmind_app::sha256(bytes),
            cancel,
            emit,
        )
    }
}

impl StreamingEventParser for SyslogParser {
    fn parser_name(&self) -> &'static str {
        "parser-syslog"
    }
    fn streaming_version(&self) -> &'static str {
        "syslog-v1"
    }
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: self.parser_name(),
            version: &self.version,
        }
    }
    fn identity_for_source(&self, _source: &str) -> Result<ParserIdentity<'_>, AppError> {
        Ok(self.identity())
    }
    fn timestamp_context(&self) -> Option<&str> {
        self.context.as_deref()
    }
    fn parse_reader(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<usize, AppError> {
        Ok(self
            .parse_reader_report(source, reader, hash, cancel, emit)?
            .accepted)
    }
    fn parse_reader_report(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        gzip::parse(self, source, reader, hash, cancel, emit)
    }
}

fn invalid() -> AppError {
    AppError::Policy("RFC 3164 requires a valid explicit year and UTC offset".into())
}
fn limit() -> AppError {
    AppError::Policy("syslog source exceeds size or record limits".into())
}

#[cfg(test)]
mod tests;

/// Reconstructs only canonical, signed syslog versions; other modules stay in
/// the resolver supplied by the composition root.
pub struct HistoricalResolver {
    fallback: Option<std::sync::Arc<dyn irmind_app::modules::ParserResolver>>,
}
impl HistoricalResolver {
    #[must_use]
    pub fn new(fallback: Option<std::sync::Arc<dyn irmind_app::modules::ParserResolver>>) -> Self {
        Self { fallback }
    }
}
impl irmind_app::modules::ParserResolver for HistoricalResolver {
    fn resolve(&self, id: &str, version: &str) -> Result<std::sync::Arc<dyn LogParser>, AppError> {
        if id == "parser-syslog" {
            return Ok(std::sync::Arc::new(SyslogParser::from_version(version)?));
        }
        self.fallback
            .as_ref()
            .ok_or_else(invalid)?
            .resolve(id, version)
    }
}

#[cfg(test)]
mod year_rollover;
