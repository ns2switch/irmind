use super::{AppError, LegacyTimestamp, SyslogParser, invalid};
use irmind_app::{ParserTimeBasis, ParserTimeContext};

impl SyslogParser {
    /// Historical fixed-year interpretation, retained for signed v1 cases.
    #[must_use]
    pub fn new(legacy: Option<LegacyTimestamp>) -> Self {
        let context = legacy.map(|value| {
            format!(
                "rfc3164;year={};offset_minutes={};basis=analyst;inferred=true",
                value.year(),
                value.offset_minutes()
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
            per_ingest: false,
            time_context: None,
        }
    }

    pub(super) fn configured(context: ParserTimeContext) -> Result<Self, AppError> {
        Ok(Self {
            legacy: Some(LegacyTimestamp::new(
                i32::from(context.year()),
                i32::from(context.offset_minutes()),
            )?),
            context: Some(format!(
                "rfc3164;first_year={};offset_minutes={};rollover={};basis={};inferred=true",
                context.year(),
                context.offset_minutes(),
                if context.rollover() {
                    "december-january"
                } else {
                    "disabled"
                },
                context.basis().as_str()
            )),
            version: format!(
                "syslog-v2:year={};offset={};rollover={};basis={}",
                context.year(),
                context.offset_minutes(),
                u8::from(context.rollover()),
                context.basis().as_str()
            ),
            per_ingest: true,
            time_context: Some(context),
        })
    }

    pub fn from_version(version: &str) -> Result<Self, AppError> {
        if version.len() > 128 {
            return Err(invalid());
        }
        if version == "syslog-v1" {
            return Ok(Self::new(None));
        }
        if version == "syslog-v2" {
            return Ok(Self::default());
        }
        let parser = if let Some(rest) = version.strip_prefix("syslog-v1:year=") {
            let (year, offset) = rest.split_once(";offset=").ok_or_else(invalid)?;
            Self::new(Some(LegacyTimestamp::new(
                year.parse().map_err(|_| invalid())?,
                offset.parse().map_err(|_| invalid())?,
            )?))
        } else {
            let mut parts = version
                .strip_prefix("syslog-v2:year=")
                .ok_or_else(invalid)?
                .split(';');
            let year = parts
                .next()
                .ok_or_else(invalid)?
                .parse()
                .map_err(|_| invalid())?;
            let offset = parts
                .next()
                .and_then(|s| s.strip_prefix("offset="))
                .ok_or_else(invalid)?
                .parse()
                .map_err(|_| invalid())?;
            let rollover = match parts.next() {
                Some("rollover=0") => false,
                Some("rollover=1") => true,
                _ => return Err(invalid()),
            };
            let basis = ParserTimeBasis::parse(
                parts
                    .next()
                    .and_then(|s| s.strip_prefix("basis="))
                    .ok_or_else(invalid)?,
            )?;
            if parts.next().is_some() {
                return Err(invalid());
            }
            Self::configured(ParserTimeContext::new(year, offset, rollover, basis)?)?
        };
        if parser.version != version {
            return Err(invalid());
        }
        Ok(parser)
    }
}

impl Default for SyslogParser {
    fn default() -> Self {
        Self {
            legacy: None,
            context: None,
            version: "syslog-v2".into(),
            per_ingest: true,
            time_context: None,
        }
    }
}
