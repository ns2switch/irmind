use super::{AppError, LinuxParser, ParserTimeContext, bad};
use irmind_app::ParserTimeBasis;
impl LinuxParser {
    pub(super) fn configured(context: ParserTimeContext) -> Self {
        Self {
            context: Some(context),
            version: Some(format!(
                "linux-v1:year={};offset={};rollover={};basis={}",
                context.year(),
                context.offset_minutes(),
                u8::from(context.rollover()),
                context.basis().as_str()
            )),
            timestamp_context: Some(format!(
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
        }
    }
    pub fn from_version(version: &str) -> Result<Self, AppError> {
        use irmind_app::StreamingEventParser as _;
        if version == "linux-v1" {
            return Ok(Self::default());
        }
        if version.len() > 128 {
            return Err(invalid());
        }
        let mut parts = version
            .strip_prefix("linux-v1:year=")
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
            Some("rollover=1") => true,
            Some("rollover=0") => false,
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
        let parser = Self::configured(ParserTimeContext::new(year, offset, rollover, basis)?);
        if parser.identity().version != version {
            return Err(invalid());
        }
        Ok(parser)
    }
}
fn invalid() -> AppError {
    bad("invalid signed Linux parser version")
}

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
    fn resolve(
        &self,
        id: &str,
        version: &str,
    ) -> Result<std::sync::Arc<dyn irmind_app::LogParser>, AppError> {
        if id == "parser-linux" {
            return Ok(std::sync::Arc::new(LinuxParser::from_version(version)?));
        }
        self.fallback
            .as_ref()
            .ok_or_else(invalid)?
            .resolve(id, version)
    }
}
