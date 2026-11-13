use crate::{AppError, ParserTimeBasis, ParserTimeContext};

#[derive(Clone, Debug, Default)]
pub struct IngestOptions {
    pub path: String,
    pub copy_original: bool,
    pub parser: Option<String>,
    pub time_context: Option<ParserTimeContext>,
    pub cluster_context: Option<crate::SourceClusterContext>,
}

impl IngestOptions {
    pub fn parse(command: &str) -> Result<Self, AppError> {
        let mut rest = command.trim();
        let mut options = Self::default();
        let (mut year, mut offset, mut rollover) = (None, None, true);
        while rest.starts_with("--") {
            let (token, tail) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
            rest = tail.trim_start();
            match token {
                "--" => break,
                "--copy-original" => options.copy_original = true,
                "--no-year-rollover" => rollover = false,
                _ => {
                    let (name, value) = if let Some(pair) = token.split_once('=') {
                        pair
                    } else {
                        let (value, tail) =
                            rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
                        rest = tail.trim_start();
                        (token, value)
                    };
                    if value.is_empty() {
                        return Err(invalid());
                    }
                    match name {
                        "--parser" => options.parser = Some(value.to_owned()),
                        "--cluster" if options.cluster_context.is_none() => {
                            options.cluster_context = command_cluster_context(Some(value))?;
                        }
                        "--year" => year = Some(value),
                        "--utc-offset" => offset = Some(value),
                        _ => return Err(invalid()),
                    }
                }
            }
        }
        options.time_context = command_time_context(year, offset, rollover)?;
        rest.trim().clone_into(&mut options.path);
        if options.path.is_empty() || options.path.len() > 4096 {
            return Err(invalid());
        }
        Ok(options)
    }
}

pub fn command_time_context(
    year: Option<&str>,
    offset: Option<&str>,
    rollover: bool,
) -> Result<Option<ParserTimeContext>, AppError> {
    match (year, offset) {
        (None, None) if rollover => Ok(None),
        (Some(year), Some(offset)) => ParserTimeContext::from_fields(year, offset, rollover, ParserTimeBasis::Command).map(Some),
        _ => Err(AppError::Policy("supply both --year YYYY and --utc-offset +HH:MM, or confirm the temporal context in the TUI".into())),
    }
}

pub fn command_cluster_context(
    value: Option<&str>,
) -> Result<Option<crate::SourceClusterContext>, AppError> {
    value
        .map(|value| {
            let identity =
                crate::ClusterIdentity::parse_qualified(value).map_err(|_| invalid_cluster())?;
            let binding = irmind_domain::SourceClusterBinding::try_new(
                identity,
                irmind_domain::ClusterContextBasis::Command,
                None,
            )
            .map_err(|_| invalid_cluster())?;
            crate::SourceClusterContext::try_new(vec![binding]).map_err(|_| invalid_cluster())
        })
        .transpose()
}
fn invalid_cluster() -> AppError {
    AppError::Policy("use --cluster PROVIDER:QUALIFIED_ID, for example kubernetes:urn:k8s:team-a; cluster identity must be explicitly supplied or confirmed in the TUI".into())
}

fn invalid() -> AppError {
    AppError::Policy("use /ingest [--parser NAME] [--cluster PROVIDER:QUALIFIED_ID] [--copy-original] [--year YYYY --utc-offset +HH:MM] [--no-year-rollover] PATH".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn command_cluster_binding_is_typed_and_never_silently_replaced() {
        let parsed =
            IngestOptions::parse("--cluster kubernetes:urn:k8s:team-a source.ndjson").unwrap();
        let context = parsed.cluster_context.unwrap();
        assert_eq!(
            context.bindings()[0].basis(),
            irmind_domain::ClusterContextBasis::Command
        );
        assert_eq!(
            context.bindings()[0].identity().qualified(),
            "kubernetes:urn:k8s:team-a"
        );
        assert!(IngestOptions::parse("--cluster ../bad source.ndjson").is_err());
        assert!(
            IngestOptions::parse(
                "--cluster kubernetes:urn:a --cluster kubernetes:urn:b source.ndjson"
            )
            .is_err()
        );
        assert!(command_cluster_context(None).unwrap().is_none());
    }
    #[test]
    fn command_context_is_shared_and_preserves_paths_with_spaces() {
        let parsed = IngestOptions::parse("--year 2026 --utc-offset -03:30 --parser parser-syslog --copy-original folder with spaces/source.log").unwrap();
        assert_eq!(parsed.path, "folder with spaces/source.log");
        assert_eq!(
            parsed.time_context.unwrap().basis(),
            ParserTimeBasis::Command
        );
        assert_eq!(parsed.time_context.unwrap().offset_minutes(), -210);
        assert!(parsed.copy_original);
        assert!(IngestOptions::parse("--year 2026 file.log").is_err());
        assert!(
            !IngestOptions::parse("--year=2026 --utc-offset=+00:00 --no-year-rollover x.log")
                .unwrap()
                .time_context
                .unwrap()
                .rollover()
        );
    }
}
