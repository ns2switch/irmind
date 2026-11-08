use super::MappingError;
use crate::{AppError, ParserTimeBasis, ParserTimeContext};
use irmind_domain::{SourceTimeBasisV1 as B, SourceTimeContextV1};

pub fn source_time_snapshot(context: &ParserTimeContext) -> Result<String, AppError> {
    Ok(domain_time_context(Some(context))?
        .ok_or_else(invalid)?
        .snapshot())
}
pub fn decode_source_time_context(
    snapshot: Option<&str>,
) -> Result<Option<ParserTimeContext>, AppError> {
    match snapshot {
        None | Some("normalized-utc") => Ok(None),
        Some(value) => {
            parser_time_context(SourceTimeContextV1::parse(value).map_err(|_| invalid())?).map(Some)
        }
    }
}
pub fn parser_time_context(context: SourceTimeContextV1) -> Result<ParserTimeContext, AppError> {
    let basis = match context.basis() {
        B::Analyst => ParserTimeBasis::Analyst,
        B::Command => ParserTimeBasis::Command,
        B::ConfirmedSuggestion => ParserTimeBasis::ConfirmedSuggestion,
    };
    ParserTimeContext::new(
        context.year(),
        context.offset_minutes(),
        context.rollover(),
        basis,
    )
    .map_err(|_| invalid())
}
pub(super) fn domain_time_context(
    context: Option<&ParserTimeContext>,
) -> Result<Option<SourceTimeContextV1>, AppError> {
    context
        .map(|c| {
            let basis = match c.basis() {
                ParserTimeBasis::Analyst => B::Analyst,
                ParserTimeBasis::Command => B::Command,
                ParserTimeBasis::ConfirmedSuggestion => B::ConfirmedSuggestion,
            };
            SourceTimeContextV1::try_new(c.year(), c.offset_minutes(), c.rollover(), basis)
                .map_err(|_| invalid())
        })
        .transpose()
}
fn invalid() -> AppError {
    MappingError::InvalidOutput.into_app()
}
