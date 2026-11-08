use super::{DetectedParser, ParserCatalog, ParserChoice};
use crate::{AppError, LogParser, ParserSelection, ParserSelectionMode, ParserTimeContext, sha256};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub struct ParserSelectionRequest<'a> {
    pub source: &'a str,
    pub sample: &'a [u8],
    pub parser_override: Option<&'a str>,
    pub forced: bool,
    pub time_context: Option<ParserTimeContext>,
}

#[derive(Clone)]
pub struct ResolvedParserSelection {
    pub selection: ParserSelection,
    pub parser: Arc<dyn LogParser>,
}

impl ParserCatalog {
    pub fn select_source(
        &self,
        request: ParserSelectionRequest<'_>,
    ) -> Result<ResolvedParserSelection, AppError> {
        let choice = self.detect(request.source, request.sample);
        let (id, confidence, mode) = choose(request, choice, self)?;
        self.ensure_available(&id)?;
        let original = self
            .experimental
            .get(&id)
            .filter(|parser| parser.detect(request.source, request.sample).is_some())
            .cloned()
            .map_or_else(|| self.get(&id), Ok)?;
        let requirement = original.time_context_requirement(request.source, request.sample)?;
        let required = requirement.as_ref().is_some_and(|value| value.required);
        if required && request.time_context.is_none() {
            return Err(AppError::ParserTimeContextRequired {
                source_name: request.source.into(),
                requirement: requirement.ok_or(AppError::ParserTimeUnsupported)?,
                suggestions: vec![],
            });
        }
        let parser = if let Some(context) = request.time_context {
            match original.with_time_context(&context) {
                Ok(parser) => parser,
                Err(AppError::ParserTimeUnsupported) if !required => original,
                Err(error) => return Err(error),
            }
        } else {
            original
        };
        if parser.identity().name != id {
            return Err(AppError::Policy(
                "configured parser changed its identity".into(),
            ));
        }
        Ok(ResolvedParserSelection {
            selection: ParserSelection {
                parser_id: id,
                parser_version: parser.identity().version.into(),
                confidence,
                mode,
                timestamp_context: parser.timestamp_context().map(str::to_owned),
                format_sample_sha256: sha256(request.sample),
            },
            parser,
        })
    }
}

fn choose(
    request: ParserSelectionRequest<'_>,
    choice: ParserChoice,
    catalog: &ParserCatalog,
) -> Result<(String, u8, ParserSelectionMode), AppError> {
    if let Some(id) = request.parser_override {
        let confidence = match &choice {
            ParserChoice::Auto(candidate) if candidate.id == id => candidate.confidence.value(),
            ParserChoice::NeedsAnalyst(candidates) => candidates
                .iter()
                .find(|candidate| candidate.id == id)
                .map_or(0, |candidate| candidate.confidence.value()),
            _ => 0,
        };
        return Ok((
            id.into(),
            confidence,
            if request.forced {
                ParserSelectionMode::Forced
            } else {
                ParserSelectionMode::Analyst
            },
        ));
    }
    match choice {
        ParserChoice::Auto(DetectedParser { id, confidence }) => {
            Ok((id, confidence.value(), ParserSelectionMode::Automatic))
        }
        ParserChoice::NeedsAnalyst(candidates) => Err(AppError::ParserSelection {
            source_name: request.source.into(),
            candidates: candidates
                .into_iter()
                .map(|c| (c.id, c.confidence.value()))
                .collect(),
        }),
        ParserChoice::Unsupported => Err(AppError::ParserSelection {
            source_name: request.source.into(),
            candidates: catalog
                .available()
                .into_iter()
                .map(|(id, _)| (id, 0))
                .collect(),
        }),
    }
}
