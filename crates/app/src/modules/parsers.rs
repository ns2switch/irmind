use crate::{
    AppError, LogParser, ParserConfidence, ParserIdentity, SignedEntry, StreamingEventParser,
};
use irmind_domain::{AuditEventKind, SourceManifestV2};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Local resolution of an immutable parser version already approved in the case.
pub trait ParserResolver: Send + Sync {
    fn resolve(&self, id: &str, version: &str) -> Result<Arc<dyn LogParser>, AppError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedParser {
    pub id: String,
    pub confidence: ParserConfidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParserChoice {
    Auto(DetectedParser),
    NeedsAnalyst(Vec<DetectedParser>),
    Unsupported,
}

#[derive(Clone, Default)]
pub struct ParserCatalog {
    pub(super) parsers: BTreeMap<String, Arc<dyn LogParser>>,
    pub(super) unavailable: BTreeMap<String, String>,
    pub(super) source_selected: BTreeSet<String>,
    pub(super) resolver: Option<Arc<dyn ParserResolver>>,
}

impl ParserCatalog {
    /// Bind the detector to its sole current original-field decoder identity.
    pub fn with_source_parser(mut self, parser: Arc<dyn LogParser>) -> Result<Self, AppError> {
        let id = parser.identity().name.to_owned();
        self.ensure_available(&id)?;
        if !self.parsers.contains_key(&id) || !self.source_selected.insert(id.clone()) {
            return Err(AppError::Policy(
                "invalid or duplicate source parser registration".into(),
            ));
        }
        self.parsers.insert(id, parser);
        Ok(self)
    }

    #[must_use]
    pub fn detect(&self, source_name: &str, sample: &[u8]) -> ParserChoice {
        let sample = &sample[..sample.len().min(64 * 1024)];
        let candidates = self
            .parsers
            .iter()
            .filter_map(|(id, parser)| {
                parser
                    .detect(source_name, sample)
                    .map(|confidence| DetectedParser {
                        id: id.clone(),
                        confidence,
                    })
            })
            .collect::<Vec<_>>();
        choose_parser(candidates)
    }

    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn ParserResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn get_version(&self, id: &str, version: &str) -> Result<Arc<dyn LogParser>, AppError> {
        self.ensure_available(id)?;
        let parser = match self.get(id) {
            Ok(parser) if parser.identity().version == version => parser,
            _ => self
                .resolver
                .as_ref()
                .ok_or_else(|| AppError::Policy("signed parser version is unavailable; create a new case and re-ingest originals with the current parser".into()))?
                .resolve(id, version)?,
        };
        if parser.identity().name != id || parser.identity().version != version {
            return Err(AppError::Policy(
                "resolved parser differs from the signed identity".into(),
            ));
        }
        Ok(parser)
    }

    pub(super) fn ensure_available(&self, id: &str) -> Result<(), AppError> {
        if let Some(reason) = self.unavailable.get(id) {
            return Err(AppError::ParserUnavailable {
                parser_id: id.into(),
                reason: reason.clone(),
            });
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Arc<dyn LogParser>, AppError> {
        self.ensure_available(id)?;
        self.parsers.get(id).cloned().ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyEventParserIsNotRegistered,
        ))
    }

    #[must_use]
    pub fn available(&self) -> Vec<(String, String)> {
        self.parsers
            .iter()
            .filter(|(id, _)| !self.unavailable.contains_key(id.as_str()))
            .map(|(id, parser)| (id.clone(), parser.identity().version.to_owned()))
            .collect()
    }

    /// Rebuild with the decoder identity recorded in each current source manifest.
    pub fn rebuild_router(&self, entries: &[SignedEntry]) -> Result<RebuildParser, AppError> {
        let mut sources = BTreeMap::new();
        for entry in entries {
            let (source, id, version) = match entry.kind {
                AuditEventKind::SourceManifestV2 => {
                    let manifest = SourceManifestV2::decode(&entry.payload)
                        .map_err(|_| AppError::InvalidChain(entry.seq))?;
                    (
                        manifest.source.source,
                        manifest.parser_id,
                        manifest.parser_version,
                    )
                }
                _ => continue,
            };
            let parser = self.get_version(&id, &version)?;
            if sources.insert(source, parser).is_some() {
                return Err(AppError::InvalidChain(entry.seq));
            }
        }
        Ok(RebuildParser { sources })
    }
}

pub struct RebuildParser {
    sources: BTreeMap<String, Arc<dyn LogParser>>,
}

impl StreamingEventParser for RebuildParser {
    fn source_parallelism(&self, source: &str) -> Result<crate::SourceParallelism, AppError> {
        self.sources
            .get(source)
            .ok_or_else(|| AppError::Policy("source has no signed parser selection".into()))?
            .source_parallelism(source)
    }

    fn streaming_version(&self) -> &'static str {
        "signed-parser-router-v1"
    }
    fn parser_name(&self) -> &'static str {
        "signed-parser-router"
    }

    fn identity_for_source(&self, source: &str) -> Result<ParserIdentity<'_>, AppError> {
        self.sources
            .get(source)
            .map(|parser| parser.identity())
            .ok_or_else(|| AppError::Policy("source has no signed parser selection".into()))
    }

    fn prefers_local_file(&self, source: &str, sample: &[u8]) -> bool {
        self.sources
            .get(source)
            .is_some_and(|parser| parser.prefers_local_file(source, sample))
    }

    fn version_for_source(&self, source: &str) -> Result<&'static str, AppError> {
        self.sources
            .get(source)
            .map(|parser| parser.streaming_version())
            .ok_or(AppError::Policy(
                "source has no signed parser selection".into(),
            ))
    }
}

fn choose_parser(mut candidates: Vec<DetectedParser>) -> ParserChoice {
    candidates.sort_by(|left, right| {
        right
            .confidence
            .cmp(&left.confidence)
            .then_with(|| left.id.cmp(&right.id))
    });
    let Some(first) = candidates.first() else {
        return ParserChoice::Unsupported;
    };
    if first.confidence.is_high()
        && candidates
            .get(1)
            .is_none_or(|next| next.confidence < first.confidence)
    {
        ParserChoice::Auto(first.clone())
    } else {
        ParserChoice::NeedsAnalyst(candidates)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
