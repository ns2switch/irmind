use crate::{
    AppError, CancellationToken, CaseId, Engine, ParserTimeRequirement, ParserTimeSuggestion,
    SourceManifestV2, modules::ParserCatalog,
};
use irmind_domain::{AuditEventKind, EvidenceHash};
use std::collections::{BTreeMap, BTreeSet};

impl Engine<'_> {
    pub fn annotate_parser_time_error(
        &self,
        id: &CaseId,
        error: AppError,
        catalog: &ParserCatalog,
        cancel: &CancellationToken,
        suggest: bool,
    ) -> AppError {
        let AppError::ParserTimeContextRequired {
            source_name,
            requirement,
            ..
        } = error
        else {
            return error;
        };
        let prepare = || {
            self.record_parser_selection_required(id, "missing-time-context")?;
            if suggest {
                self.parser_time_suggestions(id, &requirement, catalog, cancel)
            } else {
                Ok(Vec::new())
            }
        };
        match prepare() {
            Ok(suggestions) => AppError::ParserTimeContextRequired {
                source_name,
                requirement,
                suggestions,
            },
            Err(error) => error,
        }
    }

    pub fn parser_time_suggestions(
        &self,
        id: &CaseId,
        requirement: &ParserTimeRequirement,
        catalog: &ParserCatalog,
        cancel: &CancellationToken,
    ) -> Result<Vec<ParserTimeSuggestion>, AppError> {
        let _lock = self.repo.lock_case(id)?;
        self.verify_ingest_checkpoint(id, cancel)?;
        let sources = self
            .audit_log
            .entries(id)?
            .into_iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceManifestV2)
            .map(|entry| {
                SourceManifestV2::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|source| (source.source.sha256.as_str().to_owned(), source))
            .collect::<BTreeMap<_, _>>();
        let mut suggestions = Vec::new();
        let mut seen = BTreeSet::new();
        for host in requirement.hosts.iter().take(4) {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            // Presentation text supplies untrusted candidates only. Each pointer,
            // signed source, actual raw record and logged host is revalidated below.
            let mut candidates = Ok(String::new());
            host.inspect(|value| {
                candidates = self.graph.entity_timeline(id, "host", value, 20);
            });
            let candidates = candidates?;
            for (hash, index) in candidate_refs(&candidates) {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                let Some(source) = sources.get(&hash) else {
                    continue;
                };
                let Ok(parser) = catalog.get_version(&source.parser_id, &source.parser_version)
                else {
                    continue;
                };
                let raw = self.graph.raw_record(id, &hash, index)?;
                let prefix = format!("source={hash}#{index} ");
                let Some(body) = raw
                    .strip_prefix(&prefix)
                    .filter(|raw| !raw.ends_with(" [truncated]"))
                else {
                    continue;
                };
                let Some(info) =
                    parser.time_context_requirement(&source.source.source, body.as_bytes())?
                else {
                    continue;
                };
                let mut same_host = false;
                for known in &info.hosts {
                    known.inspect(|known| {
                        host.inspect(|wanted| {
                            same_host |= known == wanted;
                        });
                    });
                }
                if !same_host {
                    continue;
                }
                if let Some(context) = info.observed {
                    if seen.insert((context.year(), context.offset_minutes())) {
                        suggestions.push(ParserTimeSuggestion {
                            context,
                            source_hash: hash.clone(),
                            record_index: index,
                            host: host.clone(),
                        });
                    }
                    break;
                }
            }
        }
        Ok(suggestions)
    }
}

fn candidate_refs(text: &str) -> Vec<(String, usize)> {
    text.lines()
        .filter_map(|line| {
            let (_, pointer) = line.rsplit_once("source=")?;
            let (hash, index) = pointer.split_once('#')?;
            let hash = EvidenceHash::parse(hash).ok()?;
            Some((hash.as_str().into(), index.parse().ok()?))
        })
        .take(20)
        .collect()
}
