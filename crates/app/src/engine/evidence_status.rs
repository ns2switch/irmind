use crate::{AppError, AuditEventKind, CancellationToken, CaseId, Engine, RejectedSource};
use irmind_domain::SourceManifestV2;
use std::fmt::Write as _;

const DISPLAYED_FILES: usize = 50;

impl Engine<'_> {
    /// A read-only snapshot for the analyst. Content stays inside the case UI.
    pub fn case_evidence_status(
        &self,
        id: &CaseId,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let _lock = self.repo.lock_case(id)?;
        self.verify_unlocked_cancelable(id, cancel)?;
        let entries = self.audit_log.entries(id)?;
        let sources = entries
            .iter()
            .filter(|entry| entry.kind == AuditEventKind::SourceManifestV2)
            .map(|entry| {
                SourceManifestV2::decode(&entry.payload)
                    .map_err(|_| AppError::InvalidChain(entry.seq))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let failures = entries
            .iter()
            .filter(|entry| entry.origin == "system")
            .map(RejectedSource::from_audit)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let folder = crate::ingest_outcome::FileOutcomeReview::read(&entries)?;
        let local_blobs = self.evidence_store.evidence_hashes(id)?.len();
        let totals = self.graph.graph_summary(id).unwrap_or_else(|_| {
            "Indexed event count and time range unavailable; use /verify for details.".to_owned()
        });
        let mut report = format!(
            "Case evidence\nSources: {} · Local evidence blobs: {local_blobs} · Decoder rejections: {}\n{totals}\nFolder outcomes: {}",
            sources.len(),
            failures.len(),
            folder.summary()
        );
        for manifest in sources.iter().take(DISPLAYED_FILES) {
            let name = self.guard.screen(&manifest.source.source)?.text;
            let name = visible_source(&name);
            let _ = write!(
                report,
                "\n{} · {} bytes · SHA-256 {} · {}",
                name,
                manifest.source.size,
                manifest.source.sha256.as_str(),
                manifest.parser_id
            );
        }
        for failed in failures.iter().take(DISPLAYED_FILES) {
            let name = self.guard.screen(failed.source())?.text;
            let name = visible_source(&name);
            let _ = write!(
                report,
                "\nFailed {name} · {}",
                failed.reason().description()
            );
        }
        for notice in folder.limitations.iter().take(DISPLAYED_FILES) {
            let (path, reason) = notice.description();
            let path = visible_source(&self.guard.screen(path)?.text);
            let fingerprint = notice.fingerprint_display();
            let _ = write!(
                report,
                "\n{path} · {reason} · {fingerprint} · audit #{}",
                notice.sequence
            );
        }
        if sources.len() > DISPLAYED_FILES
            || failures.len() > DISPLAYED_FILES
            || folder.limitations.len() > DISPLAYED_FILES
        {
            let _ = write!(
                report,
                "\nShowing up to {DISPLAYED_FILES} entries per list. Totals include every authenticated entry."
            );
        }
        Ok(report)
    }
}

fn visible_source(value: &str) -> String {
    let mut safe = String::new();
    for ch in value.chars() {
        if ch.is_control()
            || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        {
            safe.extend(ch.escape_default());
        } else {
            safe.push(ch);
        }
    }
    safe
}
