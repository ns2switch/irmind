use crate::{AppError, AuthorizedCall, CancellationToken, Engine};
use irmind_domain::EvidenceHash;

impl Engine<'_> {
    pub(super) fn execute_raw_record_tool(
        &self,
        call: &AuthorizedCall,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        let hash = call
            .arg("hash")
            .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingHash))?;
        let index = call
            .arg("index")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n < 100_000)
            .ok_or(AppError::Fixed(crate::FixedAppError::PolicyMissingIndex))?;
        match call.arg("view").unwrap_or("indexed") {
            "indexed" => Ok(format!(
                "view=indexed {}",
                self.graph.raw_record(call.case_id(), hash, index)?
            )
            .into_bytes()),
            "original" => {
                let source = EvidenceHash::parse(&hash.to_ascii_lowercase())
                    .map_err(|_| AppError::Policy("invalid original source hash".into()))?;
                let reader = self.source_evidence_reader.as_ref().ok_or_else(|| AppError::Policy(
                    "Original record reading is unavailable; the indexed projection is not the original".into()))?;
                let record =
                    reader.read_verified_record(call.case_id(), &source, index as u64, cancel)?;
                let mut fields = Err(AppError::Policy("invalid original source fields".into()));
                record.inspect(|r| {
                    fields = crate::source_mapping::json::render_source_fields(r.fields())
                        .map_err(|_| AppError::Policy("invalid original source fields".into()));
                });
                let fields = fields?;
                let excerpt: String = fields.chars().take(2_000).collect();
                let suffix = if excerpt.len() < fields.len() {
                    " [truncated]"
                } else {
                    ""
                };
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                Ok(format!(
                    "view=original verified source={}#{index} {excerpt}{suffix}",
                    source.as_str()
                )
                .into_bytes())
            }
            _ => Err(AppError::Policy(
                "raw_records view must be indexed or original".into(),
            )),
        }
    }
}
