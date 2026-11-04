use super::{
    AppError, AuditEventKind, LargeCaseUseCases, ParserSelection, SourceManifestV2,
    invalid_manifest,
};
impl LargeCaseUseCases<'_, '_> {
    pub(super) fn source_event(
        &self,
        prepared: &crate::PreparedSource,
        selection: Option<&ParserSelection>,
    ) -> Result<(AuditEventKind, String), AppError> {
        Ok(match selection {
            Some(selection) => {
                if selection.parser_version != self.parser.identity().version
                    || selection.parser_id != self.parser.identity().name
                    || selection.format_sample_sha256 != prepared.format_sample_sha256
                {
                    return Err(invalid_manifest());
                }
                let manifest = SourceManifestV2 {
                    source: prepared.manifest.clone(),
                    parser_id: selection.parser_id.clone(),
                    parser_version: selection.parser_version.clone(),
                    confidence: selection.confidence,
                    selection: selection.mode,
                    timestamp_context: Some(
                        selection
                            .timestamp_context
                            .clone()
                            .unwrap_or_else(|| "normalized-utc".into()),
                    ),
                    rejected_records: prepared.parse_report.rejected,
                    rejected_sample: prepared.parse_report.samples.clone(),
                };
                (
                    AuditEventKind::SourceManifestV2,
                    manifest.encode().map_err(|_| invalid_manifest())?,
                )
            }
            None => (
                AuditEventKind::SourceManifestV1,
                prepared.manifest.encode().map_err(|_| invalid_manifest())?,
            ),
        })
    }
}
