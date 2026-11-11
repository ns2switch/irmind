use super::{
    AppError, AuditEventKind, LargeCaseUseCases, ParserSelection, SourceManifestV2,
    invalid_manifest,
};
impl LargeCaseUseCases<'_, '_> {
    pub(super) fn source_event(
        &self,
        prepared: &crate::MappedSourceAcquisition,
        selection: Option<&ParserSelection>,
    ) -> Result<(AuditEventKind, String), AppError> {
        let identity = self.parser.identity_for_source(&prepared.manifest.source)?;
        let configured;
        let selection = if let Some(selection) = selection {
            selection
        } else {
            // A directly configured parser has no detector confidence. Record
            // its actual identity instead of the historical implicit JSON v2.
            configured = ParserSelection {
                parser_id: identity.name.into(),
                parser_version: identity.version.into(),
                confidence: 0,
                mode: irmind_domain::ParserSelectionMode::Analyst,
                timestamp_context: self.parser.timestamp_context().map(str::to_owned),
                format_sample_sha256: prepared.format_sample_sha256,
            };
            &configured
        };
        if selection.parser_version != identity.version
            || selection.parser_id != identity.name
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
            rejected_records: prepared.report.rejected,
            rejected_sample: prepared.report.samples.clone(),
        };
        Ok((
            AuditEventKind::SourceManifestV2,
            manifest.encode().map_err(|_| invalid_manifest())?,
        ))
    }
}
