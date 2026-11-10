//! Original Velociraptor fields and timestamp only; extraction is a separate mapping.
use irmind_app::{
    AppError, LogParser, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        SourceDecoderSelection, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_source, source_datetime},
    },
};
use irmind_domain::Tainted;
use std::{collections::BTreeMap, sync::Arc};
pub struct VelociraptorSourceDecoder;
impl SourceDecoder for VelociraptorSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-velociraptor",
            version: "velociraptor-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let context = input.metadata.time_context;
        decode_json_source(
            input,
            self.identity(),
            &mut |fields| decode(fields, context),
            emit,
        )
    }
}
fn decode(
    fields: SourceValue,
    context: Option<&irmind_app::ParserTimeContext>,
) -> Result<DecodedSourceFrame, AppError> {
    if first(&fields, &["Artifact", "_Source"]).is_none() {
        return Err(invalid());
    }
    let raw = first(&fields, &["Timestamp", "timestamp", "Time"]).ok_or_else(invalid)?;
    let timestamp = source_datetime(raw, context)?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new("velociraptor", "velociraptor-source-v1", BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}
fn first<'a>(fields: &'a SourceValue, paths: &[&str]) -> Option<&'a str> {
    paths.iter().find_map(|path| {
        path.split('.')
            .try_fold(fields, |v, k| v.field(k))
            .and_then(SourceValue::as_text)
    })
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
pub fn source_log_parser() -> Arc<dyn LogParser> {
    Arc::new(
        SourceDecoderSelection::new(Arc::new(VelociraptorSourceDecoder))
            .with_detector(|source, sample| super::VelociraptorParser.detect(source, sample))
            .with_time_detector(|source, sample| {
                super::VelociraptorParser.time_context_requirement(source, sample)
            }),
    )
}
