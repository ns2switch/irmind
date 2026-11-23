mod compact;
mod tuples;
use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter, decode_json_named_envelope_source},
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::collections::BTreeMap;
pub struct AzureFlowSourceDecoder;
pub(super) fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    if !matches!(
        fields.field("category").and_then(SourceValue::as_text),
        Some("FlowLogFlowEvent" | "NetworkSecurityGroupFlowEvent")
    ) {
        return Err(invalid());
    }
    let time = fields
        .field("time")
        .and_then(SourceValue::as_text)
        .map(|t| IndexedTime::from_rfc3339(t, false).map_err(|_| invalid()))
        .transpose()?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: time,
        format: SourceFormatV1::try_new(
            "azure-flow-container",
            "azure-flow-source-v1",
            BTreeMap::new(),
        )
        .map_err(|_| invalid())?,
    })
}
impl SourceDecoder for AzureFlowSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-azure-flow",
            version: "azure-flow-source-v1",
        }
    }
    fn compact_ordering(&self) -> Option<&dyn irmind_app::source_mapping::CompactSourceOrdering> {
        Some(self)
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.decode_with_budget(DecodeInput::Reader(input), DecodeBudget::sequential(), emit)
    }
    fn decode_with_budget(
        &self,
        input: DecodeInput<'_>,
        budget: DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let input = input.into_reader();
        let mut output = SourceFrameEmitter::new(input.metadata, self.identity());
        let containers = decode_json_named_envelope_source(
            input,
            self.identity(),
            budget,
            &["records"],
            &prepare,
            &mut |record| {
                let mut result = Ok(());
                record.inspect(|source| result = tuples::expand(source, &mut output, emit));
                result
            },
        )?;
        let mut report = output.finish();
        report.rejected += containers.rejected;
        for sample in containers.samples {
            if report.samples.len() < 3 {
                report.samples.push(sample);
            }
        }
        Ok(report)
    }
}
pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let cancel = irmind_app::CancellationToken::new();
    let mut input = std::io::Cursor::new(sample);
    let mut frames = JsonFrames::new(&mut input, &cancel)
        .with_record_array_keys(&["records"])
        .ok()?;
    let frame = frames.next_frame().ok()??;
    let fields = decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok()?;
    prepare(fields).ok().map(|_| 98)
}
