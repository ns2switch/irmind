use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_envelope_source},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::collections::BTreeMap;

pub struct KubernetesSourceDecoder;
impl SourceDecoder for KubernetesSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-kubernetes",
            version: super::SOURCE_VERSION,
        }
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
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let context = input.metadata.cluster_context;
        let source_name = input.metadata.source.reference();
        decode_json_envelope_source(
            input,
            self.identity(),
            budget,
            &super::managed::prepare,
            &mut |record| {
                let Some(context) = context else {
                    return Err(AppError::ParserClusterContextRequired {
                        source_name: source_name.into(),
                        requirement: irmind_app::ParserClusterRequirement::try_new(true, vec![])?,
                    });
                };
                let mut identity = None;
                record.inspect(|source| {
                    identity = Some(
                        super::managed::resolve(
                            context,
                            source.fields(),
                            source.format().id(),
                            source_name,
                        )
                        .cloned(),
                    );
                });
                let identity = identity.ok_or_else(invalid)??;
                emit(
                    record
                        .with_cluster_identity(identity)
                        .map_err(|_| invalid())?,
                )
            },
        )
    }
}
pub(super) fn is_native(fields: &SourceValue) -> bool {
    fields.field("apiVersion").and_then(SourceValue::as_text) == Some("audit.k8s.io/v1")
        && fields.field("kind").and_then(SourceValue::as_text) == Some("Event")
}
pub(super) fn prepare_native(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    if !is_native(&fields)
        || fields
            .field("auditID")
            .and_then(SourceValue::as_text)
            .is_none_or(str::is_empty)
        || fields
            .field("verb")
            .and_then(SourceValue::as_text)
            .is_none_or(str::is_empty)
        || !matches!(
            fields.field("stage").and_then(SourceValue::as_text),
            Some("RequestReceived" | "ResponseStarted" | "ResponseComplete" | "Panic")
        )
    {
        return Err(invalid());
    }
    let time = fields
        .field("stageTimestamp")
        .or_else(|| fields.field("requestReceivedTimestamp"))
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let timestamp = IndexedTime::from_rfc3339(time, false).map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new("kubernetes-audit", super::SOURCE_VERSION, BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}
pub(super) fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
