use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_source},
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
        let cluster = input
            .metadata
            .cluster_context
            .ok_or(AppError::ParserClusterContextRequired {
                source_name: input.metadata.source.reference().into(),
                requirement: irmind_app::ParserClusterRequirement::try_new(true, vec![])?,
            })?
            .resolve(None)
            .map_err(|_| {
                AppError::Policy(
                    "Native audit events require an explicit analyst or command cluster binding"
                        .into(),
                )
            })?
            .clone();
        decode_json_source(input, self.identity(), budget, &prepare, &mut |record| {
            emit(
                record
                    .with_cluster_identity(cluster.clone())
                    .map_err(|_| invalid())?,
            )
        })
    }
}
pub(super) fn is_native(fields: &SourceValue) -> bool {
    fields.field("apiVersion").and_then(SourceValue::as_text) == Some("audit.k8s.io/v1")
        && fields.field("kind").and_then(SourceValue::as_text) == Some("Event")
}
fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
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
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
