use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_source},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::collections::BTreeMap;
pub struct FalcoSourceDecoder;
impl SourceDecoder for FalcoSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-falco",
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
        decode_json_source(input, self.identity(), budget, &prepare, &mut |record| {
            let mut required = false;
            record.inspect(|source| required = is_kubernetes(source.fields()));
            match context {
                Some(context) => {
                    let identity = context
                        .resolve(None)
                        .map_err(|_| invalid_context())?
                        .clone();
                    emit(
                        record
                            .with_cluster_identity(identity)
                            .map_err(|_| invalid())?,
                    )
                }
                None if required => Err(AppError::ParserClusterContextRequired {
                    source_name: source_name.into(),
                    requirement: irmind_app::ParserClusterRequirement::try_new(true, vec![])?,
                }),
                None => emit(record),
            }
        })
    }
}
pub(super) fn is_falco(fields: &SourceValue) -> bool {
    fields
        .field("rule")
        .and_then(SourceValue::as_text)
        .is_some()
        && fields
            .field("priority")
            .and_then(SourceValue::as_text)
            .is_some()
        && matches!(fields.field("output_fields"), Some(SourceValue::Object(_)))
        && fields
            .field("time")
            .and_then(SourceValue::as_text)
            .is_some()
}
pub(super) fn is_audit_plugin(fields: &SourceValue) -> bool {
    fields.field("source").and_then(SourceValue::as_text) == Some("k8s_audit")
}
pub(super) fn is_kubernetes(fields: &SourceValue) -> bool {
    if is_audit_plugin(fields) {
        return true;
    }
    fields.field("output_fields").is_some_and(|fields| {
        [
            "k8s.ns.name",
            "k8s.pod.name",
            "k8s.pod.id",
            "k8s.node.name",
            "k8s.sa.name",
        ]
        .iter()
        .any(|key| {
            fields
                .field(key)
                .and_then(SourceValue::as_text)
                .is_some_and(|value| !matches!(value, "" | "<NA>" | "<NONE>"))
        })
    })
}
fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    if !is_falco(&fields) {
        return Err(invalid());
    }
    let time = fields
        .field("time")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let timestamp = IndexedTime::from_rfc3339(time, false).map_err(|_| invalid())?;
    let format = if is_audit_plugin(&fields) {
        "falco-kubernetes-audit"
    } else if is_kubernetes(&fields) {
        "falco-kubernetes"
    } else {
        "falco"
    };
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new(format, super::SOURCE_VERSION, BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn invalid_context() -> AppError {
    AppError::Policy("Falco Kubernetes records require an explicitly confirmed cluster identity before ingestion".into())
}
