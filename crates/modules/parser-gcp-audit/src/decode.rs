use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, decode_json_source},
    },
};
use irmind_domain::{ClusterIdentity, ClusterProvider, IndexedTime, Tainted};
use std::collections::BTreeMap;
pub struct GcpAuditSourceDecoder;
impl SourceDecoder for GcpAuditSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-gcp-audit",
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
            let mut requirement = None;
            record.inspect(|source| {
                if is_gke(source.fields()) {
                    requirement = Some(gke_claim(source.fields()));
                }
            });
            if let Some(claim) = requirement {
                let claim = claim?;
                let Some(context) = context else {
                    return Err(AppError::ParserClusterContextRequired {
                        source_name: source_name.into(),
                        requirement: irmind_app::ParserClusterRequirement::try_new(
                            true,
                            claim.clone().into_iter().collect(),
                        )?,
                    });
                };
                let cluster = resolve_context(context, claim.as_ref(), source_name)?;
                if cluster.provider() != ClusterProvider::Gke {
                    return Err(invalid_context());
                }
                let mut compatible = false;
                record.inspect(|source| compatible = consistent_labels(source.fields(), cluster));
                if !compatible {
                    return Err(invalid_context());
                }
                emit(
                    record
                        .with_cluster_identity(cluster.clone())
                        .map_err(|_| invalid())?,
                )
            } else {
                if context.is_some() {
                    return Err(AppError::Policy("Export GKE cluster records separately from other Cloud Audit resource types; cluster context cannot relabel a non-cluster record".into()));
                }
                emit(record)
            }
        })
    }
}
pub(super) fn is_audit(fields: &SourceValue) -> bool {
    let Some(payload) = fields.field("protoPayload") else {
        return false;
    };
    if payload
        .field("@type")
        .and_then(SourceValue::as_text)
        .is_some_and(|t| t != "type.googleapis.com/google.cloud.audit.AuditLog")
    {
        return false;
    }
    ["methodName", "serviceName"].iter().all(|k| {
        payload
            .field(k)
            .and_then(SourceValue::as_text)
            .is_some_and(|s| !s.is_empty())
    }) && fields
        .field("timestamp")
        .and_then(SourceValue::as_text)
        .is_some()
}
pub(super) fn is_gke(fields: &SourceValue) -> bool {
    fields
        .field("resource")
        .and_then(|r| r.field("type"))
        .and_then(SourceValue::as_text)
        == Some("k8s_cluster")
}
fn labels(fields: &SourceValue) -> Option<&SourceValue> {
    fields.field("resource")?.field("labels")
}
pub(super) fn gke_claim(fields: &SourceValue) -> Result<Option<ClusterIdentity>, AppError> {
    let labels = labels(fields).ok_or_else(invalid)?;
    let mut values = Vec::new();
    for key in ["project_id", "location", "cluster_name"] {
        match labels.field(key) {
            None => values.push(None),
            Some(SourceValue::Text(value)) if valid_segment(value) => {
                values.push(Some(value.as_str()));
            }
            _ => return Err(invalid()),
        }
    }
    let values: Option<Vec<_>> = values.into_iter().collect();
    let Some(values) = values else {
        return Ok(None);
    };
    ClusterIdentity::try_new(
        ClusterProvider::Gke,
        &format!(
            "projects/{}/locations/{}/clusters/{}",
            values[0], values[1], values[2]
        ),
    )
    .map(Some)
    .map_err(|_| invalid())
}
fn consistent_labels(fields: &SourceValue, cluster: &ClusterIdentity) -> bool {
    let parts = cluster.id().split('/').collect::<Vec<_>>();
    if parts.len() != 6
        || parts[0] != "projects"
        || parts[2] != "locations"
        || parts[4] != "clusters"
    {
        return false;
    }
    let Some(labels) = labels(fields) else {
        return false;
    };
    ["project_id", "location", "cluster_name"]
        .iter()
        .zip([parts[1], parts[3], parts[5]])
        .all(|(key, expected)| {
            labels.field(key).is_none_or(
                |value| matches!(value,SourceValue::Text(v) if valid_segment(v) && v==expected),
            )
        })
}
fn valid_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    if !is_audit(&fields) {
        return Err(invalid());
    }
    let timestamp = IndexedTime::from_rfc3339(
        fields
            .field("timestamp")
            .and_then(SourceValue::as_text)
            .ok_or_else(invalid)?,
        false,
    )
    .map_err(|_| invalid())?;
    let format = if is_gke(&fields) {
        gke_claim(&fields)?;
        "gke-audit"
    } else {
        "gcp-audit"
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
    AppError::Policy(
        "GKE source cluster labels must match an explicitly confirmed GKE identity".into(),
    )
}

fn resolve_context<'a>(
    context: &'a irmind_app::SourceClusterContext,
    claim: Option<&ClusterIdentity>,
    source: &str,
) -> Result<&'a ClusterIdentity, AppError> {
    if let Ok(identity) = context.resolve(claim) {
        return Ok(identity);
    }
    if let Some(claim) = claim
        && context
            .bindings()
            .iter()
            .all(|b| b.basis() == irmind_domain::ClusterContextBasis::ConfirmedSource)
    {
        let mut claims = context
            .bindings()
            .iter()
            .map(|b| b.identity().clone())
            .collect::<Vec<_>>();
        if !claims.contains(claim) {
            claims.push(claim.clone());
        }
        if claims.len() > irmind_domain::MAX_SOURCE_CLUSTERS {
            return Err(AppError::Policy(
                "An export may bind at most eight confirmed clusters; split this export by cluster"
                    .into(),
            ));
        }
        claims.sort();
        return Err(AppError::ParserClusterContextRequired {
            source_name: source.into(),
            requirement: irmind_app::ParserClusterRequirement::try_new(true, claims)?,
        });
    }
    Err(invalid_context())
}
