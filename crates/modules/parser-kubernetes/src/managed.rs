//! Transport decoding only: retain the original envelope and the exact decoded event.
use super::decode::{invalid, is_native};
use irmind_app::{
    AppError, ParserClusterRequirement,
    source_mapping::{
        SourceValue,
        framed::DecodedSourceFrame,
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{ClusterIdentity, ClusterProvider, SourceClusterContext};
use std::collections::BTreeMap;
pub(super) fn prepare(fields: SourceValue) -> Result<DecodedSourceFrame, AppError> {
    if is_native(&fields) {
        return super::decode::prepare_native(fields);
    }
    let (format, encoded) = if let Some(message) = fields.field("message") {
        if !matches!(fields.field("timestamp"), Some(SourceValue::Number(_))) {
            return Err(invalid());
        }
        ("eks-audit", message)
    } else {
        let category = fields
            .field("category")
            .or_else(|| fields.field("Category"))
            .and_then(SourceValue::as_text);
        if !matches!(category, Some("kube-audit" | "kube-audit-admin")) {
            return Err(invalid());
        }
        let log = fields
            .field("properties")
            .and_then(|p| p.field("log"))
            .or_else(|| fields.field("log_s"))
            .ok_or_else(invalid)?;
        ("aks-audit", log)
    };
    let decoded = match encoded {
        SourceValue::Text(text) => decode_json_fields(text.as_bytes(), SourceJsonLimits::default())
            .map_err(|_| invalid())?,
        SourceValue::Object(_) => encoded.clone(),
        _ => return Err(invalid()),
    };
    let native = super::decode::prepare_native(decoded)?;
    let result = DecodedSourceFrame {
        fields: SourceValue::Object(BTreeMap::from([
            ("audit_event".into(), native.fields),
            ("transport".into(), fields),
        ])),
        timestamp: native.timestamp,
        format: irmind_app::source_mapping::SourceFormatV1::try_new(
            format,
            super::SOURCE_VERSION,
            BTreeMap::new(),
        )
        .map_err(|_| invalid())?,
    };
    claim(&result.fields, format)?;
    Ok(result)
}
pub(super) fn claim(
    fields: &SourceValue,
    format: &str,
) -> Result<Option<ClusterIdentity>, AppError> {
    if format != "aks-audit" {
        return Ok(None);
    }
    let transport = fields.field("transport").ok_or_else(invalid)?;
    let mut identity = None;
    for key in ["resourceId", "ResourceId", "_ResourceId"] {
        let Some(value) = transport.field(key) else {
            continue;
        };
        if matches!(value, SourceValue::Null) {
            continue;
        }
        let text = value.as_text().ok_or_else(invalid)?;
        if !text
            .to_ascii_lowercase()
            .contains("/providers/microsoft.containerservice/managedclusters/")
        {
            return Err(invalid());
        }
        let claim = ClusterIdentity::try_new(ClusterProvider::Aks, text).map_err(|_| invalid())?;
        if identity.as_ref().is_some_and(|previous| previous != &claim) {
            return Err(invalid());
        }
        identity = Some(claim);
    }
    Ok(identity)
}
pub(super) fn resolve<'a>(
    context: &'a SourceClusterContext,
    fields: &SourceValue,
    format: &str,
    source: &str,
) -> Result<&'a ClusterIdentity, AppError> {
    let claim = claim(fields, format)?;
    let cluster = match context.resolve(claim.as_ref()) {
        Ok(cluster) => cluster,
        Err(_)
            if claim.is_some()
                && context
                    .bindings()
                    .iter()
                    .all(|b| b.basis() == irmind_domain::ClusterContextBasis::ConfirmedSource) =>
        {
            let mut claims = context
                .bindings()
                .iter()
                .map(|b| b.identity().clone())
                .collect::<Vec<_>>();
            if let Some(claim) = claim {
                claims.push(claim);
            }
            claims.sort();
            claims.dedup();
            return Err(AppError::ParserClusterContextRequired {
                source_name: source.into(),
                requirement: ParserClusterRequirement::try_new(true, claims)?,
            });
        }
        Err(_) => return Err(context_error()),
    };
    if (format == "eks-audit" && cluster.provider() != ClusterProvider::Eks)
        || (format == "aks-audit" && cluster.provider() != ClusterProvider::Aks)
    {
        return Err(context_error());
    }
    Ok(cluster)
}
pub(super) fn requirement(sample: &[u8]) -> Result<ParserClusterRequirement, AppError> {
    let mut input = std::io::Cursor::new(&sample[..sample.len().min(65536)]);
    let cancel = irmind_app::CancellationToken::new();
    let mut frames = JsonFrames::new(&mut input, &cancel);
    let mut claims = Vec::new();
    while let Ok(Some(frame)) = frames.next_frame() {
        let Ok(fields) = decode_json_fields(frame.bytes(), SourceJsonLimits::default()) else {
            continue;
        };
        let Ok(record) = prepare(fields) else {
            continue;
        };
        if let Some(claim) = claim(&record.fields, record.format.id())?
            && !claims.contains(&claim)
        {
            claims.push(claim);
            if claims.len() > irmind_domain::MAX_SOURCE_CLUSTERS {
                return Err(context_error());
            }
        }
    }
    claims.sort();
    ParserClusterRequirement::try_new(true, claims)
}
pub(super) fn detect(sample: &[u8]) -> Option<()> {
    let mut input = std::io::Cursor::new(&sample[..sample.len().min(65536)]);
    let cancel = irmind_app::CancellationToken::new();
    let frame = JsonFrames::new(&mut input, &cancel).next_frame().ok()??;
    let fields = decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok()?;
    prepare(fields).ok().map(|_| ())
}
fn context_error() -> AppError {
    AppError::Policy("Kubernetes transport identity must match the explicitly confirmed cluster and provider; split exports by cluster or confirm every source claim".into())
}
