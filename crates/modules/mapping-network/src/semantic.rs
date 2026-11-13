//! Native glue validates preserved TSV scalar representations; finite tables classify.
mod fields;
use super::{
    headers::Headers,
    projection::{View, zeek_kind},
};
use irmind_app::source_mapping::{MappingDiagnostic, MappingError, SourceRecordV1};
use irmind_domain::{
    BoundedObservations, CommonEventV1, CommonField as F, CommonValue, EventContextV1, EventText,
};

pub(super) fn project(
    parser: &str,
    source: &SourceRecordV1,
    headers: &Headers,
) -> Result<(CommonEventV1, Vec<MappingDiagnostic>), MappingError> {
    let zeek = parser == "parser-zeek";
    let view = View::new(source, zeek)?;
    let kind = if zeek {
        zeek_kind(source, &view)
    } else {
        view.get("event_type")
            .ok_or(MappingError::UnsupportedSourceValue)?
    };
    let key = format!(
        "{}-{}-{kind}",
        if zeek { "zeek" } else { "suricata" },
        if view.is_tsv() { "tsv" } else { "json" }
    );
    let header = headers.get(source, &key)?.with_action(kind).map_err(bad)?;
    let mut context = EventContextV1::default();
    let mut observations = Vec::new();
    let mut diagnostics = Vec::new();
    fields::project(
        source,
        &view,
        zeek,
        kind,
        &mut context,
        &mut observations,
        &mut diagnostics,
    )?;
    if let Some(protocol) = match kind {
        "dns" => Some("dns"),
        "http" => Some("http"),
        "ssl" | "tls" | "x509" => Some("tls"),
        _ => None,
    } {
        context
            .try_insert(
                F::NetworkProtocol,
                CommonValue::Text(EventText::new(protocol).map_err(bad)?),
            )
            .map_err(bad)?;
    }
    if let Some(transport) = view.get("proto") {
        context
            .try_insert(
                F::NetworkTransport,
                CommonValue::Text(EventText::new(&transport.to_ascii_lowercase()).map_err(bad)?),
            )
            .map_err(bad)?;
    }
    let event = CommonEventV1::try_new(
        source.origin().clone(),
        source.timestamp(),
        header,
        context,
        BoundedObservations::try_new(observations).map_err(bad)?,
    )
    .map_err(bad)?;
    if event.event().categories().bits() == 0 {
        diagnostics.push(MappingDiagnostic::Unclassified);
    }
    Ok((event, diagnostics))
}
fn bad<T>(_: T) -> MappingError {
    MappingError::UnsupportedSourceValue
}
