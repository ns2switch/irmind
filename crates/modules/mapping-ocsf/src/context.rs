use super::view::View;
use irmind_app::source_mapping::{MappingError, SourceValue};
use irmind_domain::{CommonField as F, EventContextV1};
const FIELDS: &[(F, &str)] = &[
    (F::HostName, "device.hostname"),
    (F::HostId, "device.uid"),
    (F::UserName, "actor.user.name"),
    (F::UserId, "actor.user.uid"),
    (F::UserDomain, "actor.user.domain"),
    (F::UserTargetName, "user.name"),
    (F::UserTargetId, "user.uid"),
    (F::UserTargetDomain, "user.domain"),
    (F::SourceIp, "src_endpoint.ip"),
    (F::SourcePort, "src_endpoint.port"),
    (F::SourceDomain, "src_endpoint.domain"),
    (F::DestinationIp, "dst_endpoint.ip"),
    (F::DestinationPort, "dst_endpoint.port"),
    (F::DestinationDomain, "dst_endpoint.domain"),
    (F::ProcessPid, "process.pid"),
    (F::ProcessName, "process.name"),
    (F::ProcessCommandLine, "process.cmd_line"),
    (F::ProcessEntityId, "process.uid"),
    (F::ProcessParentPid, "process.parent_process.pid"),
    (F::ProcessParentName, "process.parent_process.name"),
    (
        F::ProcessParentCommandLine,
        "process.parent_process.cmd_line",
    ),
    (F::FilePath, "file.path"),
    (F::FileName, "file.name"),
    (F::FileSize, "file.size"),
    (F::CloudAccountId, "cloud.account.uid"),
    (F::CloudRegion, "cloud.region"),
    (F::CloudProvider, "cloud.provider"),
    (F::HttpRequestMethod, "http_request.http_method"),
    (F::HttpResponseStatusCode, "http_response.code"),
    (F::UrlFull, "http_request.url.url_string"),
];
pub(super) fn project(view: &View<'_>, supported: bool) -> Result<EventContextV1, MappingError> {
    let mut context = EventContextV1::default();
    if !supported {
        return Ok(context);
    }
    for &(field, path) in FIELDS {
        let Some(value) = view.get(path) else {
            continue;
        };
        if matches!(value, SourceValue::Null)
            || matches!(value,SourceValue::Text(t) if t.is_empty())
        {
            continue;
        }
        let value = irmind_mapping_tables::copy_common_value(field, value)?;
        context
            .try_insert(field, value)
            .map_err(|_| MappingError::UnsupportedSourceValue)?;
    }
    Ok(context)
}
