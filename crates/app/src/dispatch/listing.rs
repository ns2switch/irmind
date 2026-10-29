use crate::{AppError, AuthorizedCall, ObjectEntry};
use irmind_domain::{SourceManifestV1, UtcTimestamp};
use std::collections::BTreeSet;

pub(super) fn validated_listing(
    call: &AuthorizedCall,
    objects: &[ObjectEntry],
    total_bytes: u64,
    truncated: bool,
) -> Result<Vec<u8>, AppError> {
    let (
        Some(source),
        Some(scheme),
        Some(container),
        Some(prefix),
        Some(from),
        Some(to),
        Some(limit),
    ) = (
        call.arg("source"),
        call.arg("scheme"),
        call.arg("container"),
        call.arg("prefix"),
        call.arg("from"),
        call.arg("to"),
        call.arg("limit")
            .and_then(|value| value.parse::<usize>().ok()),
    )
    else {
        return Err(AppError::RemoteTool);
    };
    let from = UtcTimestamp::parse(from).map_err(|_| AppError::RemoteTool)?;
    let to = UtcTimestamp::parse(to).map_err(|_| AppError::RemoteTool)?;
    if objects.len() > limit || limit > 1_000 || from > to {
        return Err(AppError::RemoteTool);
    }
    let mut keys = BTreeSet::new();
    let mut sum = 0u64;
    for item in objects {
        let uri = format!("{scheme}://{container}/{}", item.key);
        let in_prefix = item.key == prefix.trim_end_matches('/')
            || item
                .key
                .strip_prefix(prefix)
                .is_some_and(|rest| prefix.ends_with('/') || rest.starts_with('/'));
        let modified = item
            .modified_unix_seconds
            .and_then(|at| i64::try_from(at).ok());
        let checked = SourceManifestV1 {
            source: uri.clone(),
            size: item.size,
            modified_unix_seconds: item.modified_unix_seconds,
            version: item.version.clone(),
            provider_checksum: item.provider_checksum.clone(),
            sha256: irmind_domain::EvidenceHash::parse(&"0".repeat(64))
                .map_err(|_| AppError::RemoteTool)?,
            copied: false,
        };
        if item.uri != uri
            || !in_prefix
            || !keys.insert(&item.key)
            || !modified.is_some_and(|at| at >= from.unix_seconds() && at <= to.unix_seconds())
            || checked.validate().is_err()
        {
            return Err(AppError::RemoteTool);
        }
        sum = sum.checked_add(item.size).ok_or(AppError::RemoteTool)?;
    }
    if sum != total_bytes {
        return Err(AppError::RemoteTool);
    }
    serde_json::to_vec(&serde_json::json!({
        "source": source, "objects": objects, "total_bytes": total_bytes, "truncated": truncated
    }))
    .map_err(|_| AppError::RemoteTool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use irmind_domain::{
        Case, CaseId, Decision, ExecutionMode, ProposedCall, Severity, Tool, evaluate,
    };
    use std::collections::BTreeMap;

    #[test]
    #[allow(clippy::unwrap_used, clippy::panic)]
    fn rejects_metadata_outside_the_authorized_prefix() {
        let from = "2026-10-23T00:00:00Z";
        let to = "2026-10-23T23:59:59Z";
        let case = Case {
            id: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            title: "synthetic".into(),
            severity: Severity::Low,
            scope: format!(
                "v3;sources=storage;accounts=;projects=;hosts=;objects=s3://bucket/AWSLogs/123/;from={from};to={to}"
            ),
            sealed: false,
        };
        let args = BTreeMap::from([
            ("source".into(), "storage".into()),
            ("scheme".into(), "s3".into()),
            ("container".into(), "bucket".into()),
            ("prefix".into(), "AWSLogs/123/".into()),
            ("from".into(), from.into()),
            ("to".into(), to.into()),
            ("limit".into(), "20".into()),
        ]);
        let Decision::Allow(call) = evaluate(
            &case,
            ProposedCall {
                tool: Tool::ObjectList,
                args,
            },
            1,
            ExecutionMode::Attended,
            1_700_000_000,
        ) else {
            panic!("scope rejected")
        };
        let item = ObjectEntry {
            uri: "s3://bucket/AWSLogs/123Other/a.json".into(),
            key: "AWSLogs/123Other/a.json".into(),
            size: 7,
            modified_unix_seconds: Some(1_792_756_800),
            version: Some("v1".into()),
            provider_checksum: None,
        };
        assert!(validated_listing(&call, &[item], 7, false).is_err());
    }
}
