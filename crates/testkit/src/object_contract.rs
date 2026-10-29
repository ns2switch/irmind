use futures_util::StreamExt as _;
use irmind_app::{AppError, CancellationToken, ObjectSource, ObjectSourceOutput};
use irmind_domain::{
    AuthorizedCall, Case, CaseId, Decision, ExecutionMode, ProposedCall, Severity, Tool, evaluate,
};
use std::collections::BTreeMap;

const FROM: &str = "2020-01-01T00:00:00Z";
const TO: &str = "2100-01-01T00:00:00Z";

/// Shared bounded-list and version-bound read contract for all three adapters.
pub async fn run_object_source_contract(
    port: &dyn ObjectSource,
    scheme: &str,
    container: &str,
    prefix: &str,
    key: &str,
    expected: &[u8],
) -> Result<irmind_app::ObjectEntry, AppError> {
    let scope = format!(
        "v3;sources={};accounts=;projects=;hosts=;objects={scheme}://{container}/{prefix};from={FROM};to={TO}",
        port.source_id()
    );
    let case = Case {
        id: CaseId::parse("00000000-0000-0000-0000-000000000001")
            .map_err(|_| AppError::RemoteTool)?,
        title: "synthetic".into(),
        severity: Severity::Low,
        scope,
        sealed: false,
    };
    let mut args = BTreeMap::from([
        ("source".into(), port.source_id().into()),
        ("scheme".into(), scheme.into()),
        ("container".into(), container.into()),
        ("prefix".into(), prefix.into()),
        ("from".into(), FROM.into()),
        ("to".into(), TO.into()),
        ("limit".into(), "20".into()),
    ]);
    let list_call = authorize(&case, Tool::ObjectList, args.clone(), 1)?;
    let ObjectSourceOutput::Listing {
        objects, truncated, ..
    } = port.execute(&list_call, &CancellationToken::new()).await?
    else {
        return Err(AppError::RemoteTool);
    };
    if truncated {
        return Err(AppError::RemoteTool);
    }
    let Some(entry) = objects.into_iter().find(|item| item.key == key) else {
        return Err(AppError::RemoteTool);
    };
    if entry.size != expected.len() as u64 {
        return Err(AppError::RemoteTool);
    }
    args.remove("prefix");
    args.remove("limit");
    args.insert("key".into(), key.into());
    args.insert("max_bytes".into(), entry.size.to_string());
    if let Some(version) = entry.version {
        args.insert("version".into(), version);
    } else if let Some(etag) = entry
        .provider_checksum
        .and_then(|value| value.strip_prefix("etag:").map(str::to_owned))
    {
        args.insert("etag".into(), etag);
    } else {
        return Err(AppError::RemoteTool);
    }
    let read_call = authorize(&case, Tool::ObjectRead, args, 2)?;
    let ObjectSourceOutput::Object {
        metadata,
        mut chunks,
    } = port.execute(&read_call, &CancellationToken::new()).await?
    else {
        return Err(AppError::RemoteTool);
    };
    let mut bytes = Vec::new();
    while let Some(chunk) = chunks.next().await {
        bytes.extend_from_slice(&chunk?);
    }
    if bytes == expected {
        Ok(metadata)
    } else {
        Err(AppError::RemoteTool)
    }
}

fn authorize(
    case: &Case,
    tool: Tool,
    args: BTreeMap<String, String>,
    seq: u64,
) -> Result<AuthorizedCall, AppError> {
    let Decision::Allow(call) = evaluate(
        case,
        ProposedCall { tool, args },
        seq,
        ExecutionMode::Attended,
        1_700_000_000,
    ) else {
        return Err(AppError::RemoteTool);
    };
    Ok(call)
}
