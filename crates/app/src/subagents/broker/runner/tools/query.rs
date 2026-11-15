use super::{
    AppError, ChildAction, GraphQueryFilter, TaskEvidenceQuery, TaskEvidenceResult, Tool, invalid,
};

pub(super) fn supported(name: &str) -> bool {
    matches!(
        name,
        "evidence_search"
            | "evidence_read"
            | "graph_summary"
            | "entity_lookup"
            | "neighbors"
            | "entity_timeline"
            | "path"
            | "text_search"
            | "raw_records"
    )
}
pub(super) fn checked(
    call: &crate::ProposedCall,
    protocol: &crate::subagents::BranchToolCall,
    task: crate::subagents::SubagentDigest,
    view: &crate::subagents::VerifiedTaskQueryView,
) -> Result<ChildAction, AppError> {
    if call.tool == Tool::SkillRead {
        return Ok(ChildAction::Method);
    }
    if call.tool == Tool::CaseAddFinding {
        return crate::subagents::finding::proposed_finding(task, protocol, view.sources())
            .map(|finding| ChildAction::Finding(Box::new(finding)))
            .map_err(|_| invalid());
    }
    let query = from_call(call)?;
    query.validate(view)?;
    Ok(ChildAction::Query(Box::new(query)))
}
pub(super) fn from_call(call: &crate::ProposedCall) -> Result<TaskEvidenceQuery, AppError> {
    let field = |name: &str| call.args.get(name).cloned().ok_or_else(invalid);
    let limit = call
        .args
        .get("limit")
        .map(|n| n.parse::<usize>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(10);
    let filter = || GraphQueryFilter::from_args(&call.args).map_err(|_| invalid());
    let entity = || Ok::<_, AppError>((field("kind")?, field("value")?));
    Ok(match call.tool {
        Tool::EvidenceSearch => TaskEvidenceQuery::EvidenceSearch {
            query: field("query")?,
            limit,
        },
        Tool::EvidenceRead => TaskEvidenceQuery::EvidenceRead {
            hash: irmind_domain::EvidenceHash::parse(&field("hash")?).map_err(|_| invalid())?,
            limit,
        },
        Tool::GraphSummary => TaskEvidenceQuery::GraphSummary,
        Tool::EntityLookup => {
            let (kind, value) = entity()?;
            TaskEvidenceQuery::EntityLookup {
                filter: filter()?,
                kind,
                value,
            }
        }
        Tool::Neighbors => {
            let (kind, value) = entity()?;
            TaskEvidenceQuery::Neighbors {
                filter: filter()?,
                kind,
                value,
                limit,
            }
        }
        Tool::EntityTimeline => TaskEvidenceQuery::Timeline {
            filter: filter()?,
            entity: Some(entity()?),
            limit,
        },
        Tool::GraphPath => TaskEvidenceQuery::Path {
            filter: filter()?,
            from: (field("from_kind")?, field("from_value")?),
            to: (field("to_kind")?, field("to_value")?),
        },
        Tool::TextSearch => TaskEvidenceQuery::TextSearch {
            filter: filter()?,
            query: field("query")?,
            limit,
        },
        Tool::RawRecords => TaskEvidenceQuery::RawRecords {
            hash: irmind_domain::EvidenceHash::parse(&field("hash")?).map_err(|_| invalid())?,
            index: field("index")?.parse().map_err(|_| invalid())?,
            original: call.args.get("view").is_some_and(|v| v == "original"),
        },
        _ => return Err(invalid()),
    })
}
pub(super) fn text(value: TaskEvidenceResult) -> Result<String, AppError> {
    match value {
        TaskEvidenceResult::Text(text) => Ok(text),
        TaskEvidenceResult::Timeline(events) => serde_json::to_string(
            &events
                .iter()
                .map(|event| {
                    (
                        &event.at,
                        &event.event,
                        &event.evidence_hash,
                        event.record_index,
                    )
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|_| invalid()),
        TaskEvidenceResult::Original(record) => {
            let mut fields = Err(invalid());
            record.inspect(|value| {
                fields = crate::source_mapping::json::render_source_fields(value.fields())
                    .map_err(|_| invalid());
            });
            let fields = fields?;
            let end = fields.floor_char_boundary(fields.len().min(2000));
            Ok(format!(
                "view=original verified {excerpt}{suffix}",
                excerpt = &fields[..end],
                suffix = if end < fields.len() {
                    " [truncated]"
                } else {
                    ""
                }
            ))
        }
    }
}
