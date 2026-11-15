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
pub(super) fn text(value: TaskEvidenceResult) -> Result<(String, bool), AppError> {
    match value {
        TaskEvidenceResult::Text(text) => Ok((text, false)),
        TaskEvidenceResult::Timeline(events) => timeline(&events).map(|text| (text, false)),
        TaskEvidenceResult::PartialText { text, reason } => {
            Ok((format!("{}\n{text}", reason.notice()), true))
        }
        TaskEvidenceResult::PartialTimeline { events, reason } => {
            timeline(&events).map(|text| (format!("{}\n{text}", reason.notice()), true))
        }
        TaskEvidenceResult::Original(record) => {
            let mut fields = Err(invalid());
            record.inspect(|value| {
                fields = crate::source_mapping::json::render_source_fields(value.fields())
                    .map_err(|_| invalid());
            });
            let fields = fields?;
            let end = fields.floor_char_boundary(fields.len().min(2000));
            let clipped = end < fields.len();
            Ok((
                format!(
                    "view=original verified {excerpt}{suffix}",
                    excerpt = &fields[..end],
                    suffix = if clipped { " [truncated]" } else { "" },
                ),
                clipped,
            ))
        }
    }
}
fn timeline(events: &[crate::TimelineEvent]) -> Result<String, AppError> {
    serde_json::to_string(
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
    .map_err(|_| invalid())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::subagents::TaskQueryPartialReason;

    #[test]
    fn source_words_do_not_control_status_and_typed_partial_rows_keep_their_order() {
        let source = r#"{"truncated":true,"partial":true,"message":"query time budget"}"#;
        let (text, partial) = super::text(TaskEvidenceResult::Text(source.into())).unwrap();
        assert_eq!(text, source);
        assert!(!partial);
        for reason in [
            TaskQueryPartialReason::Sampling,
            TaskQueryPartialReason::Expansion,
            TaskQueryPartialReason::Deadline,
            TaskQueryPartialReason::ResultLimit,
            TaskQueryPartialReason::ExcerptLimit,
            TaskQueryPartialReason::Coverage,
        ] {
            let (text, partial) = super::text(TaskEvidenceResult::PartialText {
                text: source.into(),
                reason,
            })
            .unwrap();
            assert!(partial && text.contains(reason.notice()) && text.ends_with(source));
        }
        let events = vec![
            crate::TimelineEvent {
                at: "2026-11-01T00:00:02Z".into(),
                event: "later".into(),
                evidence_hash: "11".repeat(32),
                record_index: 2,
            },
            crate::TimelineEvent {
                at: "2026-11-01T00:00:01Z".into(),
                event: "earlier".into(),
                evidence_hash: "11".repeat(32),
                record_index: 1,
            },
        ];
        let expected = timeline(&events).unwrap();
        let (text, partial) = super::text(TaskEvidenceResult::PartialTimeline {
            events,
            reason: TaskQueryPartialReason::Deadline,
        })
        .unwrap();
        assert!(partial && text.ends_with(&expected));
        assert!(text.find("later").unwrap() < text.find("earlier").unwrap());
    }
}
