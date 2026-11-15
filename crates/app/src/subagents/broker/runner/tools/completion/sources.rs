//! References come from typed query results, never from model or display text.
use super::{SubagentBranchPayload, TaskEvidenceResult, invalid};
use crate::AppError;
use crate::subagents::{BranchToolCall, SubagentDigest, SubagentSourceRef, VerifiedTaskQueryView};

pub(super) fn references(
    response: &TaskEvidenceResult,
    call: &BranchToolCall,
    view: &VerifiedTaskQueryView,
) -> Result<Vec<SubagentSourceRef>, AppError> {
    let mut sources = match response {
        TaskEvidenceResult::Timeline(events)
        | TaskEvidenceResult::PartialTimeline { events, .. } => events
            .iter()
            .map(|event| {
                Ok(SubagentSourceRef {
                    hash: SubagentDigest::parse(&event.evidence_hash).map_err(|_| invalid())?,
                    index: u64::try_from(event.record_index).map_err(|_| invalid())?,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?,
        TaskEvidenceResult::Original(record) => {
            let mut reference = None;
            record.inspect(|value| {
                reference = Some((value.origin().source().clone(), value.origin().record()));
            });
            let (hash, index) = reference.ok_or_else(invalid)?;
            if call.tool != crate::Tool::RawRecords.as_str()
                || call.arguments.get("hash").map(String::as_str) != Some(hash.as_str())
                || call
                    .arguments
                    .get("index")
                    .and_then(|v| v.parse::<u64>().ok())
                    != Some(index)
                || crate::hex(record.provenance().evidence_hash()) != hash.as_str()
                || record.provenance().record_index() != Some(index)
            {
                return Err(invalid());
            }
            vec![SubagentSourceRef {
                hash: SubagentDigest::parse(hash.as_str()).map_err(|_| invalid())?,
                index,
            }]
        }
        TaskEvidenceResult::Text(_) | TaskEvidenceResult::PartialText { .. } => vec![],
    };
    if sources
        .iter()
        .any(|source| !view.sources().contains(&crate::hex(source.hash.as_bytes())))
    {
        return Err(invalid());
    }
    sources.sort_unstable();
    sources.dedup();
    Ok(sources)
}

pub(super) fn attach(
    mut payload: SubagentBranchPayload,
    sources: Vec<SubagentSourceRef>,
) -> (SubagentBranchPayload, Vec<SubagentSourceRef>) {
    if let SubagentBranchPayload::ToolResult(result) = &mut payload {
        result.sources.clone_from(&sources);
        (payload, sources)
    } else {
        // Late results produce only a budget notice, without admitting their references.
        (payload, vec![])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_domain::{
        DecodeAnnotationsV1, EventOrigin, EvidenceHash, Provenance, SourceFormatV1, SourceRecordV1,
        SourceValue, Tainted,
    };
    use std::collections::{BTreeMap, BTreeSet};

    fn view() -> VerifiedTaskQueryView {
        VerifiedTaskQueryView {
            case: crate::CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            task: SubagentDigest::from_bytes([1; 32]),
            generation_seq: 4,
            generation_hash: SubagentDigest::from_bytes([2; 32]),
            source_set: SubagentDigest::from_bytes([3; 32]),
            sources: BTreeSet::from(["07".repeat(32)]),
            scope: crate::CaseScope::LocalOnly,
            ceiling: None,
            policy_fingerprint: SubagentDigest::from_bytes([4; 32]),
        }
    }
    fn call() -> BranchToolCall {
        BranchToolCall {
            id: "read".into(),
            tool: crate::Tool::RawRecords.as_str().into(),
            arguments: BTreeMap::from([
                ("hash".into(), "07".repeat(32)),
                ("index".into(), "7".into()),
            ]),
        }
    }
    fn original(provenance: [u8; 32], index: u64) -> TaskEvidenceResult {
        let record = SourceRecordV1::try_new(
            EventOrigin::try_new(
                EvidenceHash::from_bytes([7; 32]),
                7,
                Some(42),
                "parser-json",
                "json-stream-v3",
            )
            .unwrap(),
            "synthetic/events.json",
            None,
            SourceFormatV1::try_new("json", "source-json-v1", BTreeMap::new()).unwrap(),
            SourceValue::object(vec![(
                "message".into(),
                SourceValue::Text("synthetic".into()),
            )])
            .unwrap(),
            DecodeAnnotationsV1::default(),
        )
        .unwrap();
        TaskEvidenceResult::Original(Box::new(Tainted::from_external(
            record,
            Provenance::new(provenance, Some(index), irmind_domain::SourceKind::File),
        )))
    }
    #[test]
    fn original_references_require_matching_call_origin_and_taint_metadata() {
        let mut view = view();
        let mut call = call();
        let refs = references(&original([7; 32], 7), &call, &view).unwrap();
        assert_eq!(
            refs,
            vec![SubagentSourceRef {
                hash: SubagentDigest::from_bytes([7; 32]),
                index: 7
            }]
        );
        assert!(references(&original([8; 32], 7), &call, &view).is_err());
        assert!(references(&original([7; 32], 8), &call, &view).is_err());
        call.arguments.insert("index".into(), "6".into());
        assert!(references(&original([7; 32], 7), &call, &view).is_err());
        call = self::call();
        view.sources.clear();
        assert!(references(&original([7; 32], 7), &call, &view).is_err());
    }
    #[test]
    fn text_never_admits_references_and_typed_rows_are_sorted_deduplicated_and_scoped() {
        let view = view();
        assert!(
            references(
                &TaskEvidenceResult::Text(format!("hash={} index=7", "07".repeat(32))),
                &call(),
                &view
            )
            .unwrap()
            .is_empty()
        );
        let row = |index, hash: &str| crate::TimelineEvent {
            at: "2026-11-01T00:00:00Z".into(),
            event: "synthetic".into(),
            evidence_hash: hash.into(),
            record_index: index,
        };
        let response = TaskEvidenceResult::Timeline(vec![
            row(7, &"07".repeat(32)),
            row(2, &"07".repeat(32)),
            row(7, &"07".repeat(32)),
        ]);
        let refs = references(&response, &call(), &view).unwrap();
        assert_eq!(refs.iter().map(|r| r.index).collect::<Vec<_>>(), vec![2, 7]);
        assert!(
            references(
                &TaskEvidenceResult::Timeline(vec![row(7, &"08".repeat(32))]),
                &call(),
                &view
            )
            .is_err()
        );
    }
}
