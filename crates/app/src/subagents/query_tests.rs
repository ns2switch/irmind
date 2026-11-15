use super::*;
use crate::subagents::{SafePlanPreview, SubagentPlanV1, SubagentRecord};

fn view() -> VerifiedTaskQueryView {
    VerifiedTaskQueryView {
        case: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
        task: SubagentDigest::from_bytes([1; 32]),
        generation_seq: 4,
        generation_hash: SubagentDigest::from_bytes([2; 32]),
        source_set: SubagentDigest::from_bytes([3; 32]),
        sources: BTreeSet::from(["a".repeat(64)]),
        scope: CaseScope::LocalOnly,
        ceiling: None,
        policy_fingerprint: SubagentDigest::from_bytes([4; 32]),
    }
}
#[test]
fn task_query_view_cannot_fall_back_from_missing_sources_or_invalid_limits() {
    let view = view();
    let own = EvidenceHash::parse(&"a".repeat(64)).unwrap();
    let other = EvidenceHash::parse(&"b".repeat(64)).unwrap();
    assert!(
        TaskEvidenceQuery::EvidenceRead {
            hash: own.clone(),
            limit: 20
        }
        .validate(&view)
        .is_ok()
    );
    assert!(
        TaskEvidenceQuery::EvidenceRead {
            hash: other,
            limit: 1
        }
        .validate(&view)
        .is_err()
    );
    assert!(
        TaskEvidenceQuery::RawRecords {
            hash: own.clone(),
            index: 100_000,
            original: true
        }
        .validate(&view)
        .is_err()
    );
    assert!(
        TaskEvidenceQuery::Neighbors {
            filter: GraphQueryFilter::default(),
            kind: "unsupported-entity-kind".into(),
            value: "not an ip".into(),
            limit: 1
        }
        .validate(&view)
        .is_err()
    );
    for limit in [0, 21, usize::MAX] {
        assert!(
            TaskEvidenceQuery::TextSearch {
                filter: GraphQueryFilter::default(),
                query: "synthetic".into(),
                limit
            }
            .validate(&view)
            .is_err()
        );
    }
    let mut empty = self::view();
    empty.sources.clear();
    assert!(
        TaskEvidenceQuery::RawRecords {
            hash: own,
            index: 0,
            original: false
        }
        .validate(&empty)
        .is_err()
    );
    assert!(TaskEvidenceQuery::GraphSummary.validate(&empty).is_ok());
}

#[test]
fn automatic_plan_choice_never_substitutes_for_required_explicit_start() {
    let plan = SubagentPlanV1::decode(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/plan.json"
    ))
    .unwrap();
    let mut preview = SafePlanPreview {
        plan: plan.clone(),
        confirmation_required: true,
    };
    assert!(preview.automatic_start().is_err());
    let choice = preview.start().unwrap();
    assert!(choice.starts());
    assert!(choice.explicit());
    assert_eq!(choice.plan(), plan.identity().unwrap());
    assert_eq!(choice.budget(), plan.budget_checkpoint_sha256);
    assert!(!preview.cancel().unwrap().starts());
    preview.confirmation_required = false;
    assert!(!preview.automatic_start().unwrap().explicit());
}

#[test]
fn task_case_scope_encoding_preserves_local_and_remote_meaning() {
    assert_eq!(
        CaseScope::parse(&scope_text(&CaseScope::LocalOnly).unwrap()).unwrap(),
        CaseScope::LocalOnly
    );
    let scope = CaseScope::parse("v1;sources=siem-a;accounts=acct-a;hosts=;from=2026-11-01T00:00:00Z;to=2026-11-01T01:00:00Z").unwrap();
    let restored = CaseScope::parse(&scope_text(&scope).unwrap()).unwrap();
    assert!(scope.is_within(&restored));
    assert!(restored.is_within(&scope));
}
