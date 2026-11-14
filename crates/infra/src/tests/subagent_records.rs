use super::*;
use irmind_app::subagents::{SubagentPlanV1, SubagentRecord, verify_subagent_plan_consent};

#[test]
fn mathematically_valid_agent_signatures_cannot_authorize_a_threshold_plan() {
    let plan = SubagentPlanV1::decode(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/plan.json"
    ))
    .unwrap();
    assert!(plan.requires_signed_consent().unwrap());
    let keys: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/public-keys.json"
    ))
    .unwrap();
    let analyst = hex::decode(keys["analyst"].as_str().unwrap()).unwrap();
    let agent = hex::decode(keys["agent"].as_str().unwrap()).unwrap();
    let verifier = LocalVerifier {
        trusted: BTreeMap::new(),
    }
    .with_trusted_key(&Actor::Analyst, &analyst)
    .unwrap()
    .with_trusted_key(
        &Actor::Agent(irmind_domain::AgentId::parse("core").unwrap()),
        &agent,
    )
    .unwrap();
    let positive: SignedEntry = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/signed-plan-approval.json"
    ))
    .unwrap();
    verify_subagent_plan_consent(&positive, &plan, &verifier).unwrap();
    for raw in [
        include_bytes!(
            "../../../../docs/development/subagent-format-vectors/negative-agent-consent.json"
        )
        .as_slice(),
        include_bytes!(
            "../../../../docs/development/subagent-format-vectors/negative-forged-analyst.json"
        )
        .as_slice(),
    ] {
        let entry: SignedEntry = serde_json::from_slice(raw).unwrap();
        assert_eq!(entry.hash, sha256(&entry.canonical()));
        verifier
            .verify(&entry.public_key, &entry.hash, &entry.sig)
            .unwrap();
        assert!(verify_subagent_plan_consent(&entry, &plan, &verifier).is_err());
    }
    let mut stale = plan.clone();
    stale.budget_checkpoint_sha256 = irmind_app::subagents::SubagentDigest::from_bytes([7; 32]);
    assert!(verify_subagent_plan_consent(&positive, &stale, &verifier).is_err());
}

#[test]
fn branch_entry_domains_and_agent_binding_match_signed_vectors() {
    use irmind_app::subagents::{SubagentBranchEntry, SubagentBranchPayload};
    let keys: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/public-keys.json"
    ))
    .unwrap();
    let agent = hex::decode(keys["agent"].as_str().unwrap()).unwrap();
    let analyst = hex::decode(keys["analyst"].as_str().unwrap()).unwrap();
    let verifier = LocalVerifier {
        trusted: BTreeMap::new(),
    };
    for raw in [
        include_bytes!("../../../../docs/development/subagent-format-vectors/branch-proposal.json")
            .as_slice(),
        include_bytes!(
            "../../../../docs/development/subagent-format-vectors/branch-tool-result.json"
        )
        .as_slice(),
        include_bytes!("../../../../docs/development/subagent-format-vectors/branch-terminal.json")
            .as_slice(),
    ] {
        let entry = SubagentBranchEntry::decode(raw).unwrap();
        assert_eq!(entry.canonical().unwrap(), raw);
        entry.verify(&agent, &verifier).unwrap();
        assert!(entry.verify(&analyst, &verifier).is_err());
        let mut altered = entry.clone();
        altered.body.at += 1;
        assert!(altered.verify(&agent, &verifier).is_err());
        altered.hash = altered.body.identity().unwrap();
        assert!(altered.verify(&agent, &verifier).is_err());
    }
    let raw =
        include_str!("../../../../docs/development/subagent-format-vectors/branch-proposal.json");
    assert!(
        SubagentBranchEntry::decode(raw.replace("\"kind\":3", "\"kind\":9").as_bytes()).is_err()
    );
    let dup = raw.replace(
        "\"value\":\"alice\"",
        "\"value\":\"alice\",\"value\":\"alice\"",
    );
    assert!(SubagentBranchEntry::decode(dup.as_bytes()).is_err());
    let mut entry = SubagentBranchEntry::decode(raw.as_bytes()).unwrap();
    if let SubagentBranchPayload::ToolProposal(proposal) = &mut entry.body.payload {
        proposal
            .arguments
            .insert("value".into(), "unrelated".into());
    }
    assert!(entry.verify(&agent, &verifier).is_err());
}

#[test]
fn checkpoint_prefixes_are_acyclic_contiguous_and_terminal() {
    use irmind_app::subagents::{CheckedBranchChunk, SubagentBranchCursor, SubagentCheckpointV1};
    let plan = SubagentPlanV1::decode(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/plan.json"
    ))
    .unwrap();
    let keys: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/public-keys.json"
    ))
    .unwrap();
    let agent = hex::decode(keys["agent"].as_str().unwrap()).unwrap();
    let verifier = LocalVerifier {
        trusted: BTreeMap::new(),
    };
    let a = CheckedBranchChunk::decode(
        include_bytes!("../../../../docs/development/subagent-format-vectors/branch-chunk-0.json"),
        &agent,
        &verifier,
    )
    .unwrap();
    let b = CheckedBranchChunk::decode(
        include_bytes!("../../../../docs/development/subagent-format-vectors/branch-chunk-1.json"),
        &agent,
        &verifier,
    )
    .unwrap();
    let ca = SubagentCheckpointV1::decode(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/checkpoint-proposal.json"
    ))
    .unwrap();
    let cb = SubagentCheckpointV1::decode(include_bytes!(
        "../../../../docs/development/subagent-format-vectors/checkpoint-final.json"
    ))
    .unwrap();
    assert_eq!(
        a.checkpoint(None, vec![]).unwrap().canonical().unwrap(),
        ca.canonical().unwrap()
    );
    assert_eq!(
        b.checkpoint(Some(ca.identity().unwrap()), vec![])
            .unwrap()
            .canonical()
            .unwrap(),
        cb.canonical().unwrap()
    );
    let task = &plan.tasks[0];
    let fresh = || {
        SubagentBranchCursor::new(&plan.case_id, &plan.turn_id, task.task_id, &task.nonce).unwrap()
    };
    assert!(fresh().accept(&b, &cb).is_err());
    let mut cursor = fresh();
    cursor.accept(&a, &ca).unwrap();
    assert!(cursor.accept(&a, &ca).is_err());
    let mut altered = cb.clone();
    altered.previous_checkpoint = Some(cb.identity().unwrap());
    assert!(cursor.accept(&b, &altered).is_err());
    cursor.accept(&b, &cb).unwrap();
    assert!(cursor.is_terminal());
    assert!(cursor.accept(&b, &cb).is_err());
    let mut oversized =
        include_bytes!("../../../../docs/development/subagent-format-vectors/branch-chunk-0.json")
            .to_vec();
    oversized.resize(1024 * 1024 + 1, 0);
    assert!(CheckedBranchChunk::decode(&oversized, &agent, &verifier).is_err());
}
