use super::*;
use crate::{CompiledSkill, SkillCompiler, SkillOrigin};
use irmind_domain::{SkillMetadata, SkillMetadataInput, SkillPackage};
const SNAPSHOT: &str =
    include_str!("../../../../../docs/development/skills-v2-format-vectors/snapshot-payload.txt");
const LOAD: &str =
    include_str!("../../../../../docs/development/skills-v2-format-vectors/load-payload.txt");

struct Compiler;
impl SkillCompiler for Compiler {
    fn compile(&self, package: SkillPackage) -> Result<CompiledSkill, AppError> {
        let text = package
            .resources()
            .values()
            .next()
            .unwrap()
            .untrusted_text();
        let offset = text.find("# Review").unwrap();
        let metadata = SkillMetadata::new(SkillMetadataInput {
            format: "irmind-skill-v1".into(),
            name: "synthetic-triage".into(),
            version: "1".into(),
            description: "Review synthetic records.".into(),
            author: "Community".into(),
            license: "MIT".into(),
            target_schema: "irmind-common-event-v1".into(),
            tools: vec!["text_search".into()],
            sources: vec!["parser-json".into()],
            categories: vec![],
            invocable: true,
        })?;
        Ok(CompiledSkill::new(metadata, package, offset)?)
    }
}
#[test]
fn approved_skill_vectors_round_trip_with_exact_bytes_and_distinct_identities() {
    let snapshot = SkillSnapshotV2::decode(SNAPSHOT.trim_end()).unwrap();
    assert_eq!(snapshot.encode().unwrap(), SNAPSHOT.trim_end());
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/development/skills-v2-format-vectors/identities.json"
    ))
    .unwrap();
    assert_eq!(
        hex(snapshot.identity().unwrap().as_bytes()),
        expected["snapshot_sha256"]
    );
    assert_eq!(
        hex(snapshot.package().unwrap().hash().as_bytes()),
        expected["package_sha256"]
    );
    let skill = snapshot.compile(&Compiler).unwrap();
    assert_eq!(
        SkillSnapshotV2::new(&skill, SkillOrigin::Analyst, [0x11; 32]),
        snapshot
    );
    let load = SkillLoadV1::decode(LOAD.trim_end()).unwrap();
    assert_eq!(load.encode().unwrap(), LOAD.trim_end());
    assert_eq!(load.snapshot().unwrap(), snapshot.identity().unwrap());
    assert!(!format!("{snapshot:?}{load:?}").contains("Review the signed synthetic"));
}

#[test]
fn catalog_snapshot_v2_matches_the_approved_body_identity_and_origin_rules() {
    let bytes =
        include_bytes!("../../../../../docs/development/catalog-format-vectors/snapshot-v2.json");
    let payload = format!(
        "{}:{}",
        AuditEventKind::SkillSnapshotV2.as_str(),
        hex(bytes)
    );
    let snapshot = SkillSnapshotV2::decode(&payload).unwrap();
    assert_eq!(snapshot.encode().unwrap(), payload);
    assert_eq!(
        hex(snapshot.identity().unwrap().as_bytes()),
        "70ecd88d6f58c37302798bfa806ae8b12cca8c6c5f32468a7cc03db03929871c"
    );
    let receipt = crate::catalog::CatalogReceipt::decode(include_bytes!(
        "../../../../../docs/development/catalog-format-vectors/catalog-receipt.json"
    ))
    .unwrap();
    let skill = snapshot.compile(&Compiler).unwrap();
    let authorization = hash(snapshot.admission().unwrap()).unwrap();
    assert_eq!(
        SkillSnapshotV2::new_catalog(&skill, authorization, &receipt).unwrap(),
        snapshot
    );
    assert!(
        SkillSnapshotV2::new(&skill, SkillOrigin::Catalog, authorization)
            .encode()
            .is_err()
    );
    let changed = std::str::from_utf8(bytes)
        .unwrap()
        .replace("\"origin\":\"catalog\"", "\"origin\":\"analyst\"");
    assert!(
        SkillSnapshotV2::decode(&format!(
            "{}:{}",
            AuditEventKind::SkillSnapshotV2.as_str(),
            hex(changed.as_bytes())
        ))
        .is_err()
    );
}

#[test]
fn skill_receipt_decoding_rejects_noncanonical_data_and_inconsistent_commitments() {
    let (prefix, value) = SNAPSHOT.trim_end().split_once(':').unwrap();
    let raw = String::from_utf8(hex::decode(value).unwrap()).unwrap();
    for changed in [
        format!(" {raw}"),
        raw.replace("\"files\":", "\"extra\":0,\"files\":"),
        raw.replace("irmind-skill-interpreter-v1", "unknown-interpreter"),
        raw.replace(
            "\"release_inventory_sha256\":null",
            "\"release_inventory_sha256\":\"bad\"",
        ),
    ] {
        assert!(SkillSnapshotV2::decode(&format!("{prefix}:{}", hex(changed.as_bytes()))).is_err());
    }
    assert!(SkillSnapshotV2::decode(&format!("{prefix}:{}", value.to_uppercase())).is_err());
    let (prefix, value) = LOAD.trim_end().split_once(':').unwrap();
    let raw = String::from_utf8(hex::decode(value).unwrap()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let end = parsed["byte_end"].as_u64().unwrap();
    for changed in [
        raw.replace("\"result\":\"loaded\"", "\"result\":\"blocked\""),
        raw.replace(&format!("\"byte_end\":{end}"), "\"byte_end\":999999"),
        raw.replace("Review the signed", "Altered the signed"),
    ] {
        assert_ne!(changed, raw);
        assert!(SkillLoadV1::decode(&format!("{prefix}:{}", hex(changed.as_bytes()))).is_err());
    }
}
#[test]
fn skill_provenance_keeps_utf8_ranges_and_methodology_hashes_separate() {
    let snapshot = SkillSnapshotV2::decode(SNAPSHOT.trim_end()).unwrap();
    let package = snapshot.package().unwrap();
    let skill = snapshot.compile(&Compiler).unwrap();
    let resource = irmind_domain::TaintedSkillResource::new(
        skill.metadata().name().clone(),
        skill.metadata().version().clone(),
        &package,
        "SKILL.md",
        skill.body_offset()..package.bytes(),
    )
    .unwrap();
    assert!(resource.untrusted_text().starts_with("# Review"));
    assert_eq!(resource.provenance().package, *package.hash());
    assert!(!format!("{resource:?}").contains("Review the signed synthetic"));
}
fn entry(kind: AuditEventKind, actor: irmind_domain::Actor, payload: String) -> crate::SignedEntry {
    crate::SignedEntry {
        seq: 1,
        case_id: "synthetic".into(),
        at: 0,
        actor,
        origin: "system".into(),
        kind,
        payload,
        evidence: None,
        prev: [0; 32],
        hash: [0; 32],
        sig: Vec::new(),
        public_key: Vec::new(),
    }
}
#[test]
fn receipt_inventory_rejects_wrong_actor_order_evidence_and_turn_budget() {
    use irmind_domain::{Actor, AgentId};
    let agent = Actor::Agent(AgentId::parse("synthetic-agent").unwrap());
    let snapshot = entry(
        AuditEventKind::SkillSnapshotV2,
        Actor::Analyst,
        SNAPSHOT.trim_end().into(),
    );
    let load = entry(AuditEventKind::SkillLoadV1, agent, LOAD.trim_end().into());
    let mut state = SkillReceiptVerifier::default();
    assert!(state.accept(&load, &Compiler).is_err());
    let mut changed = snapshot.clone();
    changed.actor = load.actor.clone();
    assert!(state.accept(&changed, &Compiler).is_err());
    changed = snapshot.clone();
    changed.evidence = Some("11".repeat(32));
    assert!(state.accept(&changed, &Compiler).is_err());
    state.accept(&snapshot, &Compiler).unwrap();
    assert!(state.accept(&snapshot, &Compiler).is_err());
    let mut changed = load.clone();
    changed.actor = Actor::Analyst;
    assert!(state.accept(&changed, &Compiler).is_err());
    for _ in 0..8 {
        state.accept(&load, &Compiler).unwrap();
    }
    assert!(state.accept(&load, &Compiler).is_err());
}
#[test]
fn load_receipts_reject_unknown_resources_invalid_utf8_boundaries_and_missing_admissions() {
    use irmind_domain::{Actor, AgentId};
    let snapshot = entry(
        AuditEventKind::SkillSnapshotV2,
        Actor::Analyst,
        SNAPSHOT.trim_end().into(),
    );
    let mut state = SkillReceiptVerifier::default();
    state.accept(&snapshot, &Compiler).unwrap();
    let decoded = SkillLoadV1::decode(LOAD.trim_end()).unwrap();
    let mut json = serde_json::to_value(&decoded).unwrap();
    json["resource"] = serde_json::json!("references/missing.csv");
    let candidate: SkillLoadV1 = serde_json::from_value(json).unwrap();
    let load = entry(
        AuditEventKind::SkillLoadV1,
        Actor::Agent(AgentId::parse("synthetic-agent").unwrap()),
        candidate.encode().unwrap(),
    );
    assert!(state.accept(&load, &Compiler).is_err());
    assert!(!state.admissions().is_empty());
    let mut json = serde_json::to_value(&decoded).unwrap();
    json["byte_end"] = serde_json::json!(32768);
    let candidate: SkillLoadV1 = serde_json::from_value(json).unwrap();
    let mut load = load;
    load.payload = candidate.encode().unwrap();
    assert!(state.accept(&load, &Compiler).is_err());
}

#[test]
fn bundled_snapshot_requires_exact_compiled_inventory_and_catalog_cannot_shadow_it() {
    let original = SkillSnapshotV2::decode(SNAPSHOT.trim_end()).unwrap();
    let skill = original.compile(&Compiler).unwrap();
    let mut bytes = b"irmind-bundled-skill-inventory-v1\0".to_vec();
    bytes.extend_from_slice(&1u64.to_be_bytes());
    for text in [
        skill.metadata().name().as_str(),
        skill.metadata().version().as_str(),
    ] {
        bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
        bytes.extend_from_slice(text.as_bytes());
    }
    bytes.extend_from_slice(skill.package().hash().as_bytes());
    let inventory = crate::sha256(&bytes);
    let snapshot = SkillSnapshotV2::new(&skill, crate::SkillOrigin::Bundled, inventory);
    let mut state = SkillReceiptVerifier::default();
    state
        .accept(
            &entry(
                AuditEventKind::SkillSnapshotV2,
                irmind_domain::Actor::Analyst,
                snapshot.encode().unwrap(),
            ),
            &Compiler,
        )
        .unwrap();
    state
        .verify_bundled(std::slice::from_ref(skill.package()), &Compiler)
        .unwrap();
    assert!(state.verify_bundled(&[], &Compiler).is_err());
    let snapshot = SkillSnapshotV2::new(&skill, crate::SkillOrigin::Bundled, [5; 32]);
    let mut state = SkillReceiptVerifier::default();
    state
        .accept(
            &entry(
                AuditEventKind::SkillSnapshotV2,
                irmind_domain::Actor::Analyst,
                snapshot.encode().unwrap(),
            ),
            &Compiler,
        )
        .unwrap();
    assert!(
        state
            .verify_bundled(std::slice::from_ref(skill.package()), &Compiler)
            .is_err()
    );
    let catalog =
        include_str!("../../../../../docs/development/catalog-format-vectors/snapshot-v2.json");
    let snapshot: SkillSnapshotV2 = serde_json::from_str(catalog).unwrap();
    let mut state = SkillReceiptVerifier::default();
    state
        .accept(
            &entry(
                AuditEventKind::SkillSnapshotV2,
                irmind_domain::Actor::Analyst,
                snapshot.encode().unwrap(),
            ),
            &Compiler,
        )
        .unwrap();
    assert!(
        state
            .verify_bundled(std::slice::from_ref(skill.package()), &Compiler)
            .is_err()
    );
}

#[test]
fn subagent_skill_reads_share_parent_limits_without_main_branch_substitution() {
    use crate::subagents::{SubagentPlanV1, SubagentRecord};
    let plan = SubagentPlanV1::decode(include_bytes!(
        "../../../../../docs/development/subagent-format-vectors/plan.json"
    ))
    .unwrap();
    let snapshot = SkillSnapshotV2::decode(SNAPSHOT.trim_end()).unwrap();
    let agent = irmind_domain::Actor::Agent(irmind_domain::AgentId::parse("core").unwrap());
    let mut checked = SkillReceiptVerifier::default();
    checked
        .accept(
            &entry(
                AuditEventKind::SkillSnapshotV2,
                irmind_domain::Actor::Analyst,
                snapshot.encode().unwrap(),
            ),
            &Compiler,
        )
        .unwrap();
    let base = SkillLoadV1::decode(LOAD.trim_end()).unwrap();
    let read = |turn: &str| {
        SkillLoadV1::new(SkillReadReceipt {
            snapshot: snapshot.identity().unwrap(),
            turn: uuid::Uuid::parse_str(turn).unwrap(),
            call: "load",
            resource: base.resource(),
            range: base.range().unwrap(),
            guard: base.guard(),
            text: base.text().into(),
            detections: 0,
            result: SkillLoadResult::Loaded,
        })
        .unwrap()
    };
    let parent = read(&plan.turn_id);
    for _ in 0..7 {
        checked
            .accept(
                &entry(
                    AuditEventKind::SkillLoadV1,
                    agent.clone(),
                    parent.encode().unwrap(),
                ),
                &Compiler,
            )
            .unwrap();
    }
    checked
        .accept(
            &entry(
                AuditEventKind::SubagentPlanV1,
                agent.clone(),
                plan.audit_payload().unwrap(),
            ),
            &Compiler,
        )
        .unwrap();
    let child = read(&plan.tasks[0].nonce);
    // A task nonce is accepted only inside its authenticated branch, never in main.
    assert!(
        checked
            .accept(
                &entry(AuditEventKind::SkillLoadV1, agent, child.encode().unwrap()),
                &Compiler
            )
            .is_err()
    );
    assert!(
        checked
            .accept_task_load(&child, &uuid::Uuid::nil().to_string())
            .is_err()
    );
    checked.accept_task_load(&child, &plan.turn_id).unwrap();
    assert!(checked.accept_task_load(&child, &plan.turn_id).is_err());
}

#[test]
fn subagent_method_is_available_only_after_its_main_snapshot() {
    let snapshot = SkillSnapshotV2::decode(SNAPSHOT.trim_end()).unwrap();
    let mut checked = SkillReceiptVerifier::default();
    checked
        .accept(
            &entry(
                AuditEventKind::SkillSnapshotV2,
                irmind_domain::Actor::Analyst,
                snapshot.encode().unwrap(),
            ),
            &Compiler,
        )
        .unwrap();
    assert!(
        checked
            .snapshot_method(snapshot.identity().unwrap(), 1, &Compiler)
            .is_err()
    );
    let (name, tools) = checked
        .snapshot_method(snapshot.identity().unwrap(), 2, &Compiler)
        .unwrap();
    assert_eq!(name, "synthetic-triage");
    assert_eq!(
        tools,
        std::collections::BTreeSet::from(["text_search".into()])
    );
}
