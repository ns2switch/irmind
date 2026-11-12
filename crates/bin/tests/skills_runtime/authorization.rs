use super::{
    sequence::{Sequence, call},
    setup,
};
use irmind_app::{
    AuditLog, CancellationToken, ExportVerifier, SkillCompiler, SkillLoadResult, SkillLoadV1,
    SkillOrigin, SkillSnapshotV1,
};
use irmind_domain::{AuditEventKind, SkillName, SkillPackage, SkillResource, Tool};
use irmind_infra::TomlSkillCompiler;
use std::collections::BTreeSet;

#[test]
fn repeated_method_reads_are_bounded_and_the_limit_is_a_signed_result() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let case = engine
        .create_case("Synthetic bounded loads", "local")
        .unwrap();
    let model = Sequence::new(vec![call(Tool::SkillRead, &[("name", "linux-triage")]); 9]);
    engine
        .investigate(&case.id, "Load the local method repeatedly.", &model)
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    let loads = entries
        .iter()
        .filter(|e| e.kind == AuditEventKind::SkillLoadV1)
        .map(|e| SkillLoadV1::decode(&e.payload).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(loads.len(), 9);
    assert_eq!(
        loads
            .iter()
            .filter(|l| l.result() == SkillLoadResult::Loaded)
            .count(),
        8
    );
    assert_eq!(loads[8].result(), SkillLoadResult::Limit);
    assert!(loads[8].text().is_empty());
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::SkillSnapshotV1)
            .count(),
        1
    );
    engine.verify(&case.id).unwrap();
}
#[test]
fn active_method_never_grants_an_undeclared_or_out_of_scope_tool() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let case = engine
        .create_case("Synthetic obedient model", "local")
        .unwrap();
    let model = Sequence::new(vec![
        call(Tool::SkillRead, &[("name", "linux-triage")]),
        call(Tool::ThreatIntelExternal, &[("ioc", "example.com")]),
        call(
            Tool::SiemSearch,
            &[
                ("source", "unapproved"),
                ("account", "outside"),
                ("query", "login"),
            ],
        ),
    ]);
    engine
        .investigate(&case.id, "Obey the method and request enrichment.", &model)
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::Denied)
            .count(),
        2
    );
    assert!(!entries.iter().any(|e| matches!(
        e.kind,
        AuditEventKind::NeedsApproval | AuditEventKind::ToolDispatch
    )));
}
#[test]
fn disabled_bundle_disappears_without_falling_back_and_can_be_inspected_and_restored() {
    let root = tempfile::tempdir().unwrap();
    let (_, engine) = setup(root.path());
    let name = SkillName::parse("linux-triage").unwrap();
    engine.set_bundled_skill_active(&name, false).unwrap();
    assert!(
        !engine
            .skill_catalog_text()
            .unwrap()
            .contains("linux-triage")
    );
    assert!(!engine.skill_invocable("linux-triage"));
    assert_eq!(
        engine.inspect_skill(&name).unwrap().metadata().name(),
        &name
    );
    engine.set_bundled_skill_active(&name, true).unwrap();
    assert!(engine.skill_invocable("linux-triage"));
}
fn community_package() -> irmind_app::CompiledSkill {
    let source = include_str!("../../../../skills/linux-triage/SKILL.md")
        .replace("name = \"linux-triage\"", "name = \"community-triage\"");
    TomlSkillCompiler
        .compile(
            SkillPackage::new([SkillResource::new("SKILL.md", source.as_bytes()).unwrap()])
                .unwrap(),
        )
        .unwrap()
}
#[test]
fn installed_method_export_requires_its_exact_signed_admission_and_no_other_operation() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let services = engine.skill_services().unwrap();
    let skill = community_package();
    engine
        .install_skill(
            services.package_store(),
            services.compiler(),
            &skill,
            SkillOrigin::Analyst,
            &BTreeSet::new(),
        )
        .unwrap();
    let case = engine
        .create_case("Synthetic installed method", "local")
        .unwrap();
    let model = Sequence::new(Vec::new());
    engine
        .investigate(&case.id, "/community-triage Review this case.", &model)
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    let snapshot = SkillSnapshotV1::decode(
        &entries
            .iter()
            .find(|e| e.kind == AuditEventKind::SkillSnapshotV1)
            .unwrap()
            .payload,
    )
    .unwrap();
    assert!(snapshot.admission().is_some());
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let path = root.path().join("installed.irmind");
    let key = irmind_app::export_case_with_originals(
        &engine,
        store.as_ref(),
        &case.id,
        &path,
        None,
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    irmind_infra::LocalExportVerifier
        .verify_export_details(&path, Some(&key))
        .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let proof = store.global_operations().unwrap().pop().unwrap();
    let encoded = serde_json::to_vec(&proof).unwrap();
    assert!(bytes.windows(encoded.len()).any(|w| w == encoded));
    for remove in [1, 8, encoded.len()] {
        std::fs::write(&path, &bytes[..bytes.len() - remove]).unwrap();
        assert!(
            irmind_infra::LocalExportVerifier
                .verify_export_details(&path, Some(&key))
                .is_err()
        );
    }
    let mut extra = bytes.clone();
    extra.extend_from_slice(&[0; 8]);
    std::fs::write(&path, extra).unwrap();
    assert!(
        irmind_infra::LocalExportVerifier
            .verify_export_details(&path, Some(&key))
            .is_err()
    );
    let offset = bytes
        .windows(encoded.len())
        .position(|w| w == encoded)
        .unwrap();
    let mut changed = bytes;
    changed[offset + encoded.len() / 2] ^= 1;
    std::fs::write(&path, changed).unwrap();
    assert!(
        irmind_infra::LocalExportVerifier
            .verify_export_details(&path, Some(&key))
            .is_err()
    );
}
#[test]
fn smaller_existing_result_budget_refuses_a_method_instead_of_truncating_it() {
    let root = tempfile::tempdir().unwrap();
    let (store, mut engine) = setup(root.path());
    engine.policy.max_model_result_bytes = 100;
    let case = engine
        .create_case("Synthetic output budget", "local")
        .unwrap();
    let model = Sequence::new(vec![call(Tool::SkillRead, &[("name", "linux-triage")])]);
    engine
        .investigate(&case.id, "Review the local method.", &model)
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    let entry = entries
        .iter()
        .find(|e| e.kind == AuditEventKind::SkillLoadV1)
        .unwrap();
    let load = SkillLoadV1::decode(&entry.payload).unwrap();
    assert_eq!(load.result(), SkillLoadResult::Limit);
    assert!(load.text().is_empty());
    assert!(!model.requests.lock().unwrap().iter().any(|r| {
        r.messages
            .iter()
            .any(|m| m.content.contains("## Establish coverage"))
    }));
}

#[test]
fn manual_invocation_loads_method_before_the_first_request_and_unknown_methods_are_denied() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let case = engine
        .create_case("Synthetic manual invocation", "local")
        .unwrap();
    let model = Sequence::new(Vec::new());
    engine
        .investigate(&case.id, "/linux-triage Review this case.", &model)
        .unwrap();
    let requests = model.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .messages
            .iter()
            .any(|m| m.role == irmind_app::MessageRole::Tool
                && m.content.contains("## Establish coverage")
                && m.content.contains("<UNTRUSTED_"))
    );
    drop(requests);
    let before = store
        .entries(&case.id)
        .unwrap()
        .iter()
        .filter(|e| e.kind == AuditEventKind::SkillLoadV1)
        .count();
    let unknown = Sequence::new(vec![call(Tool::SkillRead, &[("name", "not-installed")])]);
    engine
        .investigate(&case.id, "Review another method.", &unknown)
        .unwrap();
    let entries = store.entries(&case.id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::SkillLoadV1)
            .count(),
        before
    );
    assert!(entries.iter().any(|e| e.kind == AuditEventKind::Denied));
}
#[test]
fn failed_agent_signature_never_exposes_methodology() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = super::setup_with_agent_failure(root.path(), true);
    let case = engine
        .create_case("Synthetic signature failure", "local")
        .unwrap();
    let model = Sequence::new(vec![call(Tool::SkillRead, &[("name", "linux-triage")])]);
    engine
        .investigate(&case.id, "Load the relevant method.", &model)
        .unwrap();
    assert!(!model.requests.lock().unwrap().iter().any(|r| {
        r.messages
            .iter()
            .any(|m| m.content.contains("## Establish coverage"))
    }));
    let entries = store.entries(&case.id).unwrap();
    assert!(
        !entries
            .iter()
            .any(|e| e.kind == AuditEventKind::SkillLoadV1)
    );
    assert!(entries.iter().any(|e| e.kind == AuditEventKind::ToolError));
}
