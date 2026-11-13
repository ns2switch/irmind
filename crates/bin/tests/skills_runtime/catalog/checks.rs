use super::{Scenario, model::Episode};
use irmind_app::{
    CancellationToken, Engine, EvidenceGraph, ExportVerifier, FindingKind, MessageRole,
};
use irmind_domain::{Actor, AuditEventKind, Case, CaseId};
use irmind_infra::LocalStore;
use std::path::Path;

pub(super) fn requests(scenario: &Scenario, model: &Episode) {
    let requests = model.requests.lock().unwrap();
    assert_eq!(requests.len(), 7);
    assert!(
        requests[0]
            .messages
            .iter()
            .any(|m| m.content.contains(scenario.name))
    );
    assert!(
        !requests[0]
            .messages
            .iter()
            .any(|m| m.content.contains("## Establish coverage"))
    );
    assert!(
        requests[1]
            .messages
            .iter()
            .any(|m| m.content.contains("## Establish coverage")
                && m.content.contains("<UNTRUSTED_")
                && m.role == MessageRole::Tool)
    );
    for (index, request) in requests.iter().enumerate() {
        for message in &request.messages {
            assert!(
                !message
                    .content
                    .contains("EXPANDED_SKILLS_EVALUATOR_ONLY_7b249")
            );
            if message.role == MessageRole::System {
                for external in [
                    "Synthetic catalog episode",
                    "## Establish coverage",
                    "CreateServiceAccountKey",
                    "vssadmin",
                ] {
                    assert!(!message.content.contains(external));
                }
            }
        }
        if index > 0 {
            assert!(
                !request
                    .tools
                    .iter()
                    .any(|t| t.name.starts_with("ti_") || t.name.starts_with("siem_"))
            );
        }
    }
}

pub(super) fn evaluate(scenario: &Scenario, engine: &Engine<'_>, store: &LocalStore, id: &CaseId) {
    // The independent evaluator opens private answers only after the final model reply.
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../testkit/fixtures/skills-expanded/private/ground-truth.json"
    ))
    .unwrap();
    let expected = &expected["episodes"][scenario.name];
    let findings = engine.findings(id).unwrap();
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .any(|f| f.kind == FindingKind::Hypothesis && f.value == expected["conclusion"])
    );
    assert!(
        findings
            .iter()
            .any(|f| f.kind == FindingKind::Technique && f.value == expected["technique"])
    );
    for finding in findings {
        assert!(!finding.confirmed);
        engine.confirm_finding(id, &finding.id).unwrap();
    }
    let report = engine.report(id).unwrap();
    assert!(report.contains(expected["conclusion"].as_str().unwrap()));
    let entries = engine.audit_log.entries(id).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.kind == AuditEventKind::SkillLoadV1 && matches!(e.actor, Actor::Agent(_)))
            .count(),
        1
    );
    assert!(
        !entries
            .iter()
            .any(|e| e.payload.contains("EXPANDED_SKILLS_EVALUATOR_ONLY_7b249"))
    );
    if scenario.name.starts_with("azure-") || scenario.name.starts_with("gcp-") {
        hunteval(store, id, scenario.name.starts_with("azure-"));
    }
}

fn hunteval(store: &LocalStore, id: &CaseId, azure: bool) {
    let truth = if azure {
        include_str!(
            "../../../../testkit/fixtures/skills-expanded/private/hunteval-azure-ground-truth.json"
        )
    } else {
        include_str!(
            "../../../../testkit/fixtures/skills-expanded/private/hunteval-gcp-ground-truth.json"
        )
    };
    let expected: serde_json::Value = serde_json::from_str(truth).unwrap();
    let (public, hash) = if azure {
        (
            include_str!(
                "../../../../testkit/fixtures/skills-expanded/azure-entra-identity-compromise/source/hunteval.json"
            ),
            "6eae0dadfb042e9beeed048d5ee8e84daa727d0e0d204ccf46def638c2dea6ad",
        )
    } else {
        (
            include_str!(
                "../../../../testkit/fixtures/skills-expanded/gcp-service-account-abuse/source/hunteval.json"
            ),
            "9f5dc4a91c5b7347062107c2021224e1fd48bde5145304f4e0e9558269333452",
        )
    };
    assert_eq!(
        irmind_app::hex(&irmind_app::sha256(public.as_bytes())),
        hash
    );
    let records: Vec<serde_json::Value> = serde_json::from_str(public).unwrap();
    let timeline = store.entity_timeline(id, "ip", "203.0.113.77", 20).unwrap();
    for event in expected["malicious_event_ids"].as_array().unwrap() {
        let index = records
            .iter()
            .position(|r| r["event_id"] == *event)
            .unwrap();
        let reference = format!("{hash}#{index}");
        let result = store.text_search(id, event.as_str().unwrap(), 20).unwrap();
        assert!(result.contains(&reference), "{result}");
        assert!(timeline.contains(&reference), "{timeline}");
        assert!(
            store
                .raw_record(id, hash, index)
                .unwrap()
                .contains(event.as_str().unwrap())
        );
    }
    for entity in expected["malicious_entity_ids"].as_array().unwrap() {
        let result = store.text_search(id, entity.as_str().unwrap(), 20).unwrap();
        assert!(result.contains(hash), "{result}");
    }
}

pub(super) fn export(
    engine: &Engine<'_>,
    store: &LocalStore,
    case: &Case,
    root: &Path,
    count: usize,
) {
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let path = root.join("episode.irmind");
    let key = irmind_app::export_case_with_originals(
        engine,
        store,
        &case.id,
        &path,
        None,
        false,
        &CancellationToken::new(),
    )
    .unwrap();
    let details = irmind_infra::LocalExportVerifier
        .verify_export_details(&path, Some(&key))
        .unwrap();
    assert_eq!(details.format_version, 7);
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_irmind"))
        .arg("--home")
        .arg(root.join("independent-verifier"))
        .arg("verify-export")
        .arg(path)
        .arg("--expected-key")
        .arg(key)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains(&format!("signed source manifests: {count};"))
    );
}
