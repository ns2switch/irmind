use super::{BudgetModel, limits, setup};
use irmind_app::{AuditLog, CaseMutation, SignedEntry, sha256};
use irmind_domain::{Actor, AuditEventKind, Case, CaseId, Severity};

#[test]
fn missing_allocation_requires_explicit_initialization_without_resetting_usage() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let case = create_unallocated_case(&engine, store.as_ref());
    engine.verify(&case.id).unwrap();
    assert!(engine.case_budget(&case.id).unwrap().allocated.is_none());
    let model = BudgetModel {
        requests: std::sync::Mutex::default(),
        output: Some("Synthetic reply."),
        usage: Some(irmind_app::ModelUsage {
            input_tokens: 8,
            output_tokens: 2,
        }),
    };
    assert!(
        engine
            .investigate(&case.id, "Review this case.", &model)
            .unwrap_err()
            .to_string()
            .contains("/budget")
    );
    assert!(model.requests.lock().unwrap().is_empty());
    assert!(
        engine
            .change_case_budget(&case.id, limits(2_000, 5), false)
            .is_err()
    );
    assert!(engine.case_budget(&case.id).unwrap().allocated.is_none());
    engine
        .change_case_budget(&case.id, limits(2_000, 5), true)
        .unwrap();
    assert_eq!(engine.case_budget(&case.id).unwrap().usage.model_tokens, 10);
    engine
        .investigate(&case.id, "Review this case.", &model)
        .unwrap();
    let status = engine.case_budget(&case.id).unwrap();
    assert_eq!(status.allocated, Some(limits(2_000, 5)));
    assert_eq!(status.usage.model_tokens, 20);
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let destination = root.path().join("initialized-budget.irmind");
    let key = irmind_app::export_case_with_originals(
        &engine,
        store.as_ref(),
        &case.id,
        &destination,
        None,
        false,
        &irmind_app::CancellationToken::new(),
    )
    .unwrap();
    irmind_app::verify_export_details(&irmind_infra::LocalExportVerifier, &destination, Some(&key))
        .unwrap();
    if std::env::var_os("IRMIND_REFRESH_SKILL_EXPORT_SEEDS").is_some() {
        std::fs::copy(
            destination,
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fuzz/seeds/export/valid-v7-budget-initialization.irmind"),
        )
        .unwrap();
    }
}

fn create_unallocated_case(
    engine: &irmind_app::Engine<'_>,
    store: &irmind_infra::LocalStore,
) -> Case {
    let case = Case {
        id: CaseId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        title: "Synthetic unallocated case".into(),
        severity: Severity::Medium,
        scope: "local".into(),
        sealed: false,
    };
    let mut previous = None;
    for (kind, payload) in [
        (
            AuditEventKind::CaseCreated,
            r#"{"version":3,"title":"Synthetic unallocated case","severity":"medium","scope":"local"}"#,
        ),
        (AuditEventKind::ModelRequest, "synthetic prior request"),
        (AuditEventKind::ModelReply, "synthetic prior response"),
        (
            AuditEventKind::ModelUsage,
            r#"{"input_tokens":8,"output_tokens":2,"estimated_cost_microusd":null}"#,
        ),
    ] {
        let prior: Option<&SignedEntry> = previous.as_ref();
        let mut entry = SignedEntry {
            seq: prior.map_or(1, |e| e.seq + 1),
            case_id: case.id.as_str().into(),
            at: 0,
            actor: Actor::Analyst,
            origin: "System".into(),
            kind,
            payload: payload.into(),
            evidence: None,
            prev: prior.map_or([0; 32], |e| e.hash),
            hash: [0; 32],
            sig: vec![],
            public_key: engine.signer.public_key(),
        };
        entry.hash = sha256(&entry.canonical());
        entry.sig = engine.signer.sign(&entry.hash).unwrap();
        if kind == AuditEventKind::CaseCreated {
            store
                .transact(&entry, CaseMutation::Create(case.clone()))
                .unwrap();
        } else {
            store.append(&entry).unwrap();
        }
        previous = Some(entry);
    }
    case
}
