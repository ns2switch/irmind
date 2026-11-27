use super::{BudgetModel, limits, setup};
use irmind_app::{AuditLog, CaseMutation, SignedEntry, sha256};
use irmind_domain::{Actor, AuditEventKind, Case, CaseId, Severity};

#[test]
fn missing_initial_allocation_cannot_open_verify_or_export() {
    for current in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (store, engine) = setup(root.path());
        let case = create_unallocated_case(&engine, store.as_ref(), current);
        let before = store.last_entry(&case.id).unwrap().unwrap();
        let cancel = irmind_app::CancellationToken::new();
        let error = engine.open_case_verified(&case.id, &cancel).unwrap_err();
        if !current {
            assert!(matches!(
                error,
                irmind_app::AppError::Fixed(irmind_app::FixedAppError::CaseFormat(
                    irmind_app::case_format::CaseFormatError::Case(Some(6)),
                ))
            ));
        }
        assert!(engine.verify(&case.id).is_err());
        assert!(
            engine
                .change_case_budget(&case.id, limits(2_000, 5), true)
                .is_err()
        );
        let destination = root.path().join("unsupported.irmind");
        assert!(
            irmind_app::export_case_with_originals(
                &engine,
                store.as_ref(),
                &case.id,
                &destination,
                None,
                false,
                &cancel
            )
            .is_err()
        );
        assert!(!destination.exists());
        let after = store.last_entry(&case.id).unwrap().unwrap();
        assert_eq!((after.seq, after.hash), (before.seq, before.hash));
        let model = BudgetModel {
            requests: std::sync::Mutex::default(),
            output: Some("Synthetic reply."),
            usage: None,
        };
        assert!(engine.investigate(&case.id, "Hello", &model).is_err());
        assert!(model.requests.lock().unwrap().is_empty());
    }
}

fn create_unallocated_case(
    engine: &irmind_app::Engine<'_>,
    store: &irmind_infra::LocalStore,
    current: bool,
) -> Case {
    let case = Case {
        id: CaseId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        title: "Synthetic unallocated case".into(),
        severity: Severity::Medium,
        scope: "local".into(),
        sealed: false,
    };
    let created = format!(
        r#"{{"version":{},"title":"Synthetic unallocated case","severity":"medium","scope":"local"}}"#,
        if current { 7 } else { 6 }
    );
    let mut previous = None;
    for (kind, payload) in [
        (AuditEventKind::CaseCreated, created.as_str()),
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
            origin: "system".into(),
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
