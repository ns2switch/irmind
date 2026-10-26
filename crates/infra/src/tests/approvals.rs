#[test]
fn agent_signature_cannot_resolve_analyst_approval() {
    let analyst = SigningKey::from_bytes(&[11u8; 32]);
    let agent = SigningKey::from_bytes(&[12u8; 32]);
    let case = Case {
        id: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
        title: "x".into(),
        severity: Severity::Medium,
        scope: "local".into(),
        sealed: false,
    };
    let proposal = ProposedCall {
        tool: Tool::ThreatIntelExternal,
        args: BTreeMap::from([("ioc".into(), "example.com".into())]),
    };
    let Decision::NeedsApproval(pending) = evaluate(
        &case,
        proposal.clone(),
        2,
        ExecutionMode::Unattended,
        1_700_000_000,
    ) else {
        panic!("expected pending approval");
    };
    let challenge = pending.challenge();
    let verifier = LocalAnalystVerifier(analyst.verifying_key());
    assert!(
        pending
            .resolve(&agent.sign(&challenge).to_bytes(), &verifier, 1_700_000_000)
            .is_err()
    );
    let Decision::NeedsApproval(pending) =
        evaluate(&case, proposal, 2, ExecutionMode::Unattended, 1_700_000_000)
    else {
        panic!("expected pending approval");
    };
    assert!(
        pending
            .resolve(
                &analyst.sign(&challenge).to_bytes(),
                &verifier,
                1_700_000_000
            )
            .is_ok()
    );
    let Decision::NeedsApproval(pending) = evaluate(
        &case,
        ProposedCall {
            tool: Tool::ThreatIntelExternal,
            args: BTreeMap::from([("ioc".into(), "example.com".into())]),
        },
        2,
        ExecutionMode::Unattended,
        1_700_000_000,
    ) else {
        panic!("expected pending approval");
    };
    let recovered = irmind_domain::PendingApproval::recover(
        &case,
        ExecutionMode::Unattended,
        &pending.challenge(),
        1_700_000_000,
    )
    .unwrap();
    assert_eq!(recovered.challenge(), pending.challenge());
    assert!(
        pending
            .reject(
                &agent.sign(&recovered.rejection_challenge()).to_bytes(),
                &verifier
            )
            .is_err()
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn analyst_resolves_persistent_agent_requests_without_external_execution() {
    let root = tempfile::tempdir().unwrap();
    let analyst_key = SigningKey::from_bytes(&[51u8; 32]);
    let agent_key = SigningKey::from_bytes(&[52u8; 32]);
    let analyst = Arc::new(TestSigner {
        actor: Actor::Analyst,
        key: analyst_key,
    });
    let agent = Arc::new(TestSigner {
        actor: Actor::Agent(irmind_domain::AgentId::parse("watcher-1").unwrap()),
        key: agent_key,
    });
    let guard = Arc::new(MandatoryGuard::new().unwrap());
    let parser = Arc::new(JsonParser);
    let case_id = {
        let store = Arc::new(LocalStore::open(root.path()).unwrap());
        let attended = Engine::new(
            EnginePorts::new(
                store.clone(),
                store.clone(),
                store.clone(),
                store.clone(),
                CryptoPorts::new(
                    analyst.clone(),
                    Arc::new(
                        LocalVerifier::from_signer(analyst.as_ref())
                            .with_trusted_key(&agent.actor(), &agent.public_key())
                            .unwrap(),
                    ),
                ),
                guard.clone(),
                parser.clone(),
            ),
            ExecutionMode::Attended,
            Arc::new(SystemClock),
        )
        .unwrap();
        let unattended = Engine::new(
            EnginePorts::new(
                store.clone(),
                store.clone(),
                store.clone(),
                store.clone(),
                CryptoPorts::new(
                    agent.clone(),
                    Arc::new(
                        LocalVerifier::from_signer(analyst.as_ref())
                            .with_trusted_key(&agent.actor(), &agent.public_key())
                            .unwrap(),
                    ),
                ),
                guard.clone(),
                parser.clone(),
            ),
            ExecutionMode::Unattended,
            Arc::new(SystemClock),
        )
        .unwrap();
        let case = attended.create_case("Approval", "local evidence").unwrap();
        let model = ObedientModel {
            seen: Mutex::new(Vec::new()),
        };
        unattended
            .investigate(&case.id, "Investigate", &model)
            .unwrap();
        let pending = attended.pending_approvals(&case.id).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tool, Tool::ThreatIntelExternal);
        assert_eq!(
            pending[0].args.get("ioc").map(String::as_str),
            Some("attacker.example")
        );
        assert!(attended.seal(&case.id).is_err());
        assert!(unattended.approve(&case.id, &pending[0].id).is_err());
        case.id
    };
    let reopened = Arc::new(LocalStore::open(root.path()).unwrap());
    let attended = Engine::new(
        EnginePorts::new(
            reopened.clone(),
            reopened.clone(),
            reopened.clone(),
            reopened.clone(),
            CryptoPorts::new(
                analyst.clone(),
                Arc::new(
                    LocalVerifier::from_signer(analyst.as_ref())
                        .with_trusted_key(&agent.actor(), &agent.public_key())
                        .unwrap(),
                ),
            ),
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let unattended = Engine::new(
        EnginePorts::new(
            reopened.clone(),
            reopened.clone(),
            reopened.clone(),
            reopened.clone(),
            CryptoPorts::new(
                agent.clone(),
                Arc::new(
                    LocalVerifier::from_signer(analyst.as_ref())
                        .with_trusted_key(&agent.actor(), &agent.public_key())
                        .unwrap(),
                ),
            ),
            guard.clone(),
            parser.clone(),
        ),
        ExecutionMode::Unattended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let first = attended.pending_approvals(&case_id).unwrap().remove(0);
    assert!(
        attended
            .approve(&case_id, &first.id)
            .unwrap()
            .contains("no request was sent")
    );
    assert!(attended.approve(&case_id, &first.id).is_err());
    assert!(attended.pending_approvals(&case_id).unwrap().is_empty());
    let model = ObedientModel {
        seen: Mutex::new(Vec::new()),
    };
    unattended
        .investigate(&case_id, "Investigate again", &model)
        .unwrap();
    let second = attended.pending_approvals(&case_id).unwrap().remove(0);
    let before_invalid = reopened.entries(&case_id).unwrap().len();
    assert!(
        attended
            .edit_approval(
                &case_id,
                &second.id,
                BTreeMap::from([("unexpected".into(), "value".into())])
            )
            .is_err()
    );
    assert!(
        unattended
            .edit_approval(
                &case_id,
                &second.id,
                BTreeMap::from([("ioc".into(), "edited.example".into())])
            )
            .is_err()
    );
    assert_eq!(reopened.entries(&case_id).unwrap().len(), before_invalid);
    assert!(
        attended
            .edit_approval(
                &case_id,
                &second.id,
                BTreeMap::from([("ioc".into(), "edited.example".into())])
            )
            .unwrap()
            .contains("no tool was executed")
    );
    let replacement = attended.pending_approvals(&case_id).unwrap().remove(0);
    assert_ne!(replacement.id, second.id);
    assert_eq!(replacement.mode, ExecutionMode::Unattended);
    assert_eq!(
        replacement.args.get("ioc").map(String::as_str),
        Some("edited.example")
    );
    assert!(attended.approve(&case_id, &second.id).is_err());
    assert!(
        attended
            .deny(&case_id, &replacement.id, "out of scope")
            .is_ok()
    );
    assert!(attended.pending_approvals(&case_id).unwrap().is_empty());
    let entries = reopened.entries(&case_id).unwrap();
    assert!(entries.iter().any(|entry| entry.kind
        == irmind_domain::AuditEventKind::ApprovalGranted
        && entry.actor == Actor::Analyst));
    assert!(entries.iter().any(|entry| entry.kind
        == irmind_domain::AuditEventKind::ApprovalDenied
        && entry.actor == Actor::Analyst));
    assert!(entries.iter().any(
        |entry| entry.kind == irmind_domain::AuditEventKind::Proposal && entry.origin == "analyst"
    ));
    assert!(
        !entries
            .iter()
            .any(|entry| entry.kind == irmind_domain::AuditEventKind::ToolResult)
    );
    assert_eq!(attended.verify(&case_id).unwrap(), entries.len());
    attended.seal(&case_id).unwrap();
}
