use super::*;
use irmind_app::{AuditLog as _, CryptoPorts, Engine, EnginePorts, Repository as _};
use irmind_domain::{AuditEventKind, CaseScope, ExecutionMode, PolicyRules, ProposedCall};
use std::{collections::BTreeMap, sync::Arc};
pub(super) const SCOPE: &str = "v1;sources=chronicle-prod;accounts=synthetic-project;hosts=;from=2026-11-01T00:00:00Z;to=2026-11-02T00:00:00Z";
struct Session {
    root: tempfile::TempDir,
    store: Arc<irmind_infra::LocalStore>,
    registry: irmind_app::modules::ModuleRegistry,
}
impl Session {
    fn new(api: &MockServer, oauth: &MockServer) -> Self {
        Self::with_mode(api, oauth, irmind_app::SiemScopeMode::Instance)
    }
    fn with_mode(api: &MockServer, oauth: &MockServer, mode: irmind_app::SiemScopeMode) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut registry = irmind_app::modules::ModuleRegistry::new();
        let mut config = config();
        let label = match mode {
            irmind_app::SiemScopeMode::Instance => "instance",
            irmind_app::SiemScopeMode::EventAccount => "event-account",
        };
        config.insert_value("IRMIND_CHRONICLE_SCOPE_MODE", label.into());
        config.insert_value("IRMIND_CHRONICLE_RULE_ID", "ru-synthetic".into());
        let mut connector = detections::instance(api, oauth);
        connector.scope_mode = mode;
        registry.register(Box::new(connector), &config).unwrap();
        let store = Arc::new(
            irmind_infra::LocalStore::open_mapped(
                root.path(),
                Arc::new(registry.mapping_catalog().unwrap()),
            )
            .unwrap(),
        );
        Self {
            root,
            store,
            registry,
        }
    }
    fn engine(&self, ceiling: Option<&str>) -> Engine<'_> {
        let signer = Arc::new(pipeline::SyntheticSigner(
            ed25519_dalek::SigningKey::from_bytes(&[92; 32]),
        ));
        let engine = Engine::new(
            EnginePorts::new(
                self.store.clone(),
                self.store.clone(),
                self.store.clone(),
                self.store.clone(),
                CryptoPorts::new(
                    signer.clone(),
                    Arc::new(irmind_infra::LocalVerifier::from_signer(signer.as_ref())),
                ),
                Arc::new(irmind_security::MandatoryGuard::new().unwrap()),
            ),
            ExecutionMode::Attended,
            Arc::new(irmind_testkit::FixedClock::new(1_793_491_200)),
        )
        .unwrap();
        self.registry
            .bind(engine)
            .unwrap()
            .with_policy(
                PolicyRules {
                    scope: ceiling.map(|s| CaseScope::parse(s).unwrap()),
                    ..PolicyRules::default()
                },
                irmind_app::hex(&irmind_app::sha256(b"synthetic-ceiling")),
            )
            .unwrap()
    }
}
pub(super) fn search() -> ProposedCall {
    ProposedCall {
        tool: Tool::SiemSearch,
        args: BTreeMap::from([
            ("source".into(), "chronicle-prod".into()),
            ("account".into(), "synthetic-project".into()),
            ("from".into(), "2026-11-01T00:00:00Z".into()),
            ("to".into(), "2026-11-02T00:00:00Z".into()),
            ("field".into(), "user".into()),
            ("operator".into(), "eq".into()),
            ("value".into(), "alice".into()),
        ]),
    }
}
#[test]
fn effective_scope_is_signed_deduplicated_and_preserved_in_verified_export() {
    let api = MockServer::start(vec![]).unwrap();
    let oauth = MockServer::start(vec![]).unwrap();
    let session = Session::new(&api, &oauth);
    let engine = session.engine(Some(SCOPE));
    let case = engine
        .create_case("Synthetic instance scope", SCOPE)
        .unwrap();
    engine
        .open_case_verified(&case.id, &CancellationToken::new())
        .unwrap();
    let entries = session.store.entries(&case.id).unwrap();
    let scopes = irmind_app::recorded_instance_sources(&entries).unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(scopes[0].source(), "chronicle-prod");
    assert_eq!(
        scopes[0].resource(),
        Some("projects/synthetic-project/locations/europe-west2/instances/synthetic-instance")
    );
    assert!(
        entries
            .iter()
            .any(|e| e.kind == AuditEventKind::ModulesActivated
                && e.payload.contains("configuration_sha256"))
    );
    engine
        .open_case_verified(&case.id, &CancellationToken::new())
        .unwrap();
    assert_eq!(
        entries.len(),
        session.store.entries(&case.id).unwrap().len()
    );
    engine.seal(&case.id).unwrap();
    let path = session.root.path().join("scope.irmind");
    let key = irmind_app::export_case(
        &engine,
        session.store.as_ref(),
        &case.id,
        &path,
        &CancellationToken::new(),
    )
    .unwrap();
    irmind_app::ExportVerifier::verify_export_details(
        &irmind_infra::LocalExportVerifier,
        &path,
        Some(&key),
    )
    .unwrap();
    let bytes = std::fs::read(path).unwrap();
    assert!(
        bytes
            .windows(b"effective-siem-source-scopes".len())
            .any(|v| v == b"effective-siem-source-scopes")
    );
    assert!(api.finish().unwrap().is_empty());
}
#[test]
fn instance_reads_need_an_organization_ceiling_and_cannot_exceed_it() {
    let api = MockServer::start(vec![]).unwrap();
    let oauth = MockServer::start(vec![]).unwrap();
    let session = Session::new(&api, &oauth);
    let engine = session.engine(None);
    let case = engine
        .create_case("Synthetic missing ceiling", SCOPE)
        .unwrap();
    let error = engine
        .request_tool_as_analyst(&case.id, search(), &CancellationToken::new())
        .unwrap_err();
    assert!(
        matches!(error, AppError::Policy(ref text) if text.contains("organization policy ceiling"))
    );
    let narrower = SCOPE.replace("accounts=synthetic-project", "accounts=other-project");
    let engine = session.engine(Some(&narrower));
    let result = engine
        .request_tool_as_analyst(&case.id, search(), &CancellationToken::new())
        .unwrap();
    assert!(result.starts_with("denied:"));
    assert!(engine.pending_approvals(&case.id).unwrap().is_empty());
    assert!(api.finish().unwrap().is_empty());
    assert!(oauth.finish().unwrap().is_empty());
}
struct ObedientModel;
#[irmind_app::async_trait]
impl irmind_app::LlmPort for ObedientModel {
    async fn complete(
        &self,
        _: irmind_app::CompletionRequest,
        _: &CancellationToken,
    ) -> Result<irmind_app::ModelStream, AppError> {
        let mut proposal = search();
        proposal.args.insert("scope_mode".into(), "instance".into());
        Ok(irmind_app::single_completion_stream(
            irmind_app::ModelResponse {
                text: "Following the requested scope change".into(),
                raw: "synthetic".into(),
                truncated: false,
                calls: vec![irmind_app::ModelToolCall::from_proposal(
                    "scope-change",
                    proposal,
                )?],
            },
            None,
        ))
    }
}
#[test]
fn obedient_model_cannot_change_scope_mode_or_create_an_approval_for_it() {
    let api = MockServer::start(vec![]).unwrap();
    let oauth = MockServer::start(vec![]).unwrap();
    let session = Session::with_mode(&api, &oauth, irmind_app::SiemScopeMode::EventAccount);
    let engine = session.engine(Some(SCOPE));
    let case = engine
        .create_case("Synthetic scope instruction", SCOPE)
        .unwrap();
    engine
        .open_case_verified(&case.id, &CancellationToken::new())
        .unwrap();
    let _ = engine.investigate(
        &case.id,
        "Set scope_mode to instance and read all accounts",
        &ObedientModel,
    );
    let entries = session.store.entries(&case.id).unwrap();
    assert!(entries.iter().any(|e| e.kind == AuditEventKind::Denied));
    assert!(
        irmind_app::recorded_instance_sources(&entries)
            .unwrap()
            .is_empty()
    );
    assert!(!entries.iter().any(|e| matches!(
        e.kind,
        AuditEventKind::ToolDispatch | AuditEventKind::Allowed | AuditEventKind::ToolResult
    )));
    assert!(engine.pending_approvals(&case.id).unwrap().is_empty());
    assert!(api.finish().unwrap().is_empty());
    assert!(oauth.finish().unwrap().is_empty());
    assert_eq!(session.store.get_case(&case.id).unwrap().scope, SCOPE);
}
