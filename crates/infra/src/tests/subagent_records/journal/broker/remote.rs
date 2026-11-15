mod objects;
use super::*;
use irmind_app::subagents::{
    TaskEvidenceQueries, TaskEvidenceQuery, TaskEvidenceResult, VerifiedTaskQueryView,
};
use std::sync::Mutex;

const RESPONSE: &[u8] =
    br#"{"Records":[{"eventTime":"2026-11-01T00:00:00Z","eventName":"GetRole","user":"SyntheticRole"}]}"#;
struct Cloud(Mutex<Vec<BTreeMap<String, String>>>);
#[async_trait]
impl CloudAuditPort for Cloud {
    fn source_id(&self) -> &'static str {
        "aws-test"
    }
    async fn execute(
        &self,
        call: &irmind_domain::AuthorizedCall,
        _: &CancellationToken,
    ) -> Result<Vec<u8>, AppError> {
        self.0.lock().unwrap().push(call.proposal_args().clone());
        Ok(RESPONSE.to_vec())
    }
}
struct Views(Mutex<Vec<(SubagentDigest, Vec<String>)>>);
impl TaskEvidenceQueries for Views {
    fn execute(
        &self,
        view: &VerifiedTaskQueryView,
        query: TaskEvidenceQuery,
        _: &CancellationToken,
    ) -> Result<TaskEvidenceResult, AppError> {
        query.validate(view)?;
        self.0
            .lock()
            .unwrap()
            .push((view.task(), view.sources().iter().cloned().collect()));
        Ok(TaskEvidenceResult::Text("Synthetic scoped summary".into()))
    }
}
struct Model {
    outside: bool,
}
#[async_trait]
impl LlmPort for Model {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let independent = request.messages[1].content.contains("Independent");
        let called = |id| {
            request
                .messages
                .iter()
                .any(|message| message.tool_call_id.as_deref() == Some(id))
        };
        let call = if !independent && !called("remote") {
            Some((
                "remote",
                Tool::CloudIdentity,
                BTreeMap::from([
                    ("source".into(), "aws-test".into()),
                    (
                        "account".into(),
                        if self.outside {
                            "999999999999"
                        } else {
                            "123456789012"
                        }
                        .into(),
                    ),
                    ("kind".into(), "role".into()),
                    ("name".into(), "SyntheticRole".into()),
                ]),
            ))
        } else if !called("summary") {
            Some(("summary", Tool::GraphSummary, BTreeMap::new()))
        } else {
            None
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic scoped cloud review".into(),
                calls: call
                    .map(|(id, tool, args)| {
                        ModelToolCall::from_proposal(id, ProposedCall { tool, args }).unwrap()
                    })
                    .into_iter()
                    .collect(),
                raw: "synthetic".into(),
                truncated: false,
            },
            Some(ModelUsage {
                input_tokens: 5,
                output_tokens: 2,
            }),
        ))
    }
}
#[test]
fn remote_read_acquisition_extends_only_its_own_source_view_and_never_approves_wider_scope() {
    for outside in [false, true] {
        let history = History::new();
        let root = tempfile::tempdir().unwrap();
        let views = Arc::new(Views(Mutex::default()));
        let (store, engine) =
            stored_history_engine_with_queries(root.path(), &history, &[], views.clone());
        let cloud = Cloud(Mutex::default());
        let mut registry = ModuleRegistry::new();
        registry
            .register(Box::new(JsonParser), &ModuleConfig::new())
            .unwrap();
        let engine = engine
            .with_cloud_audit(&cloud)
            .unwrap()
            .with_large_case_pipeline(
                Arc::new(ParquetStore::open_mapped(root.path(), source_mapping_catalog()).unwrap()),
                Arc::new(json_source_parser()),
            )
            .with_parser_catalog(registry.parser_catalog());
        let scope = "v1;sources=aws-test;accounts=123456789012;hosts=;from=2026-11-01T00:00:00Z;to=2026-11-01T23:59:59Z";
        engine.change_scope(&history.case, scope).unwrap();
        let mut remote = proposal(100_000);
        remote.type_id = "cloud".into();
        remote.budget.rounds = 3;
        remote.remote_scope = Some(irmind_domain::CaseScope::parse(scope).unwrap());
        let mut independent = proposal(100_000);
        independent.objective = "Independent local review".into();
        let cancel = CancellationToken::new();
        let prepared = engine
            .prepare_subagent_plan(
                &history.case,
                "00000000-0000-0000-0000-000000000009".parse().unwrap(),
                vec![remote, independent],
                SubagentResources::default(),
                &cancel,
            )
            .unwrap();
        let started = engine
            .admit_subagent_plan(
                &prepared,
                &prepared.preview().automatic_start().unwrap(),
                &cancel,
            )
            .unwrap()
            .unwrap();
        let results = engine
            .run_subagent_plan(&started, &Model { outside }, 2, &cancel)
            .unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(cloud.0.lock().unwrap().len(), usize::from(!outside));
        assert!(engine.pending_approvals(&history.case).unwrap().is_empty());
        let views = views.0.lock().unwrap();
        let expected = hex(&sha256(RESPONSE));
        assert!(
            views
                .iter()
                .filter(|(task, _)| *task == started.plan().tasks[1].task_id)
                .all(|(_, sources)| sources.is_empty())
        );
        if !outside {
            assert!(
                views
                    .iter()
                    .any(|(task, sources)| *task == started.plan().tasks[0].task_id
                        && sources == std::slice::from_ref(&expected))
            );
            let entries = store.entries(&history.case).unwrap();
            assert!(
                entries
                    .iter()
                    .any(|entry| entry.kind == AuditEventKind::SourceRecordSetV1
                        && matches!(entry.actor, Actor::Agent(_)))
            );
        }
        drop(views);
        engine.finish_subagent_plan(&started).unwrap();
        tools::verify_and_export(store.as_ref(), &engine, &history, root.path());
    }
}
fn source_mapping_catalog() -> Arc<irmind_app::source_mapping::MappingCatalog> {
    Arc::new(
        irmind_app::source_mapping::MappingCatalog::freeze(
            vec![Arc::new(irmind_mod_parser_json::JsonSourceDecoder)],
            vec![Arc::new(
                irmind_mod_mapping_json_compat::JsonCompatibilityMapping::new().unwrap(),
            )],
        )
        .unwrap(),
    )
}
