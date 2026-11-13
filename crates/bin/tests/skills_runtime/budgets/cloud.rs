use super::*;
use irmind_app::{
    CompletionRequest, LlmPort, ModelEvent, ModelResponse, ModelStream, ModelToolCall, ObjectEntry,
    ObjectSource, ObjectSourceOutput,
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
const URI: &str = "s3://synthetic-budget/logs/source.json";
struct ListingOnly(AtomicUsize);
#[irmind_app::async_trait]
impl ObjectSource for ListingOnly {
    fn source_id(&self) -> &'static str {
        "storage"
    }
    async fn execute(
        &self,
        call: &irmind_domain::AuthorizedCall,
        _: &CancellationToken,
    ) -> Result<ObjectSourceOutput, irmind_app::AppError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        assert_eq!(call.tool(), &Tool::ObjectList, "no transfer may start");
        Ok(ObjectSourceOutput::Listing {
            objects: vec![ObjectEntry {
                uri: URI.into(),
                key: "logs/source.json".into(),
                size: 512,
                modified_unix_seconds: Some(1_792_756_800),
                version: Some("v1".into()),
                provider_checksum: None,
            }],
            total_bytes: 512,
            truncated: false,
        })
    }
}
fn proposal(tool: Tool) -> ProposedCall {
    let mut args = BTreeMap::from([
        ("source".into(), "storage".into()),
        ("scheme".into(), "s3".into()),
        ("container".into(), "synthetic-budget".into()),
        ("from".into(), "2026-10-23T00:00:00Z".into()),
        ("to".into(), "2026-10-23T23:59:59Z".into()),
    ]);
    if tool == Tool::ObjectList {
        args.insert("prefix".into(), "logs/".into());
        args.insert("limit".into(), "20".into());
    } else {
        args.insert("key".into(), "logs/source.json".into());
        args.insert("version".into(), "v1".into());
        args.insert("max_bytes".into(), "1024".into());
    }
    ProposedCall { tool, args }
}
struct CloudModel(Mutex<Vec<CompletionRequest>>);
#[irmind_app::async_trait]
impl LlmPort for CloudModel {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, irmind_app::AppError> {
        request.validate()?;
        let final_only = request.tools.is_empty();
        self.0.lock().unwrap().push(request);
        let calls = if final_only {
            vec![]
        } else {
            vec![
                ModelToolCall::from_proposal("cloud-budget-read", proposal(Tool::ObjectRead))?,
                ModelToolCall::from_proposal(
                    "must-not-run-after-limit",
                    ProposedCall {
                        tool: Tool::GraphSummary,
                        args: BTreeMap::new(),
                    },
                )?,
            ]
        };
        Ok(Box::pin(futures_util::stream::iter([Ok(
            ModelEvent::Completed {
                response: ModelResponse {
                    text: if final_only {
                        "The listed source remains available; transfer was not started.".into()
                    } else {
                        String::new()
                    },
                    raw: "synthetic cloud allocation response".into(),
                    calls,
                    truncated: false,
                },
                usage: Some(irmind_app::ModelUsage {
                    input_tokens: 8,
                    output_tokens: 2,
                }),
            },
        )])))
    }
}
#[test]
fn cloud_allocation_stops_before_transfer_and_finishes_without_tools() {
    let root = tempfile::tempdir().unwrap();
    let (store, engine) = setup(root.path());
    let source = ListingOnly(AtomicUsize::new(0));
    let engine = engine
        .with_large_case_pipeline(
            store.clone(),
            std::sync::Arc::new(irmind_mod_parser_json::JsonParser),
        )
        .with_object_source(&source)
        .unwrap()
        .with_case_budget_defaults(CaseBudgetLimits {
            cloud_bytes: 64,
            ..limits(2000, 20)
        })
        .unwrap();
    let scope = "v3;sources=storage;accounts=;projects=;hosts=;objects=s3://synthetic-budget/logs/;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
    let case = engine
        .create_case("Synthetic cloud allocation", scope)
        .unwrap();
    engine
        .request_tool_as_analyst(
            &case.id,
            proposal(Tool::ObjectList),
            &CancellationToken::new(),
        )
        .unwrap();
    let model = CloudModel(Mutex::default());
    let answer = engine
        .investigate(&case.id, "Read the listed synthetic source.", &model)
        .unwrap();
    assert!(answer.contains("transfer was not started"));
    assert!(answer.contains("case cloud transfer limit"));
    assert!(answer.contains("/budget"));
    assert_eq!(source.0.load(Ordering::SeqCst), 1);
    let requests = model.0.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].tools.is_empty());
    assert!(
        requests[1]
            .messages
            .iter()
            .any(|m| m.content.contains("1024 requested, limit 64"))
    );
    let status = engine.case_budget(&case.id).unwrap();
    assert_eq!(status.usage.cloud_bytes, 0);
    assert_eq!(status.usage.tool_calls, 1);
    assert!(
        !store
            .entries(&case.id)
            .unwrap()
            .iter()
            .any(|e| e.kind == AuditEventKind::Allowed && e.payload.contains("graph_summary"))
    );
    engine.verify(&case.id).unwrap();
}
