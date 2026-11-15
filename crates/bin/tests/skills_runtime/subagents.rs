//! An attended, entirely synthetic Windows/AWS/Kubernetes investigation.
use super::*;
use irmind_app::subagents::{
    AnalystPlanChoice, AnalystPlanInteraction, PortFuture, SafePlanPreview, SubagentResources,
};
use irmind_app::{AuditLog, CaseExporter, LargeCaseUseCases, ModelUsage};
use irmind_domain::AuditEventKind;

struct Review;
impl AnalystPlanInteraction for Review {
    fn review<'a>(
        &'a self,
        preview: &'a SafePlanPreview,
        _: &'a CancellationToken,
    ) -> PortFuture<'a, AnalystPlanChoice> {
        Box::pin(async move {
            assert_eq!(preview.tasks().len(), 3);
            assert!(!preview.confirmation_required());
            preview.automatic_start()
        })
    }
}

struct MixedEpisode {
    hashes: Vec<String>,
    requests: Mutex<Vec<CompletionRequest>>,
}
impl MixedEpisode {
    fn root_calls(&self, request: &CompletionRequest) -> Vec<ModelToolCall> {
        if request
            .messages
            .iter()
            .any(|message| message.tool_call_id.as_deref() == Some("mixed_plan"))
        {
            for hash in &self.hashes {
                assert!(
                    request
                        .messages
                        .iter()
                        .any(|message| message.role == irmind_app::MessageRole::Tool
                            && message.content.contains(hash)
                            && message.content.contains("UNTRUSTED_"))
                );
            }
            return vec![];
        }
        let tasks = [
            ("endpoint", "windows-triage"),
            ("cloud", "aws-credential-compromise"),
            ("kubernetes", "k8s-cluster-compromise"),
        ]
        .into_iter()
        .zip(&self.hashes)
        .map(|((kind, skill), hash)| {
            serde_json::json!({
                "type_id":kind,"objective":format!("Review the assigned synthetic source {hash}"),
                "sources":[hash],"remote_scope":null,"skill":skill,
                "budget":SubagentResources {tokens:40_000,calls:8,rounds:4,cloud_bytes:0}
            })
        })
        .collect::<Vec<_>>();
        vec![
            ModelToolCall::from_proposal(
                "mixed_plan",
                ProposedCall {
                    tool: Tool::DelegateTask,
                    args: BTreeMap::from([(
                        "tasks".into(),
                        serde_json::to_string(&tasks).unwrap(),
                    )]),
                },
            )
            .unwrap(),
        ]
    }
    fn child_calls(&self, request: &CompletionRequest) -> Vec<ModelToolCall> {
        let hash = self
            .hashes
            .iter()
            .find(|hash| request.messages[1].content.contains(hash.as_str()))
            .unwrap();
        let read = request
            .messages
            .iter()
            .any(|m| m.tool_call_id.as_deref() == Some("assigned_original"));
        let found = request
            .messages
            .iter()
            .any(|m| m.tool_call_id.as_deref() == Some("assigned_finding"));
        if found {
            return vec![];
        }
        assert!(
            !request
                .tools
                .iter()
                .any(|tool| tool.name == "delegate_task")
        );
        let (id, tool, args) = if read {
            let original = request
                .messages
                .iter()
                .find(|m| m.tool_call_id.as_deref() == Some("assigned_original"))
                .unwrap();
            assert_eq!(original.role, irmind_app::MessageRole::Tool);
            assert!(
                original.content.contains("UNTRUSTED_")
                    && original.content.contains("view=original verified"),
                "{}",
                original.content
            );
            (
                "assigned_finding",
                Tool::CaseAddFinding,
                BTreeMap::from([
                    ("kind".into(), "hypothesis".into()),
                    ("value".into(), format!("Synthetic source reviewed: {hash}")),
                    ("evidence_hash".into(), hash.clone()),
                    ("supporting_evidence".into(), hash.clone()),
                ]),
            )
        } else {
            (
                "assigned_original",
                Tool::RawRecords,
                BTreeMap::from([
                    ("hash".into(), hash.clone()),
                    ("index".into(), "0".into()),
                    ("view".into(), "original".into()),
                ]),
            )
        };
        vec![ModelToolCall::from_proposal(id, ProposedCall { tool, args }).unwrap()]
    }
}
#[irmind_app::async_trait]
impl LlmPort for MixedEpisode {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let child = request.messages[0]
            .content
            .contains("You are an IRMind subagent");
        for message in request
            .messages
            .iter()
            .filter(|m| m.role == irmind_app::MessageRole::System)
        {
            for hash in &self.hashes {
                assert!(!message.content.contains(hash));
            }
            assert!(!message.content.contains("UNTRUSTED_"));
        }
        let calls = if child {
            self.child_calls(&request)
        } else {
            self.root_calls(&request)
        };
        let text = if child && calls.is_empty() {
            let hash = self
                .hashes
                .iter()
                .find(|hash| request.messages[1].content.contains(hash.as_str()))
                .unwrap();
            format!("Completed synthetic source review {hash}")
        } else if calls.is_empty() {
            "Three synthetic sources reviewed; findings require Analyst confirmation.".into()
        } else {
            "Reviewing the bounded synthetic sources.".into()
        };
        self.requests.lock().unwrap().push(request);
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text,
                calls,
                raw: "scripted".into(),
                truncated: false,
            },
            Some(ModelUsage {
                input_tokens: 10,
                output_tokens: 5,
            }),
        ))
    }
}

#[test]
fn subagents_mixed_windows_aws_kubernetes_episode_reads_real_sources_confirms_and_verifies_v8() {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(crate::current_sources::open(&root.path().join("data")));
    let (_, engine) =
        setup_with_subagents(root.path(), store.clone(), false, Some(Arc::new(Review)));
    let case = engine
        .create_case("Synthetic mixed-source delegation", "local")
        .unwrap();
    let hashes = ingest_sources(root.path(), store.as_ref(), &engine, &case.id);
    let model = MixedEpisode {
        hashes: hashes.clone(),
        requests: Mutex::default(),
    };
    let answer = engine
        .investigate(
            &case.id,
            "Delegate independent reviews of the three synthetic sources, then summarize.",
            &model,
        )
        .unwrap();
    assert!(answer.contains("Three synthetic sources"));
    let requests = model.requests.lock().unwrap();
    assert_eq!(requests.len(), 11);
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.messages[0].content.contains("You are an IRMind subagent"))
            .count(),
        9
    );
    drop(requests);
    let findings = engine.findings(&case.id).unwrap();
    assert_eq!(findings.len(), 3);
    for hash in &hashes {
        let finding = findings
            .iter()
            .find(|finding| &finding.evidence_hash == hash)
            .unwrap();
        assert!(!finding.confirmed);
        engine.confirm_finding(&case.id, &finding.id).unwrap();
    }
    assert!(
        engine
            .findings(&case.id)
            .unwrap()
            .iter()
            .all(|f| f.confirmed)
    );
    let results = store
        .entries(&case.id)
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == AuditEventKind::SubagentResultV1)
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 3);
    for entry in results {
        use irmind_app::subagents::{SubagentRecord, SubagentResultV1};
        let encoded = entry.payload.split_once(':').unwrap().1;
        let payload = (0..encoded.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let result = SubagentResultV1::decode(&payload).unwrap();
        assert_eq!(result.sources.len(), 1);
        assert_eq!(result.sources[0].index, 0);
        assert!(hashes.contains(&irmind_app::hex(result.sources[0].hash.as_bytes())));
    }
    engine.verify(&case.id).unwrap();
    engine.seal(&case.id).unwrap();
    let output = root.path().join("mixed.irmind");
    let key =
        CaseExporter::export_case(store.as_ref(), &case.id, &output, &CancellationToken::new())
            .unwrap();
    let verified =
        irmind_app::verify_export_details(&irmind_infra::LocalExportVerifier, &output, Some(&key))
            .unwrap();
    assert_eq!(verified.format_version, 8);
}

fn ingest_sources(
    root: &Path,
    store: &LocalStore,
    engine: &Engine<'_>,
    case: &irmind_app::CaseId,
) -> Vec<String> {
    let fixtures = [
        (
            "windows.jsonl",
            "parser-hayabusa",
            include_str!("../../../testkit/fixtures/parser-hayabusa/source/events.jsonl"),
            None,
        ),
        (
            "aws.json",
            "parser-json",
            include_str!("../../../modules/parser-json/tests/fixtures/hunteval-aws-iam-001.json"),
            None,
        ),
        (
            "kubernetes.ndjson",
            "parser-kubernetes",
            include_str!(
                "../../../testkit/fixtures/skills-expanded/k8s-cluster-compromise/source/audit.ndjson"
            ),
            Some("kubernetes:urn:k8s:synthetic-cluster"),
        ),
    ];
    fixtures
        .into_iter()
        .map(|(name, parser, content, cluster)| {
            std::fs::write(root.join(name), content).unwrap();
            let catalog = crate::current_sources::catalog();
            let context = irmind_app::command_cluster_context(cluster).unwrap();
            let selected = catalog
                .select_source(irmind_app::modules::ParserSelectionRequest {
                    source: name,
                    sample: content.as_bytes(),
                    parser_override: Some(parser),
                    forced: true,
                    time_context: None,
                    cluster_context: context.as_ref(),
                })
                .unwrap();
            let large = LargeCaseUseCases {
                engine,
                store,
                parser: selected.parser.as_ref(),
            };
            large
                .ingest_local_batch_selected(
                    case,
                    root,
                    &[name.into()],
                    true,
                    &BTreeMap::from([(name.into(), selected.selection)]),
                    &CancellationToken::new(),
                )
                .unwrap();
            irmind_app::hex(&irmind_app::sha256(content.as_bytes()))
        })
        .collect()
}
