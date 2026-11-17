use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

struct QueryModel {
    call: ProposedCall,
    sent: AtomicBool,
}
#[async_trait]
impl LlmPort for QueryModel {
    async fn complete(
        &self,
        request: CompletionRequest,
        _: &CancellationToken,
    ) -> Result<ModelStream, AppError> {
        request.validate()?;
        let calls = if self.sent.swap(true, Ordering::SeqCst) {
            vec![]
        } else {
            model_calls(vec![self.call.clone()])
        };
        Ok(irmind_app::single_completion_stream(
            ModelResponse {
                text: "Synthetic query finished.".into(),
                calls,
                raw: "synthetic".into(),
                truncated: false,
            },
            Some(ModelUsage {
                cache: None,
                input_tokens: 3,
                output_tokens: 2,
            }),
        ))
    }
}
fn arguments(tool: &Tool, field: &str, value: &str) -> BTreeMap<String, String> {
    let mut args = BTreeMap::from([(field.into(), value.into())]);
    match tool {
        Tool::EntityLookup | Tool::Neighbors | Tool::EntityTimeline => {
            args.insert("kind".into(), "k8s_pod".into());
            args.insert("value".into(), "frontend".into());
        }
        Tool::GraphPath => {
            for (key, value) in [
                ("from_kind", "k8s_pod"),
                ("from_value", "frontend"),
                ("to_kind", "k8s_user"),
                ("to_value", "alice"),
            ] {
                args.insert(key.into(), value.into());
            }
        }
        Tool::TextSearch => {
            args.insert("query".into(), "frontend".into());
        }
        _ => unreachable!(),
    }
    args
}
fn direct_query(
    store: &LocalStore,
    case: &CaseId,
    tool: &Tool,
    filter: &GraphQueryFilter,
) -> String {
    match tool {
        Tool::EntityLookup => store
            .entity_lookup_filtered(case, filter, "k8s_pod", "frontend")
            .unwrap(),
        Tool::Neighbors => store
            .neighbors_filtered(case, filter, "k8s_pod", "frontend", 10)
            .unwrap(),
        Tool::EntityTimeline => store
            .entity_timeline_filtered(case, filter, "k8s_pod", "frontend", 10)
            .unwrap(),
        Tool::GraphPath => store
            .graph_path_filtered(case, filter, ("k8s_pod", "frontend"), ("k8s_user", "alice"))
            .unwrap(),
        Tool::TextSearch => store
            .text_search_filtered(case, filter, "frontend", 10)
            .unwrap(),
        _ => unreachable!(),
    }
}

#[test]
fn model_graph_tools_preserve_every_validated_cluster_host_classification_and_role_filter() {
    let root = tempfile::tempdir().unwrap();
    let catalog = Arc::new(
        MappingCatalog::freeze(
            vec![Arc::new(ContextDecoder)],
            vec![Arc::new(Mapper::new())],
        )
        .unwrap(),
    );
    let (store, engine, catalog) = fixture_catalog(root.path(), catalog);
    let case = engine
        .create_case("Synthetic model query filters", "local only")
        .unwrap();
    ingest_sources(store.as_ref(), &engine, &catalog, &case.id, root.path());
    for tool in [
        Tool::EntityLookup,
        Tool::Neighbors,
        Tool::EntityTimeline,
        Tool::GraphPath,
        Tool::TextSearch,
    ] {
        for (field, value) in [
            ("cluster", "kubernetes:urn:k8s:a"),
            ("host", "absent-host"),
            ("event_category", "file"),
            ("event_type", "allowed"),
            ("event_outcome", "success"),
            ("entity_role", "source"),
        ] {
            let args = arguments(&tool, field, value);
            let filter = GraphQueryFilter::from_args(&args).unwrap();
            let expected = direct_query(store.as_ref(), &case.id, &tool, &filter);
            let previous = store.last_entry(&case.id).unwrap().unwrap().seq;
            let model = QueryModel {
                call: ProposedCall {
                    tool: tool.clone(),
                    args,
                },
                sent: AtomicBool::new(false),
            };
            engine
                .investigate(&case.id, "Read the bounded synthetic records", &model)
                .unwrap();
            let entries = store.entries(&case.id).unwrap();
            let result = entries
                .iter()
                .find(|entry| entry.seq > previous && entry.kind == AuditEventKind::ToolResult)
                .unwrap();
            let actual = store
                .get_evidence(&case.id, result.evidence.as_deref().unwrap())
                .unwrap();
            assert_eq!(
                String::from_utf8(actual).unwrap(),
                expected,
                "{}: {field}={value}",
                tool.as_str()
            );
        }
    }
    engine.verify(&case.id).unwrap();
}
