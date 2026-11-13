//! Opt-in, provider-free request-size measurements; no prompt content is exported.
use irmind_app::{AuditLog, CompletionRequest};
use irmind_domain::AuditEventKind;
use std::path::Path;

pub(crate) fn record(
    name: &str,
    turns: &[&[CompletionRequest]],
    final_response_bytes: usize,
    store: &irmind_infra::LocalStore,
    id: &irmind_app::CaseId,
    suffix: &str,
) {
    let Some(destination) = std::env::var_os("IRMIND_SKILL_BUDGET_MEASUREMENTS") else {
        return;
    };
    let mut input_bytes = 0usize;
    let mut output_bytes = final_response_bytes;
    let mut proposals = 0usize;
    let mut requests_count = 0usize;
    for requests in turns {
        requests_count += requests.len();
        input_bytes += requests.iter().map(request_bytes).sum::<usize>();
        // Every previous response is replayed as an assistant message in the next request.
        for pair in requests.windows(2) {
            let response = pair[1]
                .messages
                .iter()
                .rev()
                .find(|m| !m.tool_calls.is_empty())
                .unwrap();
            proposals += response.tool_calls.len();
            output_bytes += response.content.len()
                + response
                    .tool_calls
                    .iter()
                    .map(|c| c.arguments_json().len())
                    .sum::<usize>();
        }
    }
    let entries = store.entries(id).unwrap();
    let reports = entries
        .iter()
        .filter(|e| e.kind == AuditEventKind::ModelUsage)
        .count();
    let charged_calls = entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.kind,
                AuditEventKind::Allowed | AuditEventKind::ToolDispatch
            )
        })
        .count();
    let report = serde_json::json!({
        "skill": name, "turns": turns.len(), "model_requests": requests_count,
        "model_tool_proposals": proposals, "charged_tool_calls": charged_calls, "neutral_request_json_bytes": input_bytes,
        "observed_response_content_bytes": output_bytes,
        "planning_tokens_at_four_bytes_per_token": (input_bytes + output_bytes).div_ceil(4),
        "provider_usage_reports": reports, "provider_tokens": null,
        "method": "provider-neutral-json-v1; output content excludes provider framing and hidden reasoning; planning estimate is not billing or a hard-limit counter"
    });
    let destination = Path::new(&destination);
    std::fs::create_dir_all(destination).unwrap();
    std::fs::write(
        destination.join(format!("{name}-{suffix}.json")),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
}

fn request_bytes(request: &CompletionRequest) -> usize {
    let messages: Vec<_> = request.messages.iter().map(|m| {
        let calls: Vec<_> = m.tool_calls.iter().map(|c| serde_json::json!({"id":c.id(),"name":c.proposal().tool.as_str(),"arguments":c.arguments_json()})).collect();
        serde_json::json!({"role":format!("{:?}",m.role),"content":m.content,"tool_calls":calls,"tool_call_id":m.tool_call_id})
    }).collect();
    let tools: Vec<_> = request.tools.iter().map(|t| serde_json::json!({"name":t.name,"description":t.description,"parameters":t.parameters})).collect();
    serde_json::to_vec(&serde_json::json!({"messages":messages,"tools":tools,"max_output_tokens":request.max_output_tokens})).unwrap().len()
}
