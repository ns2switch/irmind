//! Opt-in development observation of synthetic engine requests, never a provider.
use super::*;
use irmind_app::ModelUsage;
use std::io::Write as _;

mod scenarios;

static WRITER: Mutex<()> = Mutex::new(());

pub(super) fn capture(
    scenario: &str,
    turn: usize,
    request: &CompletionRequest,
    output_bytes: usize,
) -> Option<ModelUsage> {
    let destination = std::env::var_os("IRMIND_CONTEXT_COST_TRACE")?;
    let messages: Vec<_> =
        request
            .messages
            .iter()
            .map(|m| {
                let calls: Vec<_> = m.tool_calls.iter().map(|c| serde_json::json!({
            "id":c.id(),"name":c.proposal().tool.as_str(),"arguments":c.arguments_json()
        })).collect();
                serde_json::json!({"role":format!("{:?}",m.role),"content":m.content,
            "tool_calls":calls,"tool_call_id":m.tool_call_id})
            })
            .collect();
    let tools: Vec<_> = request
        .tools
        .iter()
        .map(|t| {
            serde_json::json!({
                "name":t.name,"description":t.description,"parameters":t.parameters
            })
        })
        .collect();
    let body = serde_json::json!({"messages":messages,"tools":tools});
    let input_bytes = serde_json::to_vec(&body).unwrap().len();
    let usage = ModelUsage {
        input_tokens: input_bytes.div_ceil(4) as u64,
        output_tokens: output_bytes.div_ceil(4) as u64,
    };
    let _lock = WRITER.lock().unwrap();
    std::fs::create_dir_all(&destination).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(Path::new(&destination).join(format!("{scenario}.jsonl")))
        .unwrap();
    let row = serde_json::json!({"scenario":scenario,"turn":turn,
        "request":body,"simulated_usage":usage});
    writeln!(file, "{}", serde_json::to_string(&row).unwrap()).unwrap();
    Some(usage)
}
