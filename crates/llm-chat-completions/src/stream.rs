use irmind_app::{AppError, ModelResponse, ModelUsage};
use irmind_domain::{ProposedCall, Tool};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Read};

const MAX_STREAM_BYTES: usize = 2_000_000;

#[derive(Default)]
struct ToolDelta {
    id: Option<String>,
    name: String,
    arguments: String,
}

pub(super) fn parse(reader: impl Read) -> Result<(ModelResponse, ModelUsage), AppError> {
    let mut reader = BufReader::new(reader.take((MAX_STREAM_BYTES + 1) as u64));
    let mut line = String::new();
    let mut raw = String::new();
    let mut bytes_read = 0usize;
    let mut text = String::new();
    let mut tools = BTreeMap::<usize, ToolDelta>::new();
    let mut usage = None;
    let mut finished = false;
    let mut done = false;
    loop {
        line.clear();
        let count = reader
            .read_line(&mut line)
            .map_err(|error| AppError::Model(format!("provider stream read: {error}")))?;
        if count == 0 {
            break;
        }
        bytes_read += count;
        if bytes_read > MAX_STREAM_BYTES {
            return Err(AppError::Model("provider stream exceeds 2 MB".into()));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let data = line
            .strip_prefix("data:")
            .ok_or_else(|| AppError::Model("unexpected provider stream field".into()))?
            .trim_start();
        if data == "[DONE]" {
            done = true;
            break;
        }
        raw.push_str(data);
        raw.push('\n');
        let chunk: Value = serde_json::from_str(data)
            .map_err(|error| AppError::Model(format!("invalid provider chunk: {error}")))?;
        if let Some(value) = chunk.get("usage").filter(|value| !value.is_null()) {
            if usage.is_some() {
                return Err(AppError::Model("duplicate provider usage".into()));
            }
            usage = Some(ModelUsage {
                input_tokens: value
                    .get("prompt_tokens")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| AppError::Model("missing prompt token usage".into()))?,
                output_tokens: value
                    .get("completion_tokens")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| AppError::Model("missing completion token usage".into()))?,
            });
        }
        let choices = chunk
            .get("choices")
            .and_then(Value::as_array)
            .ok_or_else(|| AppError::Model("missing provider choices".into()))?;
        if choices.len() > 1 {
            return Err(AppError::Model("multiple provider choices".into()));
        }
        let Some(choice) = choices.first() else {
            continue;
        };
        if choice.get("index").and_then(Value::as_u64) != Some(0) {
            return Err(AppError::Model("unexpected provider choice index".into()));
        }
        if finished {
            return Err(AppError::Model("provider output after finish".into()));
        }
        let delta = choice
            .get("delta")
            .and_then(Value::as_object)
            .ok_or_else(|| AppError::Model("missing provider delta".into()))?;
        if let Some(part) = delta.get("content").and_then(Value::as_str) {
            text.push_str(part);
        }
        if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                let index = call
                    .get("index")
                    .and_then(Value::as_u64)
                    .and_then(|index| usize::try_from(index).ok())
                    .filter(|index| *index < 16)
                    .ok_or_else(|| AppError::Model("invalid provider tool index".into()))?;
                let collected = tools.entry(index).or_default();
                if let Some(id) = call.get("id").and_then(Value::as_str) {
                    if collected.id.as_deref().is_some_and(|prior| prior != id) {
                        return Err(AppError::Model("provider tool ID changed".into()));
                    }
                    collected.id = Some(id.to_owned());
                }
                if call
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| kind != "function")
                {
                    return Err(AppError::Model("unsupported provider tool type".into()));
                }
                if let Some(function) = call.get("function") {
                    if let Some(name) = function.get("name").and_then(Value::as_str) {
                        collected.name.push_str(name);
                    }
                    if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
                        collected.arguments.push_str(arguments);
                    }
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            if !matches!(reason, "stop" | "tool_calls") {
                return Err(AppError::Model("provider stopped unexpectedly".into()));
            }
            finished = true;
        }
    }
    if !done || !finished {
        return Err(AppError::Model("provider stream incomplete".into()));
    }
    let usage = usage.ok_or_else(|| AppError::Model("provider stream omitted usage".into()))?;
    let mut calls = Vec::with_capacity(tools.len());
    for (expected, (index, tool)) in tools.into_iter().enumerate() {
        if index != expected || tool.id.is_none() {
            return Err(AppError::Model("incomplete provider tool call".into()));
        }
        calls.push(parse_tool(&tool.name, &tool.arguments)?);
    }
    Ok((ModelResponse { text, calls, raw }, usage))
}

fn parse_tool(name: &str, arguments: &str) -> Result<ProposedCall, AppError> {
    let tool = Tool::parse(name).map_err(|_| AppError::Policy("unknown provider tool".into()))?;
    let value: Value = serde_json::from_str(arguments)
        .map_err(|error| AppError::Model(format!("invalid provider tool arguments: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| AppError::Policy("tool arguments must be an object".into()))?;
    let mut args = BTreeMap::new();
    for (key, value) in object {
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            _ => {
                return Err(AppError::Policy(
                    "tool argument must be string or number".into(),
                ));
            }
        };
        args.insert(key.clone(), value);
    }
    Ok(ProposedCall { tool, args })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn assembles_split_tool_call_before_authorization() {
        let wire = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"evidence_\",\"arguments\":\"{\\\"que\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"search\",\"arguments\":\"ry\\\":\\\"AssumeRole\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":14,\"completion_tokens\":7}}\n\n",
            "data: [DONE]\n\n"
        );
        let (answer, usage) = parse(wire.as_bytes()).unwrap();
        assert_eq!(answer.calls.len(), 1);
        assert_eq!(answer.calls[0].tool, Tool::EvidenceSearch);
        assert_eq!(
            answer.calls[0].args.get("query").map(String::as_str),
            Some("AssumeRole")
        );
        assert_eq!(usage.input_tokens, 14);
        assert_eq!(usage.output_tokens, 7);
    }

    #[test]
    fn rejects_interrupted_or_unaccounted_stream() {
        let prefix = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":\"stop\"}]}\n\n";
        assert!(parse(prefix.as_bytes()).is_err());
        let without_usage = format!("{prefix}data: [DONE]\n\n");
        assert!(parse(without_usage.as_bytes()).is_err());
    }
}
