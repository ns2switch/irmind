use irmind_app::{AppError, ModelResponse, ModelUsage};
use irmind_domain::{ProposedCall, Tool};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Read};

const MAX_STREAM_BYTES: usize = 2_000_000;

#[derive(Default)]
pub(super) struct TextPreview {
    pending: Vec<u8>,
}

impl TextPreview {
    pub(super) fn push(&mut self, chunk: &[u8]) -> Result<Vec<String>, AppError> {
        self.pending.extend_from_slice(chunk);
        if self.pending.len() > MAX_STREAM_BYTES {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderStreamExceeds2MB,
            )));
        }
        let mut text = Vec::new();
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line = self.pending.drain(..=end).collect::<Vec<_>>();
            let line = std::str::from_utf8(&line).map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::UnexpectedProviderStreamField,
                ))
            })?;
            let Some(data) = line.trim_end_matches(['\r', '\n']).strip_prefix("data:") else {
                continue;
            };
            let data = data.trim_start();
            if data == "[DONE]" {
                continue;
            }
            let value: Value = serde_json::from_str(data).map_err(|_| {
                AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::UnexpectedProviderStreamField,
                ))
            })?;
            if let Some(part) = value["choices"][0]["delta"]["content"].as_str()
                && !part.is_empty()
            {
                text.push(part.to_owned());
            }
        }
        Ok(text)
    }
}

#[derive(Default)]
struct ToolDelta {
    id: Option<String>,
    name: String,
    arguments: String,
}

#[derive(Default)]
struct StreamState {
    raw: String,
    text: String,
    tools: BTreeMap<usize, ToolDelta>,
    usage: Option<ModelUsage>,
    finished: bool,
    done: bool,
    bytes_read: usize,
}

pub(super) fn parse(reader: impl Read) -> Result<(ModelResponse, ModelUsage), AppError> {
    let mut reader = BufReader::new(reader.take((MAX_STREAM_BYTES + 1) as u64));
    let mut line = String::new();
    let mut state = StreamState::default();
    loop {
        line.clear();
        let count = reader
            .read_line(&mut line)
            .map_err(|error| AppError::Model(format!("provider stream read: {error}")))?;
        if count == 0 {
            break;
        }
        state.bytes_read += count;
        if state.bytes_read > MAX_STREAM_BYTES {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderStreamExceeds2MB,
            )));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let data = line
            .strip_prefix("data:")
            .ok_or({
                AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::UnexpectedProviderStreamField,
                ))
            })?
            .trim_start();
        if data == "[DONE]" {
            state.done = true;
            break;
        }
        state.raw.push_str(data);
        state.raw.push('\n');
        let chunk: Value = serde_json::from_str(data)
            .map_err(|error| AppError::Model(format!("invalid provider chunk: {error}")))?;
        state.apply_chunk(&chunk)?;
    }
    state.finish()
}

impl StreamState {
    fn apply_chunk(&mut self, chunk: &Value) -> Result<(), AppError> {
        if let Some(value) = chunk.get("usage").filter(|value| !value.is_null()) {
            if self.usage.is_some() {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::DuplicateProviderUsage,
                )));
            }
            self.usage = Some(ModelUsage {
                input_tokens: value.get("prompt_tokens").and_then(Value::as_u64).ok_or({
                    AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                        irmind_app::AdapterModelError::MissingPromptTokenUsage,
                    ))
                })?,
                output_tokens: value
                    .get("completion_tokens")
                    .and_then(Value::as_u64)
                    .ok_or({
                        AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                            irmind_app::AdapterModelError::MissingCompletionTokenUsage,
                        ))
                    })?,
            });
        }
        let choices = chunk.get("choices").and_then(Value::as_array).ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::MissingProviderChoices,
            ))
        })?;
        if choices.len() > 1 {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::MultipleProviderChoices,
            )));
        }
        if let Some(choice) = choices.first() {
            self.apply_choice(choice)?;
        }
        Ok(())
    }

    fn apply_choice(&mut self, choice: &Value) -> Result<(), AppError> {
        if choice.get("index").and_then(Value::as_u64) != Some(0) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::UnexpectedProviderChoiceIndex,
            )));
        }
        if self.finished {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderOutputAfterFinish,
            )));
        }
        let delta = choice.get("delta").and_then(Value::as_object).ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::MissingProviderDelta,
            ))
        })?;
        if let Some(part) = delta.get("content").and_then(Value::as_str) {
            self.text.push_str(part);
        }
        if let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                self.apply_tool_delta(call)?;
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            if !matches!(reason, "stop" | "tool_calls") {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::ProviderStoppedUnexpectedly,
                )));
            }
            self.finished = true;
        }
        Ok(())
    }

    fn apply_tool_delta(&mut self, call: &Value) -> Result<(), AppError> {
        let index = call
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < 16)
            .ok_or({
                AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::InvalidProviderToolIndex,
                ))
            })?;
        let collected = self.tools.entry(index).or_default();
        if let Some(id) = call.get("id").and_then(Value::as_str) {
            if collected.id.as_deref().is_some_and(|prior| prior != id) {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::ProviderToolIDChanged,
                )));
            }
            collected.id = Some(id.to_owned());
        }
        if call
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind != "function")
        {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::UnsupportedProviderToolType,
            )));
        }
        if let Some(function) = call.get("function") {
            if let Some(name) = function.get("name").and_then(Value::as_str) {
                collected.name.push_str(name);
            }
            if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
                collected.arguments.push_str(arguments);
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<(ModelResponse, ModelUsage), AppError> {
        if !self.done || !self.finished {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderStreamIncomplete,
            )));
        }
        let usage = self.usage.ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderStreamOmittedUsage,
            ))
        })?;
        let mut calls = Vec::with_capacity(self.tools.len());
        for (expected, (index, tool)) in self.tools.into_iter().enumerate() {
            if index != expected || tool.id.is_none() {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::IncompleteProviderToolCall,
                )));
            }
            calls.push(parse_tool(&tool.name, &tool.arguments)?);
        }
        Ok((
            ModelResponse {
                text: self.text,
                calls,
                raw: self.raw,
            },
            usage,
        ))
    }
}

fn parse_tool(name: &str, arguments: &str) -> Result<ProposedCall, AppError> {
    let tool = Tool::parse(name).map_err(|_| {
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::UnknownProviderTool,
        ))
    })?;
    let value: Value = serde_json::from_str(arguments)
        .map_err(|error| AppError::Model(format!("invalid provider tool arguments: {error}")))?;
    let object = value.as_object().ok_or({
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::ToolArgumentsMustBeAnObject,
        ))
    })?;
    let mut args = BTreeMap::new();
    for (key, value) in object {
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Number(value) => value.to_string(),
            _ => {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                    irmind_app::AdapterPolicyError::ToolArgumentMustBeStringOrNumber,
                )));
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
    fn preview_emits_only_complete_text_frames() {
        let mut preview = TextPreview::default();
        let first = b"data: {\"choices\":[{\"delta\":{\"content\":\"hel";
        assert!(preview.push(first).unwrap().is_empty());
        assert_eq!(preview.push(b"lo\"}}]}\n\n").unwrap(), ["hello"]);
    }

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
