use irmind_app::{AppError, ModelResponse, ModelUsage};
use irmind_domain::{ProposedCall, Tool};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead as _, BufReader, Read};

const MAX_STREAM_BYTES: usize = 2_000_000;

enum Block {
    Text(String),
    Tool {
        id: String,
        name: String,
        initial: Value,
        partial: String,
    },
    Ignored,
}

#[derive(Default)]
struct State {
    started: bool,
    stopped: bool,
    finish: Option<String>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    blocks: BTreeMap<usize, Block>,
    closed: BTreeSet<usize>,
    raw: String,
}

pub(super) fn parse(reader: impl Read) -> Result<(ModelResponse, ModelUsage), AppError> {
    let mut reader = BufReader::new(reader.take((MAX_STREAM_BYTES + 1) as u64));
    let mut state = State::default();
    let mut line = String::new();
    let mut event = String::new();
    let mut data = String::new();
    let mut total = 0usize;
    loop {
        line.clear();
        let count = reader
            .read_line(&mut line)
            .map_err(|error| AppError::Model(format!("provider stream read: {error}")))?;
        if count == 0 {
            break;
        }
        total += count;
        if total > MAX_STREAM_BYTES {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderStreamExceeds2MB,
            )));
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            if !event.is_empty() || !data.is_empty() {
                state.event(&event, &data)?;
                event.clear();
                data.clear();
            }
        } else if let Some(value) = line.strip_prefix("event:") {
            if !event.is_empty() {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::DuplicateProviderEventField,
                )));
            }
            event.push_str(value.trim_start());
        } else if let Some(value) = line.strip_prefix("data:") {
            if !data.is_empty() {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::MultipleProviderDataFields,
                )));
            }
            data.push_str(value.trim_start());
        } else if !line.starts_with(':') {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::UnexpectedProviderStreamField,
            )));
        }
    }
    if !event.is_empty() || !data.is_empty() {
        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
            irmind_app::AdapterModelError::ProviderStreamIncomplete,
        )));
    }
    state.finish()
}

impl State {
    fn event(&mut self, name: &str, data: &str) -> Result<(), AppError> {
        if self.stopped {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderOutputAfterMessageStop,
            )));
        }
        let value: Value = serde_json::from_str(data)
            .map_err(|error| AppError::Model(format!("invalid provider event: {error}")))?;
        if value["type"].as_str() != Some(name) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderEventNameMismatch,
            )));
        }
        self.raw.push_str(data);
        self.raw.push('\n');
        match name {
            "message_start" => {
                if self.started {
                    return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                        irmind_app::AdapterModelError::DuplicateMessageStart,
                    )));
                }
                self.started = true;
                self.input_tokens = total_input(&value["message"]["usage"])?;
            }
            "ping" => {}
            "error" => {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::ProviderStreamError,
                )));
            }
            "content_block_start" => {
                self.start_block(&value)?;
            }
            "content_block_delta" => {
                self.delta_block(&value)?;
            }
            "content_block_stop" => {
                self.require_started()?;
                let index = block_index(&value)?;
                if !self.blocks.contains_key(&index) || !self.closed.insert(index) {
                    return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                        irmind_app::AdapterModelError::InvalidContentBlockStop,
                    )));
                }
            }
            "message_delta" => {
                self.message_delta(&value)?;
            }
            "message_stop" => {
                self.require_started()?;
                self.stopped = true;
            }
            _ => {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::UnsupportedProviderEvent,
                )));
            }
        }
        Ok(())
    }

    fn start_block(&mut self, value: &Value) -> Result<(), AppError> {
        self.require_started()?;
        let index = block_index(value)?;
        if self.blocks.contains_key(&index) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::DuplicateContentBlock,
            )));
        }
        let block = &value["content_block"];
        let item = match block["type"].as_str() {
            Some("text") => Block::Text(block["text"].as_str().unwrap_or_default().to_owned()),
            Some("tool_use") => Block::Tool {
                id: required_string(block, "id")?.to_owned(),
                name: required_string(block, "name")?.to_owned(),
                initial: block["input"].clone(),
                partial: String::new(),
            },
            Some("thinking" | "redacted_thinking" | "fallback") => Block::Ignored,
            _ => {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::UnsupportedProviderContentBlock,
                )));
            }
        };
        self.blocks.insert(index, item);
        Ok(())
    }

    fn delta_block(&mut self, value: &Value) -> Result<(), AppError> {
        self.require_started()?;
        let index = block_index(value)?;
        if self.closed.contains(&index) {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::DeltaAfterContentBlockStop,
            )));
        }
        let block = self.blocks.get_mut(&index).ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::DeltaWithoutContentBlock,
            ))
        })?;
        let delta = &value["delta"];
        match (block, delta["type"].as_str()) {
            (Block::Text(text), Some("text_delta")) => {
                text.push_str(required_string(delta, "text")?);
            }
            (Block::Tool { partial, .. }, Some("input_json_delta")) => {
                partial.push_str(required_string(delta, "partial_json")?);
            }
            (
                Block::Ignored,
                Some("thinking_delta" | "signature_delta" | "redacted_thinking_delta"),
            ) => {}
            _ => {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::InvalidProviderContentDelta,
                )));
            }
        }
        Ok(())
    }

    fn message_delta(&mut self, value: &Value) -> Result<(), AppError> {
        self.require_started()?;
        if let Some(input) = total_input(&value["usage"])? {
            self.input_tokens = Some(input);
        }
        if let Some(output) = value["usage"]["output_tokens"].as_u64() {
            self.output_tokens = Some(output);
        }
        if let Some(reason) = value["delta"]["stop_reason"].as_str() {
            if !matches!(reason, "end_turn" | "tool_use" | "stop_sequence") {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::ProviderStoppedUnexpectedly,
                )));
            }
            self.finish = Some(reason.to_owned());
        }
        Ok(())
    }

    fn require_started(&self) -> Result<(), AppError> {
        if !self.started {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderEventBeforeMessageStart,
            )));
        }
        Ok(())
    }

    fn finish(self) -> Result<(ModelResponse, ModelUsage), AppError> {
        if !self.stopped || self.finish.is_none() || self.closed.len() != self.blocks.len() {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderStreamIncomplete,
            )));
        }
        let usage = ModelUsage {
            input_tokens: self.input_tokens.ok_or({
                AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::MissingInputTokenUsage,
                ))
            })?,
            output_tokens: self.output_tokens.ok_or({
                AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::MissingOutputTokenUsage,
                ))
            })?,
        };
        let mut text = String::new();
        let mut calls = Vec::new();
        for (expected, (index, block)) in self.blocks.into_iter().enumerate() {
            if index != expected {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::NonContiguousContentBlocks,
                )));
            }
            match block {
                Block::Text(part) => text.push_str(&part),
                Block::Tool {
                    id,
                    name,
                    initial,
                    partial,
                } => {
                    if id.is_empty() {
                        return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                            irmind_app::AdapterModelError::MissingProviderToolID,
                        )));
                    }
                    let args = if partial.is_empty() {
                        initial
                    } else {
                        serde_json::from_str(&partial).map_err(|error| {
                            AppError::Model(format!("invalid tool input: {error}"))
                        })?
                    };
                    calls.push(parse_tool(&name, &args)?);
                }
                Block::Ignored => {}
            }
        }
        if self.finish.as_deref() == Some("tool_use") && calls.is_empty() {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ToolUseFinishWithoutToolCall,
            )));
        }
        if self.finish.as_deref() != Some("tool_use") && !calls.is_empty() {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ToolCallWithoutToolUseFinish,
            )));
        }
        Ok((
            ModelResponse {
                text,
                calls,
                raw: self.raw,
            },
            usage,
        ))
    }
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, AppError> {
    value[key]
        .as_str()
        .ok_or_else(|| AppError::Model(format!("missing provider {key}")))
}

fn total_input(usage: &Value) -> Result<Option<u64>, AppError> {
    let Some(input) = usage["input_tokens"].as_u64() else {
        return Ok(None);
    };
    let cached = usage["cache_read_input_tokens"].as_u64().unwrap_or(0);
    let created = usage["cache_creation_input_tokens"].as_u64().unwrap_or(0);
    let total = input
        .checked_add(cached)
        .and_then(|value| value.checked_add(created))
        .ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderInputTokenUsageOverflow,
            ))
        })?;
    Ok(Some(total))
}

fn block_index(value: &Value) -> Result<usize, AppError> {
    value["index"]
        .as_u64()
        .and_then(|index| usize::try_from(index).ok())
        .filter(|index| *index < 16)
        .ok_or({
            AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::InvalidProviderBlockIndex,
            ))
        })
}

fn parse_tool(name: &str, input: &Value) -> Result<ProposedCall, AppError> {
    let tool = Tool::parse(name).map_err(|_| {
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::UnknownProviderTool,
        ))
    })?;
    let object = input.as_object().ok_or({
        AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::ToolInputMustBeAnObject,
        ))
    })?;
    let mut args = BTreeMap::new();
    for (key, value) in object {
        let value = match value {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
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

include!("stream_tests.rs");
