//! One opt-in local SSE capture, with only allowlisted protocol values retained.
use serde_json::{Map, Value, json};
use std::{fs::OpenOptions, io::Write as _, path::PathBuf};

const MAX_TRACE_BYTES: usize = 256 * 1024;

pub(super) struct ReceivedStream {
    pub bytes: Vec<u8>,
    path: Option<PathBuf>,
}

impl ReceivedStream {
    pub(super) fn new() -> Self {
        Self {
            bytes: Vec::new(),
            path: std::env::var_os("IRMIND_SSE_DIAGNOSTICS_FILE")
                .filter(|path| !path.is_empty())
                .map(PathBuf::from),
        }
    }
}

impl Drop for ReceivedStream {
    fn drop(&mut self) {
        let Some(path) = &self.path else { return };
        if self.bytes.is_empty() {
            return;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        if let Ok(mut file) = options.open(path) {
            let _ = file.write_all(&redact_stream(&self.bytes));
        }
    }
}

fn redact_stream(bytes: &[u8]) -> Vec<u8> {
    let mut trace = Vec::new();
    for raw in bytes.split(|byte| *byte == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        let frame = if line.starts_with(b":") {
            ": redacted comment\n\n".to_owned()
        } else if let Some(data) = line.strip_prefix(b"data:") {
            let data = data.trim_ascii_start();
            if data == b"[DONE]" {
                trace.extend_from_slice(b"data: [DONE]\n\n");
                break;
            }
            if let Ok(chunk) = serde_json::from_slice::<Value>(data) {
                format!("data: {}\n\n", redact_chunk(&chunk))
            } else {
                // Keep a failing frame recognizable without retaining any bytes of it.
                "data: !redacted-invalid-json\n\n".to_owned()
            }
        } else {
            "event: redacted-unsupported-field\n\n".to_owned()
        };
        let capped = b": diagnostic capture reached its size limit\n\n";
        if trace.len() + frame.len() + capped.len() > MAX_TRACE_BYTES {
            trace.extend_from_slice(capped);
            break;
        }
        trace.extend_from_slice(frame.as_bytes());
    }
    trace
}

fn redact_chunk(chunk: &Value) -> Value {
    let Some(chunk) = chunk.as_object() else {
        return shape(chunk);
    };
    let mut redacted = Map::new();
    if let Some(choices) = chunk.get("choices") {
        let choices = choices.as_array().map_or_else(
            || shape(choices),
            |items| Value::Array(items.iter().take(2).map(redact_choice).collect()),
        );
        redacted.insert("choices".into(), choices);
    }
    if let Some(usage) = chunk.get("usage") {
        let usage = usage.as_object().map_or_else(
            || shape(usage),
            |fields| {
                Value::Object(
                    ["prompt_tokens", "completion_tokens", "total_tokens"]
                        .into_iter()
                        .filter_map(|key| {
                            let value = fields.get(key)?;
                            Some((
                                key.into(),
                                value.as_u64().map_or_else(|| shape(value), Value::from),
                            ))
                        })
                        .collect(),
                )
            },
        );
        redacted.insert("usage".into(), usage);
    }
    Value::Object(redacted)
}

fn redact_choice(choice: &Value) -> Value {
    let Some(choice) = choice.as_object() else {
        return shape(choice);
    };
    Value::Object(
        [
            "index",
            "finish_reason",
            "delta",
            "text",
            "message",
            "tool_calls",
            "function_call",
        ]
        .into_iter()
        .filter_map(|field| {
            let value = choice.get(field)?;
            let safe = match field {
                "index" if value.as_u64().is_some() => json!(u8::from(value.as_u64() != Some(0))),
                "finish_reason"
                    if matches!(
                        value.as_str(),
                        Some("stop" | "length" | "tool_calls" | "content_filter")
                    ) =>
                {
                    value.clone()
                }
                "delta" => redact_delta(value),
                _ => shape(value),
            };
            Some((field.into(), safe))
        })
        .collect(),
    )
}

fn redact_delta(delta: &Value) -> Value {
    let Some(delta) = delta.as_object() else {
        return shape(delta);
    };
    let mut redacted = Map::new();
    for (field, value) in delta {
        match field.as_str() {
            "role" if value.as_str() == Some("assistant") => {
                redacted.insert(field.clone(), json!("assistant"));
            }
            "role" | "content" | "reasoning_content" | "tool_calls" | "function_call" => {
                redacted.insert(field.clone(), shape(value));
            }
            _ if !value.is_null() && value.as_str() != Some("") => {
                redacted.insert("redacted_unknown_delta_field".into(), json!("<redacted>"));
            }
            _ => (),
        }
    }
    Value::Object(redacted)
}

fn shape(value: &Value) -> Value {
    match value {
        Value::Null => Value::Null,
        Value::Bool(_) => json!(false),
        Value::Number(_) => json!(-1),
        Value::String(text) if text.is_empty() => json!(""),
        Value::String(_) => json!("<redacted>"),
        Value::Array(items) if items.is_empty() => json!([]),
        Value::Array(_) => json!([null]),
        Value::Object(object) if object.is_empty() => json!({}),
        Value::Object(_) => json!({"redacted":null}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_replays_glm_ending_without_reply_reasoning_or_arbitrary_metadata()
    -> Result<(), irmind_app::AppError> {
        let input = b": synthetic-header-secret\r\n\r\ndata: {\"id\":\"synthetic-id-secret\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"synthetic-answer-secret\"},\"finish_reason\":\"stop\"}]}\r\n\r\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"synthetic-reasoning-secret\"}}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":19,\"synthetic-usage-secret\":\"synthetic-echo-secret\"}}\r\n\r\ndata: [DONE]\r\n\r\n";
        let trace = redact_stream(input);
        let text = String::from_utf8_lossy(&trace);
        assert!(!text.contains("secret"));
        assert!(text.contains("reasoning_content"));
        let (answer, usage) = crate::stream::parse(trace.as_slice())?;
        assert_eq!(answer.text, "<redacted>");
        assert_eq!(usage.map(|counts| counts.output_tokens), Some(19));
        Ok(())
    }

    #[test]
    fn trace_redacts_malformed_frames_and_preserves_a_rejected_late_answer() {
        assert_eq!(
            redact_stream(b"data: malformed-secret\n\n"),
            b"data: !redacted-invalid-json\n\n"
        );
        let input = b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"late-secret\"}}]}\n\ndata: [DONE]\n\n";
        let trace = redact_stream(input);
        assert!(!String::from_utf8_lossy(&trace).contains("secret"));
        assert!(matches!(
            crate::stream::parse(trace.as_slice()),
            Err(irmind_app::AppError::Fixed(
                irmind_app::FixedAppError::AdapterModel(
                    irmind_app::AdapterModelError::ProviderOutputAfterFinish,
                )
            ))
        ));
    }

    #[test]
    fn trace_bounds_the_redacted_output() {
        let trace = redact_stream(&b": private\n".repeat(MAX_TRACE_BYTES));
        assert!(trace.len() <= MAX_TRACE_BYTES);
        assert!(trace.ends_with(b": diagnostic capture reached its size limit\n\n"));
    }
}
