use super::MAX_STREAM_BYTES;
use irmind_app::AppError;
use serde_json::Value;

#[derive(Default)]
pub(crate) struct TextPreview {
    pending: Vec<u8>,
    event: String,
    data: String,
}

impl TextPreview {
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<String>, AppError> {
        self.pending.extend_from_slice(chunk);
        if self.pending.len() > MAX_STREAM_BYTES {
            return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                irmind_app::AdapterModelError::ProviderStreamExceeds2MB,
            )));
        }
        let mut text = Vec::new();
        while let Some(end) = self.pending.iter().position(|byte| *byte == b'\n') {
            let line = self.pending.drain(..=end).collect::<Vec<_>>();
            let line = std::str::from_utf8(&line)
                .map_err(|_| {
                    AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                        irmind_app::AdapterModelError::UnexpectedProviderStreamField,
                    ))
                })?
                .trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                if !self.event.is_empty() && !self.data.is_empty() {
                    let value: Value = serde_json::from_str(&self.data).map_err(|_| {
                        AppError::Fixed(irmind_app::FixedAppError::AdapterModel(
                            irmind_app::AdapterModelError::UnexpectedProviderStreamField,
                        ))
                    })?;
                    let part = match self.event.as_str() {
                        "content_block_start" if value["content_block"]["type"] == "text" => {
                            value["content_block"]["text"].as_str()
                        }
                        "content_block_delta" if value["delta"]["type"] == "text_delta" => {
                            value["delta"]["text"].as_str()
                        }
                        _ => None,
                    };
                    if let Some(part) = part.filter(|part| !part.is_empty()) {
                        text.push(part.to_owned());
                    }
                }
                self.event.clear();
                self.data.clear();
            } else if let Some(event) = line.strip_prefix("event:") {
                self.event.push_str(event.trim_start());
            } else if let Some(data) = line.strip_prefix("data:") {
                self.data.push_str(data.trim_start());
            }
        }
        Ok(text)
    }
}
