use crate::{AppError, config::Format, error};
use irmind_app::CancellationToken;
use std::io::BufRead;

const MAX_SOURCE_BYTES: u64 = 50 * 1024 * 1024 * 1024;

pub(crate) struct Frame {
    pub bytes: Vec<u8>,
    pub consumed: u64,
    pub leading: u64,
    pub invalid: bool,
}

impl Frame {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            consumed: 0,
            leading: 0,
            invalid: false,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum JsonMode {
    Unknown,
    Single,
    Array,
    Closed,
}

pub(crate) struct Frames<R> {
    reader: R,
    format: Format,
    maximum: usize,
    json_mode: JsonMode,
    separator: bool,
    after_comma: bool,
    finished: bool,
    total: u64,
}

impl<R: BufRead> Frames<R> {
    pub(crate) fn new(reader: R, format: Format, maximum: usize) -> Self {
        Self {
            reader,
            format,
            maximum,
            json_mode: JsonMode::Unknown,
            separator: false,
            after_comma: false,
            finished: false,
            total: 0,
        }
    }

    pub(crate) fn next(&mut self, cancel: &CancellationToken) -> Result<Option<Frame>, AppError> {
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if self.finished {
            return Ok(None);
        }
        if self.format == Format::Json {
            self.json(cancel)
        } else {
            self.line(cancel)
        }
    }

    fn account(&mut self, bytes: usize) -> Result<(), AppError> {
        self.total = self
            .total
            .checked_add(bytes as u64)
            .ok_or_else(|| error("source size overflow"))?;
        if self.total > MAX_SOURCE_BYTES {
            return Err(error("declarative source exceeds 50 GiB"));
        }
        Ok(())
    }

    fn line(&mut self, cancel: &CancellationToken) -> Result<Option<Frame>, AppError> {
        let mut frame = Frame::new();
        let mut quoted = false;
        loop {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let bytes = self
                .reader
                .fill_buf()
                .map_err(|_| error("cannot read declarative source"))?;
            if bytes.is_empty() {
                self.finished = true;
                return Ok((frame.consumed != 0).then_some(frame));
            }
            let mut end = bytes.len();
            let mut complete = false;
            for (index, byte) in bytes.iter().enumerate() {
                if self.format == Format::Csv && *byte == b'"' {
                    quoted = !quoted;
                }
                if *byte == b'\n' && !quoted {
                    end = index + 1;
                    complete = true;
                    break;
                }
            }
            let room = self
                .maximum
                .saturating_add(1)
                .saturating_sub(frame.bytes.len());
            frame.bytes.extend_from_slice(&bytes[..end.min(room)]);
            frame.consumed += end as u64;
            self.reader.consume(end);
            self.account(end)?;
            if complete {
                return Ok(Some(frame));
            }
        }
    }

    fn peek(&mut self) -> Result<Option<u8>, AppError> {
        self.reader
            .fill_buf()
            .map(|bytes| bytes.first().copied())
            .map_err(|_| error("cannot read declarative JSON source"))
    }

    fn byte(&mut self, cancel: &CancellationToken) -> Result<Option<u8>, AppError> {
        if self.total.is_multiple_of(4096) && cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let value = self.peek()?;
        if value.is_some() {
            self.reader.consume(1);
            self.account(1)?;
        }
        Ok(value)
    }

    fn json(&mut self, cancel: &CancellationToken) -> Result<Option<Frame>, AppError> {
        if self.json_mode == JsonMode::Closed {
            return self.trailing(cancel);
        }
        let mut frame = Frame::new();
        while let Some(byte) = self.byte(cancel)? {
            frame.consumed += 1;
            if byte.is_ascii_whitespace() {
                continue;
            }
            if self.json_mode == JsonMode::Unknown {
                self.json_mode = if byte == b'[' {
                    JsonMode::Array
                } else {
                    JsonMode::Single
                };
                if byte == b'[' {
                    continue;
                }
            } else if self.json_mode == JsonMode::Array {
                if byte == b']' {
                    self.json_mode = JsonMode::Closed;
                    if self.after_comma {
                        frame.bytes.push(byte);
                        frame.invalid = true;
                        return Ok(Some(frame));
                    }
                    return self.trailing_after(frame, cancel);
                }
                if self.separator && byte == b',' {
                    self.separator = false;
                    self.after_comma = true;
                    continue;
                }
                if byte == b',' {
                    frame.bytes.push(byte);
                    frame.invalid = true;
                    self.after_comma = true;
                    return Ok(Some(frame));
                }
                frame.invalid = self.separator;
            } else if self.separator {
                frame.invalid = true;
            }
            frame.leading = frame.consumed - 1;
            frame.bytes.push(byte);
            frame.invalid |= byte != b'{';
            self.value(&mut frame, byte, cancel)?;
            self.separator = true;
            self.after_comma = false;
            return Ok(Some(frame));
        }
        self.finished = true;
        if self.json_mode == JsonMode::Array {
            frame.invalid = true;
            frame.bytes = b"[".to_vec();
            return Ok(Some(frame));
        }
        Ok(None)
    }

    fn value(
        &mut self,
        frame: &mut Frame,
        first: u8,
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let mut depth = usize::from(matches!(first, b'{' | b'['));
        let mut quoted = first == b'"';
        let mut escaped = false;
        while let Some(next) = self.peek()? {
            if !quoted && depth == 0 && (next.is_ascii_whitespace() || matches!(next, b',' | b']'))
            {
                return Ok(());
            }
            let Some(byte) = self.byte(cancel)? else {
                break;
            };
            frame.consumed += 1;
            if frame.bytes.len() <= self.maximum {
                frame.bytes.push(byte);
            }
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                    if depth == 0 {
                        return Ok(());
                    }
                }
            } else {
                match byte {
                    b'"' => quoted = true,
                    b'{' | b'[' => depth = depth.saturating_add(1),
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return Ok(());
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn trailing(&mut self, cancel: &CancellationToken) -> Result<Option<Frame>, AppError> {
        self.trailing_after(Frame::new(), cancel)
    }

    fn trailing_after(
        &mut self,
        mut frame: Frame,
        cancel: &CancellationToken,
    ) -> Result<Option<Frame>, AppError> {
        while let Some(byte) = self.byte(cancel)? {
            frame.consumed += 1;
            if !byte.is_ascii_whitespace() || !frame.bytes.is_empty() {
                if frame.bytes.len() <= self.maximum {
                    frame.bytes.push(byte);
                }
                frame.invalid = true;
            }
        }
        self.finished = true;
        Ok(frame.invalid.then_some(frame))
    }
}
