//! Streaming record boundaries. An oversized first line is never consumed as a sample.
use irmind_app::{AppError, CancellationToken};
use std::{
    collections::BTreeSet,
    io::{BufRead, BufReader, Read},
};

const MAX_RECORD: usize = 4 * 1024 * 1024;

pub(super) struct Frame {
    pub(super) bytes: Vec<u8>,
    pub(super) offset: u64,
    pub(super) oversized: bool,
}
struct Capture(Vec<u8>, bool);
impl Capture {
    fn push(&mut self, byte: u8) {
        if self.0.len() <= MAX_RECORD {
            self.0.push(byte);
        } else {
            self.1 = true;
        }
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Roots,
    Array { wrapped: bool, comma: bool },
}

pub(super) struct Frames<'a> {
    input: BufReader<&'a mut dyn Read>,
    cancel: &'a CancellationToken,
    position: u64,
    mode: Mode,
    wrapper_keys: BTreeSet<String>,
}
impl<'a> Frames<'a> {
    pub(super) fn new(reader: &'a mut dyn Read, cancel: &'a CancellationToken) -> Self {
        Self {
            input: BufReader::new(reader),
            cancel,
            position: 0,
            mode: Mode::Roots,
            wrapper_keys: BTreeSet::new(),
        }
    }
    pub(super) fn next(&mut self) -> Result<Option<Frame>, AppError> {
        loop {
            self.whitespace(&mut None)?;
            match self.mode {
                Mode::Roots => match self.peek()? {
                    None => return Ok(None),
                    Some(b'[') => {
                        self.byte()?;
                        self.mode = Mode::Array {
                            wrapped: false,
                            comma: false,
                        };
                    }
                    Some(b'{') => {
                        if let Some(frame) = self.object()? {
                            return Ok(Some(frame));
                        }
                    }
                    _ => return self.value_frame(),
                },
                Mode::Array { wrapped, comma } => {
                    if self.array_separator(wrapped, comma)? {
                        continue;
                    }
                    self.mode = Mode::Array {
                        wrapped,
                        comma: true,
                    };
                    return self.value_frame();
                }
            }
        }
    }
    fn array_separator(&mut self, wrapped: bool, comma: bool) -> Result<bool, AppError> {
        if self.peek()? == Some(b']') {
            self.byte()?;
            if wrapped {
                self.finish_wrapper()?;
            }
            self.mode = Mode::Roots;
            return Ok(true);
        }
        if comma {
            if self.byte()? != b',' {
                return Err(invalid());
            }
            self.whitespace(&mut None)?;
            if self.peek()? == Some(b']') {
                return Err(invalid());
            }
        }
        Ok(false)
    }
    fn value_frame(&mut self) -> Result<Option<Frame>, AppError> {
        let offset = self.position;
        let mut bytes = Capture(Vec::new(), false);
        self.value(&mut bytes)?;
        Ok(Some(Frame {
            oversized: bytes.1 || bytes.0.len() > MAX_RECORD,
            bytes: bytes.0,
            offset,
        }))
    }
    fn object(&mut self) -> Result<Option<Frame>, AppError> {
        let offset = self.position;
        let mut bytes = Capture(Vec::new(), false);
        bytes.push(self.byte()?);
        let mut keys = BTreeSet::new();
        let mut duplicates = false;
        self.whitespace(&mut Some(&mut bytes))?;
        while self.peek()? != Some(b'}') {
            let metadata_end = bytes.0.len();
            let key = self.key(&mut bytes)?;
            duplicates |= !keys.insert(key.clone());
            if keys.len() > 1024 {
                return Err(invalid());
            }
            if matches!(key.as_str(), "Records" | "records" | "events")
                && self.peek()? == Some(b'[')
            {
                if duplicates || bytes.1 || !valid_prefix(&bytes.0[..metadata_end]) {
                    return Err(invalid());
                }
                self.byte()?;
                self.wrapper_keys = keys;
                self.mode = Mode::Array {
                    wrapped: true,
                    comma: false,
                };
                return Ok(None);
            }
            self.value(&mut bytes)?;
            self.whitespace(&mut Some(&mut bytes))?;
            if self.peek()? != Some(b',') {
                break;
            }
            bytes.push(self.byte()?);
            self.whitespace(&mut Some(&mut bytes))?;
            if self.peek()? == Some(b'}') {
                return Err(invalid());
            }
        }
        if self.byte()? != b'}' {
            return Err(invalid());
        }
        bytes.push(b'}');
        Ok(Some(Frame {
            oversized: bytes.1 || bytes.0.len() > MAX_RECORD,
            bytes: bytes.0,
            offset,
        }))
    }
    fn finish_wrapper(&mut self) -> Result<(), AppError> {
        let mut bytes = Capture(Vec::new(), false);
        self.whitespace(&mut Some(&mut bytes))?;
        while self.peek()? == Some(b',') {
            bytes.push(self.byte()?);
            let key = self.key(&mut bytes)?;
            if self.wrapper_keys.len() >= 1024
                || !self.wrapper_keys.insert(key.clone())
                || matches!(key.as_str(), "Records" | "records" | "events")
            {
                return Err(invalid());
            }
            self.value(&mut bytes)?;
            self.whitespace(&mut Some(&mut bytes))?;
            if bytes.1 {
                return Err(invalid());
            }
        }
        if self.byte()? != b'}' {
            return Err(invalid());
        }
        self.wrapper_keys.clear();
        if !valid_tail(&bytes.0) {
            return Err(invalid());
        }
        Ok(())
    }
    fn key(&mut self, bytes: &mut Capture) -> Result<String, AppError> {
        self.whitespace(&mut Some(bytes))?;
        let mut key = Capture(Vec::new(), false);
        self.value(&mut key)?;
        if key.0.len() > 1538 {
            return Err(invalid());
        }
        let decoded: String = serde_json::from_slice(&key.0).map_err(|_| invalid())?;
        if decoded.is_empty() || decoded.len() > 256 {
            return Err(invalid());
        }
        for byte in key.0 {
            bytes.push(byte);
        }
        self.whitespace(&mut Some(bytes))?;
        if self.byte()? != b':' {
            return Err(invalid());
        }
        bytes.push(b':');
        self.whitespace(&mut Some(bytes))?;
        Ok(decoded)
    }
    fn value(&mut self, output: &mut Capture) -> Result<(), AppError> {
        let first = self.byte()?;
        output.push(first);
        let mut depth = usize::from(matches!(first, b'{' | b'['));
        let mut quoted = first == b'"';
        let mut escaped = false;
        if depth == 0 && !quoted {
            while self
                .peek()?
                .is_some_and(|b| !matches!(b, b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}'))
            {
                output.push(self.byte()?);
            }
            return Ok(());
        }
        loop {
            let byte = self.byte()?;
            output.push(byte);
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
            } else {
                match byte {
                    b'"' => quoted = true,
                    b'{' | b'[' => depth = depth.checked_add(1).ok_or_else(invalid)?,
                    b'}' | b']' => depth = depth.checked_sub(1).ok_or_else(invalid)?,
                    _ => {}
                }
            }
            if depth == 0 && !quoted {
                return Ok(());
            }
        }
    }
    fn whitespace(&mut self, output: &mut Option<&mut Capture>) -> Result<(), AppError> {
        while matches!(self.peek()?, Some(b' ' | b'\n' | b'\r' | b'\t')) {
            let byte = self.byte()?;
            if let Some(output) = output {
                output.push(byte);
            }
        }
        Ok(())
    }
    fn peek(&mut self) -> Result<Option<u8>, AppError> {
        if self.position.is_multiple_of(4096) && self.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        self.input
            .fill_buf()
            .map(|v| v.first().copied())
            .map_err(|_| invalid())
    }
    fn byte(&mut self) -> Result<u8, AppError> {
        let byte = self.peek()?.ok_or_else(invalid)?;
        self.input.consume(1);
        self.position = self.position.checked_add(1).ok_or_else(invalid)?;
        Ok(byte)
    }
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}

fn valid_prefix(prefix: &[u8]) -> bool {
    let prefix = trim(prefix);
    let prefix = prefix.strip_suffix(b",").unwrap_or(prefix);
    let mut document = prefix.to_vec();
    document.push(b'}');
    valid_metadata(&document)
}
fn valid_tail(tail: &[u8]) -> bool {
    let tail = trim(tail);
    let tail = tail.strip_prefix(b",").unwrap_or(tail);
    let mut document = vec![b'{'];
    document.extend_from_slice(tail);
    document.push(b'}');
    valid_metadata(&document)
}
fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}
fn valid_metadata(bytes: &[u8]) -> bool {
    irmind_app::source_mapping::json::validate_json_value(
        bytes,
        irmind_app::source_mapping::json::SourceJsonLimits::default(),
    )
    .is_ok()
}
