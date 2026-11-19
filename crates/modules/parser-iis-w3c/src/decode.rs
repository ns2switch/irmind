use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceNumber, SourceRecordV1,
        SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter, text_frame},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::BufReader,
    sync::Arc,
};

pub struct IisW3cSourceDecoder;

const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;
const MAX_FIELDS: usize = 128;
const MAX_LINE: usize = 65_536;

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}

fn content(input: &[u8]) -> &[u8] {
    input
        .strip_prefix(b"\xef\xbb\xbf")
        .unwrap_or(input)
        .trim_ascii()
}

#[derive(Clone)]
struct Columns {
    names: Arc<[String]>,
    size: usize,
}

impl Columns {
    fn new(raw: &[u8]) -> Result<Self, AppError> {
        if raw.len() > MAX_LINE {
            return Err(invalid());
        }
        let text = std::str::from_utf8(raw).map_err(|_| invalid())?;
        let names: Vec<String> = text
            .split_ascii_whitespace()
            .take(MAX_FIELDS + 1)
            .map(str::to_owned)
            .collect();
        let keys: BTreeSet<&str> = names.iter().map(String::as_str).collect();
        if names.len() > MAX_FIELDS
            || names.len() != keys.len()
            || !keys.contains("date")
            || !keys.contains("time")
            || !keys
                .iter()
                .any(|key| matches!(*key, "cs-method" | "cs-uri-stem" | "sc-status"))
            || names.iter().any(|name| {
                name.len() > 128
                    || !name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-()".contains(&byte))
            })
        {
            return Err(invalid());
        }
        let size = raw.len();
        Ok(Self {
            names: names.into(),
            size,
        })
    }
}

fn decode_record(input: &[u8], columns: Option<Columns>) -> Result<DecodedSourceFrame, AppError> {
    let columns = columns.ok_or_else(invalid)?;
    if input.len() > MAX_LINE {
        return Err(invalid());
    }
    let input = std::str::from_utf8(content(input)).map_err(|_| invalid())?;
    let mut values = input.split_ascii_whitespace();
    let mut fields = BTreeMap::new();
    for name in columns.names.iter() {
        let value = values.next().ok_or_else(invalid)?;
        let field = match name.as_str() {
            "sc-status" | "sc-bytes" | "cs-bytes" | "s-port" | "c-port"
                if value != "-" && value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                let number = value.parse::<u64>().map_err(|_| invalid())?;
                SourceValue::Number(
                    SourceNumber::try_new(&number.to_string()).map_err(|_| invalid())?,
                )
            }
            _ => SourceValue::Text(value.to_owned()),
        };
        fields.insert(name.clone(), field);
    }
    if values.next().is_some() {
        return Err(invalid());
    }
    let date = fields
        .get("date")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    let time = fields
        .get("time")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?;
    if date.len() != 10 || !(8..=18).contains(&time.len()) {
        return Err(invalid());
    }
    let timestamp =
        IndexedTime::from_rfc3339(&format!("{date}T{time}Z"), false).map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields: SourceValue::object(fields.into_iter().collect()).map_err(|_| invalid())?,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new("iis-w3c", super::VERSION, BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}

impl SourceDecoder for IisW3cSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: super::PARSER,
            version: super::VERSION,
        }
    }

    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        self.decode_with_budget(DecodeInput::Reader(input), DecodeBudget::sequential(), emit)
    }

    fn decode_with_budget(
        &self,
        input: DecodeInput<'_>,
        budget: DecodeBudget,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let input = input.into_reader();
        let cancel = input.metadata.cancel;
        let mut reader = BufReader::new(input.reader);
        let mut columns: Option<Columns> = None;
        let mut offset = 0;
        let mut output = SourceFrameEmitter::new(input.metadata, self.identity());
        output.decode_frames(
            budget,
            || {
                loop {
                    let Some((line, consumed)) =
                        text_frame(&mut reader, cancel, MAX_SOURCE - offset)?
                    else {
                        return Ok(None);
                    };
                    let start = offset;
                    offset += consumed;
                    let trimmed = content(&line);
                    if let Some(fields) = trimmed.strip_prefix(b"#Fields:") {
                        columns = Columns::new(fields).ok();
                        if columns.is_none() {
                            return Ok(Some((line, Some(start), None)));
                        }
                        continue;
                    }
                    if trimmed.is_empty()
                        || (trimmed.starts_with(b"#") && consumed <= MAX_LINE as u64)
                    {
                        continue;
                    }
                    return Ok(Some((line, Some(start), columns.clone())));
                }
            },
            decode_record,
            |columns| columns.as_ref().map_or(0, |value| value.size),
            emit,
        )?;
        Ok(output.finish())
    }
}

pub(super) fn detect(sample: &[u8]) -> bool {
    let sample = &sample[..sample.len().min(MAX_LINE)];
    let mut software = false;
    for line in sample.split(|&byte| byte == b'\n') {
        let line = content(line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with(b"#Software: Microsoft Internet Information Services") {
            software = true;
        }
        if let Some(fields) = line.strip_prefix(b"#Fields:") {
            return Columns::new(fields).is_ok_and(|columns| {
                software
                    || columns.names.iter().any(|name| {
                        matches!(
                            name.as_str(),
                            "sc-win32-status" | "cs-uri-stem" | "sc-substatus"
                        )
                    })
            });
        }
        if !line.starts_with(b"#") {
            return false;
        }
    }
    false
}
