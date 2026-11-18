use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceDiscriminator, SourceFormatV1, SourceInput,
        SourceMetadata, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter, text_frame},
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Read},
};
pub struct VpcFlowSourceDecoder;
const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;
const DEFAULT: &[&str] = &[
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
];
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn header(line: &str) -> Option<Vec<String>> {
    let names: Vec<_> = line.split_ascii_whitespace().map(str::to_owned).collect();
    if names.len() > 64
        || names.len() < 3
        || !names.iter().any(|s| s == "version")
        || !names.iter().any(|s| matches!(s.as_str(), "start" | "end"))
        || !names.iter().any(|s| s == "srcaddr")
        || !names.iter().any(|s| s == "dstaddr")
        || names.iter().collect::<BTreeSet<_>>().len() != names.len()
        || names
            .iter()
            .any(|s| s.len() > 64 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    {
        return None;
    }
    Some(names)
}
fn prepare(
    bytes: &[u8],
    names: &[String],
    _compressed: bool,
    declared: bool,
) -> Result<DecodedSourceFrame, AppError> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let values: Vec<_> = text.split_ascii_whitespace().collect();
    if values.len() != names.len()
        || (!declared && values.first() != Some(&"2"))
        || bytes.len() > irmind_domain::SOURCE_MAX_BYTES
    {
        return Err(invalid());
    }
    let columns = names
        .iter()
        .cloned()
        .zip(values.iter().map(|v| SourceValue::Text((*v).to_owned())))
        .collect::<BTreeMap<_, _>>();
    let time = columns
        .get("start")
        .or_else(|| columns.get("end"))
        .and_then(SourceValue::as_text)
        .filter(|v| *v != "-");
    let timestamp = time
        .map(|v| IndexedTime::from_epoch_decimal(v, false).map_err(|_| invalid()))
        .transpose()?;
    let fields = SourceValue::object(vec![(
        "columns".into(),
        SourceValue::object(columns.into_iter().collect()).map_err(|_| invalid())?,
    )])
    .map_err(|_| invalid())?;
    let format = SourceFormatV1::try_new(
        "aws-vpc-flow",
        "vpc-flow-source-v1",
        BTreeMap::from([(
            SourceDiscriminator::Dataset,
            if declared { "header" } else { "default-v2" }.into(),
        )]),
    )
    .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp,
        format,
    })
}
impl SourceDecoder for VpcFlowSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-vpc-flow",
            version: "vpc-flow-source-v1",
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
        let mut reader = BufReader::new(input.reader);
        if reader
            .fill_buf()
            .map_err(|_| invalid())?
            .starts_with(&[0x1f, 0x8b])
        {
            let compressed = crate::gzip::bounded(reader, input.metadata.cancel);
            let gzip = flate2::read::MultiGzDecoder::new(compressed);
            let mut decoded = crate::gzip::bounded(gzip, input.metadata.cancel);
            let result = lines(&mut decoded, input.metadata, true, budget, emit);
            if input.metadata.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            if decoded.exceeded() || decoded.inner().get_ref().exceeded() {
                return Err(AppError::Fixed(FixedAppError::SourceLimit));
            }
            result
        } else {
            lines(&mut reader, input.metadata, false, budget, emit)
        }
    }
}
fn lines(
    reader: &mut dyn Read,
    metadata: SourceMetadata<'_>,
    compressed: bool,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut limited = reader.take(MAX_SOURCE + 1);
    let mut reader = BufReader::new(&mut limited);
    let json = reader
        .fill_buf()
        .map_err(|_| invalid())?
        .trim_ascii_start()
        .first()
        == Some(&b'{');
    let result = if json {
        json_lines(&mut reader, metadata, compressed, budget, emit)
    } else {
        text_lines(&mut reader, metadata, compressed, budget, emit)
    };
    drop(reader);
    if limited.limit() == 0 {
        return Err(AppError::Fixed(FixedAppError::SourceLimit));
    }
    result
}
fn json_lines(
    reader: &mut dyn Read,
    metadata: SourceMetadata<'_>,
    compressed: bool,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut output = SourceFrameEmitter::new(metadata, VpcFlowSourceDecoder.identity());
    let mut names: Vec<String> = DEFAULT.iter().map(|s| (*s).to_owned()).collect();
    let mut declared = false;
    let mut frames = JsonFrames::new(reader, metadata.cancel)
        .with_record_array_keys(&["events", "logEvents"])?;
    output.decode_frames(
        budget,
        || loop {
            let Some(frame) = frames.next_frame()? else {
                return Ok(None);
            };
            let fields = decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok();
            let message = fields
                .as_ref()
                .and_then(|v| v.field("message"))
                .and_then(SourceValue::as_text);
            if let Some(message) = message
                && let Some(found) = header(message)
            {
                names = found;
                declared = true;
                continue;
            }
            let at = (!compressed).then_some(frame.offset());
            let bad = message.is_none();
            let bytes = message.map_or_else(|| frame.bytes().to_vec(), |v| v.as_bytes().to_vec());
            return Ok(Some((bytes, at, (names.clone(), declared, bad))));
        },
        |bytes, (names, declared, bad)| {
            if bad {
                Err(invalid())
            } else {
                prepare(bytes, &names, compressed, declared)
            }
        },
        |(names, _, _)| names.iter().map(String::len).sum(),
        emit,
    )?;
    Ok(output.finish())
}
fn text_lines(
    reader: &mut dyn Read,
    metadata: SourceMetadata<'_>,
    compressed: bool,
    budget: DecodeBudget,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let mut reader = BufReader::new(reader);
    let mut output = SourceFrameEmitter::new(metadata, VpcFlowSourceDecoder.identity());
    let mut names: Vec<String> = DEFAULT.iter().map(|s| (*s).to_owned()).collect();
    let mut declared = false;
    let mut offset = 0;
    output.decode_frames(
        budget,
        || loop {
            let Some((bytes, size)) =
                text_frame(&mut reader, metadata.cancel, MAX_SOURCE - offset)?
            else {
                return Ok(None);
            };
            let at = offset;
            offset += size;
            if bytes.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if let Ok(text) = std::str::from_utf8(&bytes)
                && let Some(found) = header(text)
            {
                names = found;
                declared = true;
                continue;
            }
            return Ok(Some((
                bytes,
                (!compressed).then_some(at),
                (names.clone(), declared),
            )));
        },
        |bytes, (names, declared)| prepare(bytes, &names, compressed, declared),
        |(names, _)| names.iter().map(String::len).sum(),
        emit,
    )?;
    Ok(output.finish())
}
pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let expanded = if sample.starts_with(&[0x1f, 0x8b]) {
        crate::gzip::sample(sample)
    } else {
        sample.to_vec()
    };
    let first = expanded
        .split(|b| *b == b'\n')
        .find(|line| !line.iter().all(u8::is_ascii_whitespace))?;
    let text = if expanded.trim_ascii_start().first() == Some(&b'{') {
        let cancel = irmind_app::CancellationToken::new();
        let mut input = std::io::Cursor::new(&expanded);
        let mut frames = JsonFrames::new(&mut input, &cancel)
            .with_record_array_keys(&["events", "logEvents"])
            .ok()?;
        let frame = frames.next_frame().ok()??;
        let fields = decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok()?;
        fields
            .field("message")
            .and_then(SourceValue::as_text)?
            .to_owned()
    } else {
        std::str::from_utf8(first).ok()?.to_owned()
    };
    if header(&text).is_some() {
        return Some(98);
    }
    let values: Vec<_> = text.split_ascii_whitespace().collect();
    if values.len() != 14 || values[0] != "2" || !matches!(values[13], "OK" | "NODATA" | "SKIPDATA")
    {
        return None;
    }
    prepare(
        text.as_bytes(),
        &DEFAULT.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        false,
        false,
    )
    .ok()
    .map(|_| 70)
}
