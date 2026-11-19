use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, ParserTimeContext, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceFormatV1, SourceInput, SourceRecordV1, SourceValue,
        framed::{DecodedSourceFrame, SourceFrameEmitter, text_frame},
    },
};
use irmind_domain::{IndexedTime, Tainted};
use std::{collections::BTreeMap, io::BufReader};

mod packet;
use packet::Packet;

pub struct WindowsDnsSourceDecoder;

const MAX_SOURCE: u64 = 50 * 1024 * 1024 * 1024;
const MAX_HEADER: u32 = 65_536;
const MAX_PACKET: usize = 8192;

fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}

fn content(input: &[u8]) -> &[u8] {
    input
        .strip_prefix(b"\xef\xbb\xbf")
        .unwrap_or(input)
        .trim_ascii()
}

fn log_header(input: &[u8]) -> bool {
    content(input).starts_with(b"DNS Server log file creation at ")
}

fn packet_line(line: &[u8]) -> bool {
    line.split(u8::is_ascii_whitespace)
        .filter(|part| !part.is_empty())
        .nth(4)
        == Some(b"PACKET")
}

fn decode_packet(bytes: &[u8], context: ParserTimeContext) -> Result<DecodedSourceFrame, AppError> {
    if bytes.len() > MAX_PACKET {
        return Err(invalid());
    }
    let raw = std::str::from_utf8(content(bytes)).map_err(|_| invalid())?;
    let packet = Packet::parse(raw).ok_or_else(invalid)?;
    let datetime = packet
        .datetime(&context.offset_text())
        .ok_or_else(invalid)?;
    let timestamp = IndexedTime::from_rfc3339(&datetime, true).map_err(|_| invalid())?;
    let mut fields = vec![
        ("date", packet.date.to_owned()),
        ("clock", packet.clock.to_owned()),
        ("meridiem", packet.meridiem.to_owned()),
        ("thread", packet.thread.to_owned()),
        ("packet_context", packet.pointer.to_owned()),
        ("transport", packet.transport.to_owned()),
        ("direction", packet.direction.to_owned()),
        ("remote_ip", packet.remote.to_owned()),
        ("transaction_id", packet.xid.to_owned()),
        ("message", packet.message.to_owned()),
        ("opcode", packet.opcode.to_owned()),
        ("flags", packet.flags.to_owned()),
        ("response_code", packet.rcode.to_owned()),
        ("query_type", packet.qtype.to_owned()),
        ("query_name_native", packet.original_name().to_owned()),
    ];
    if let Some(name) = packet.domain() {
        fields.push(("query_name", name));
    }
    if let Some(trailing) = packet.trailing {
        fields.push(("additional_text", trailing.to_owned()));
    }
    let fields = SourceValue::object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), SourceValue::Text(value)))
            .collect(),
    )
    .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format: SourceFormatV1::try_new("windows-dns-debug", super::VERSION, BTreeMap::new())
            .map_err(|_| invalid())?,
    })
}

impl SourceDecoder for WindowsDnsSourceDecoder {
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
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let context = input.metadata.time_context.copied().ok_or_else(|| {
            AppError::Policy(
                "Windows DNS debug logs require a confirmed fixed UTC offset and first packet year"
                    .into(),
            )
        })?;
        let mut reader = BufReader::new(input.reader);
        let (header, mut offset) =
            text_frame(&mut reader, cancel, u64::from(MAX_HEADER))?.ok_or_else(invalid)?;
        if !log_header(&header) {
            return Err(invalid());
        }
        let mut started = false;
        let mut first_validated = false;
        let mut output = SourceFrameEmitter::new(input.metadata, self.identity());
        output.decode_frames(
            budget,
            || {
                loop {
                    let Some((line, consumed)) =
                        text_frame(&mut reader, cancel, MAX_SOURCE.saturating_sub(offset))?
                    else {
                        return Ok(None);
                    };
                    let start = offset;
                    offset += consumed;
                    if content(&line).is_empty() {
                        continue;
                    }
                    if !started && packet_line(&line) {
                        started = true;
                    }
                    if !started && offset <= u64::from(MAX_HEADER) {
                        continue;
                    }
                    if !first_validated && let Some(packet) = read_packet(&line)
                        && packet.datetime("Z").is_some_and(|datetime| IndexedTime::from_rfc3339(&datetime, false).is_ok())
                        && let Some(year) = packet.year()
                    {
                        if year != context.year() {
                            return Err(AppError::Policy(
                                "Windows DNS debug first packet year differs from the confirmed year".into(),
                            ));
                        }
                        first_validated = true;
                    }
                    return Ok(Some((line, Some(start), ())));
                }
            },
            |line, ()| decode_packet(line, context),
            |()| 0,
            emit,
        )?;
        Ok(output.finish())
    }
}

fn read_packet(bytes: &[u8]) -> Option<Packet<'_>> {
    (bytes.len() <= MAX_PACKET)
        .then(|| Packet::parse(std::str::from_utf8(content(bytes)).ok()?))
        .flatten()
}

pub(super) fn detect(sample: &[u8]) -> Option<(u16, u8)> {
    let sample = &sample[..sample.len().min(MAX_HEADER as usize)];
    let mut lines = sample.split(|&byte| byte == b'\n');
    if !log_header(lines.next()?) {
        return None;
    }
    let first = lines.find(|line| packet_line(line))?;
    let packet = read_packet(first)?;
    IndexedTime::from_rfc3339(&packet.datetime("Z")?, false).ok()?;
    let score = if packet.day()? > 12 { 98 } else { 79 };
    Some((packet.year()?, score))
}
