use irmind_app::{
    AppError, FixedAppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeBudget, DecodeInput, SourceDiscriminator, SourceFormatV1, SourceInput,
        SourceRecordV1, SourceValue,
        framed::{
            DecodedSourceFrame, SourceFrameEmitter, csv_frame, csv_values,
            decode_json_named_envelope_source, source_datetime,
        },
        json::{JsonFrames, SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::Tainted;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
};
pub struct DefenderSourceDecoder;
fn invalid() -> AppError {
    AppError::Fixed(FixedAppError::SourceFormat)
}
fn text<'a>(fields: &'a SourceValue, key: &str) -> Option<&'a str> {
    fields.field(key).and_then(SourceValue::as_text)
}
fn view(fields: &SourceValue) -> Option<(&SourceValue, bool)> {
    if let Some(category) = text(fields, "category")
        && category.starts_with("AdvancedHunting-")
    {
        let inner = fields.field("properties")?;
        return matches!(inner, SourceValue::Object(_)).then_some((inner, true));
    }
    Some((fields, false))
}
fn native(fields: &SourceValue) -> bool {
    text(fields, "Timestamp").is_some()
        && ((text(fields, "DeviceId").is_some() && text(fields, "ActionType").is_some())
            || (text(fields, "AlertId").is_some()
                && (fields.field("Title").is_some() || fields.field("EntityType").is_some())))
}
fn dataset<'a>(outer: &'a SourceValue, fields: &'a SourceValue) -> &'a str {
    if let Some(category) = text(outer, "category").and_then(|s| s.strip_prefix("AdvancedHunting-"))
    {
        return category;
    }
    for key in ["Table", "$table", "Type"] {
        if let Some(table) = text(fields, key) {
            return table;
        }
    }
    if fields.field("AlertId").is_some() {
        return if fields.field("Title").is_some() {
            "AlertInfo"
        } else {
            "AlertEvidence"
        };
    }
    if fields.field("RegistryKey").is_some() {
        return "DeviceRegistryEvents";
    }
    if fields.field("RemoteIP").is_some() && fields.field("LocalIP").is_some() {
        return "DeviceNetworkEvents";
    }
    if fields.field("LogonType").is_some() {
        return "DeviceLogonEvents";
    }
    if fields.field("ProcessId").is_some() && fields.field("ProcessCommandLine").is_some() {
        return "DeviceProcessEvents";
    }
    match text(fields, "ActionType") {
        Some("ImageLoaded") => "DeviceImageLoadEvents",
        Some("FileCreated" | "FileModified" | "FileDeleted" | "FileRenamed") => "DeviceFileEvents",
        _ => "UnknownDeviceEvents",
    }
}
fn prepare(fields: SourceValue, csv: bool) -> Result<DecodedSourceFrame, AppError> {
    let (inner, stream) = view(&fields).ok_or_else(invalid)?;
    if !native(inner) {
        return Err(invalid());
    }
    let raw = text(inner, "Timestamp").ok_or_else(invalid)?;
    // Advanced Hunting Timestamp is UTC; an omitted suffix is interpreted only
    // under this documented source contract, never from the machine clock.
    let timestamp =
        source_datetime(raw, None).or_else(|_| source_datetime(&format!("{raw}Z"), None))?;
    let raw_dataset = dataset(&fields, inner);
    let dataset = match raw_dataset {
        "DeviceProcessEvents"
        | "DeviceNetworkEvents"
        | "DeviceFileEvents"
        | "DeviceRegistryEvents"
        | "DeviceLogonEvents"
        | "DeviceImageLoadEvents"
        | "DeviceEvents"
        | "AlertInfo"
        | "AlertEvidence" => raw_dataset,
        _ => "UnknownDeviceEvents",
    };
    let format = if stream {
        "mde-stream"
    } else if csv {
        "mde-csv"
    } else {
        "mde-json"
    };
    let format = SourceFormatV1::try_new(
        format,
        "defender-source-v1",
        BTreeMap::from([(SourceDiscriminator::RecordType, dataset.to_owned())]),
    )
    .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(timestamp),
        format,
    })
}
impl SourceDecoder for DefenderSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-defender",
            version: "defender-source-v1",
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
        let metadata = input.metadata;
        let mut reader = BufReader::new(input.reader);
        if matches!(
            reader
                .fill_buf()
                .map_err(|_| invalid())?
                .trim_ascii_start()
                .first(),
            Some(b'{' | b'[')
        ) {
            return decode_json_named_envelope_source(
                SourceInput {
                    metadata,
                    reader: &mut reader,
                },
                self.identity(),
                budget,
                &["Results", "results", "records"],
                &|fields| prepare(fields, false),
                emit,
            );
        }
        let (header, mut offset) =
            csv_frame(&mut reader, metadata.cancel, 50 * 1024 * 1024 * 1024)?
                .ok_or_else(invalid)?;
        let mut headers = csv_values(&header)?;
        if let Some(first) = headers.first_mut() {
            *first = first.trim_start_matches('\u{feff}').to_owned();
        }
        if !headers.iter().any(|v| v == "Timestamp")
            || headers.iter().collect::<BTreeSet<_>>().len() != headers.len()
        {
            return Err(invalid());
        }
        let mut output = SourceFrameEmitter::new(metadata, self.identity());
        output.decode_frames(
            budget,
            || {
                let Some((bytes, size)) = csv_frame(
                    &mut reader,
                    metadata.cancel,
                    (50_u64 * 1024 * 1024 * 1024).saturating_sub(offset),
                )?
                else {
                    return Ok(None);
                };
                let start = offset;
                offset = offset.checked_add(size).ok_or_else(invalid)?;
                Ok(Some((bytes, Some(start), ())))
            },
            |bytes, ()| {
                let values = csv_values(bytes)?;
                if values.len() != headers.len() {
                    return Err(invalid());
                }
                let fields = SourceValue::object(
                    headers
                        .iter()
                        .cloned()
                        .zip(values.into_iter().map(SourceValue::Text))
                        .collect(),
                )
                .map_err(|_| invalid())?;
                prepare(fields, true)
            },
            |()| header.len(),
            emit,
        )?;
        Ok(output.finish())
    }
}
pub(super) fn detect(sample: &[u8]) -> Option<u8> {
    let cancel = irmind_app::CancellationToken::new();
    let mut reader = std::io::Cursor::new(sample);
    if matches!(sample.trim_ascii_start().first(), Some(b'{' | b'[')) {
        let mut frames = JsonFrames::new(&mut reader, &cancel)
            .with_record_array_keys(&["Results", "results", "records"])
            .ok()?;
        let frame = frames.next_frame().ok()??;
        return prepare(
            decode_json_fields(frame.bytes(), SourceJsonLimits::default()).ok()?,
            false,
        )
        .ok()
        .map(|_| 98);
    }
    let (header, _) = csv_frame(&mut reader, &cancel, 65536).ok()??;
    let mut headers = csv_values(&header).ok()?;
    if let Some(first) = headers.first_mut() {
        *first = first.trim_start_matches('\u{feff}').to_owned();
    }
    let (row, _) = csv_frame(&mut reader, &cancel, 65536).ok()??;
    let values = csv_values(&row).ok()?;
    if values.len() != headers.len() {
        return None;
    }
    prepare(
        SourceValue::object(
            headers
                .into_iter()
                .zip(values.into_iter().map(SourceValue::Text))
                .collect(),
        )
        .ok()?,
        true,
    )
    .ok()
    .map(|_| 98)
}
