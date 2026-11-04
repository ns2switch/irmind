use crate::{
    AppError, DeclarativeParser, config::Format, error, input::Frames, json_fields,
    mapping::Original,
};
use irmind_app::{CancellationToken, GraphRecord, ParseReport};
use irmind_domain::{ParserLocation, Provenance, SourceKind, Tainted};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufReader, Read},
};

impl DeclarativeParser {
    /// Decode bounded records without installing the definition or writing evidence.
    pub fn parse_source(
        &self,
        source: &str,
        reader: &mut dyn Read,
        hash: [u8; 32],
        cancel: &CancellationToken,
        emit: &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let mut report = ParseReport {
            accepted: 0,
            rejected: 0,
            samples: Vec::new(),
        };
        let mut frames = Frames::new(
            BufReader::new(reader),
            self.definition.input.format,
            self.definition.limits.record_bytes,
        );
        let mut header = None;
        let mut offset = 0u64;
        let mut index = 0usize;
        while let Some(frame) = frames.next(cancel)? {
            let current = offset + frame.leading;
            offset = offset
                .checked_add(frame.consumed)
                .ok_or_else(|| error("declarative source size overflow"))?;
            if offset > 50 * 1024 * 1024 * 1024 {
                return Err(error("declarative source exceeds 50 GiB"));
            }
            if !frame.invalid
                && frame.consumed <= self.definition.limits.record_bytes as u64
                && frame.bytes.iter().all(u8::is_ascii_whitespace)
            {
                continue;
            }
            if index >= self.definition.limits.records {
                return Err(error("declarative source exceeds record limit"));
            }
            if self.definition.input.format == Format::Csv
                && self.definition.input.header
                && header.is_none()
            {
                header = Some(self.csv_header(&frame.bytes)?);
                continue;
            }
            let record = if frame.invalid {
                Err(error("invalid JSON framing"))
            } else if frame.bytes.len() > self.definition.limits.record_bytes {
                Err(error("declarative record exceeds size limit"))
            } else {
                self.record(index, &frame.bytes, header.as_deref())
            };
            match record {
                Ok(record) => {
                    let location = ParserLocation::new(source, self.id(), current)
                        .map_err(|_| error("invalid declarative source location"))?;
                    let record = Tainted::from_external(
                        record,
                        Provenance::new(hash, Some(index as u64), SourceKind::File),
                    )
                    .with_parser_location(location);
                    emit(record)?;
                    report.accepted += 1;
                }
                Err(_) => reject(&mut report, &frame.bytes),
            }
            index += 1;
        }
        Ok(report)
    }

    fn csv_header(&self, bytes: &[u8]) -> Result<Vec<String>, AppError> {
        if bytes.len() > self.definition.limits.record_bytes {
            return Err(error("CSV header exceeds size limit"));
        }
        let values = self.csv_values(bytes)?;
        let unique = values.iter().collect::<BTreeSet<_>>();
        if values.is_empty()
            || unique.len() != values.len()
            || values
                .iter()
                .any(|value| value.is_empty() || value.len() > 256)
        {
            return Err(error("CSV header has empty, duplicate or oversized fields"));
        }
        Ok(values)
    }

    fn csv_values(&self, bytes: &[u8]) -> Result<Vec<String>, AppError> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .delimiter(self.definition.delimiter()?)
            .from_reader(bytes);
        let record = reader
            .records()
            .next()
            .transpose()
            .map_err(|_| error("invalid CSV record"))?
            .ok_or_else(|| error("empty CSV record"))?;
        if record.len() > self.definition.limits.fields {
            return Err(error("CSV field limit exceeded"));
        }
        Ok(record.iter().map(str::to_owned).collect())
    }

    fn record(
        &self,
        index: usize,
        bytes: &[u8],
        header: Option<&[String]>,
    ) -> Result<GraphRecord, AppError> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| error("declarative record is not UTF-8"))?;
        match self.definition.input.format {
            Format::Json | Format::Ndjson => {
                let wanted = self
                    .definition
                    .mapping
                    .values()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>();
                let fields = json_fields::extract(text, &wanted, &self.definition.limits)?;
                let raw = serde_json::from_str(text).map_err(|_| error("invalid JSON record"))?;
                self.map_record(index, &fields, Original::Json(raw))
            }
            Format::Regex => {
                let regex = self
                    .input_regex
                    .as_ref()
                    .ok_or_else(|| error("regex input is unavailable"))?;
                let captures = regex
                    .captures(text.trim_end_matches(['\r', '\n']))
                    .ok_or_else(|| error("record does not match declared pattern"))?;
                let mut fields = BTreeMap::new();
                for name in self.definition.mapping.values() {
                    if let Some(value) = captures.name(name) {
                        if value.len() > 4096 {
                            return Err(error("mapped regex capture exceeds 4096 bytes"));
                        }
                        fields.insert(name.clone(), value.as_str().to_owned());
                    }
                }
                self.map_record(index, &fields, Original::Text(text))
            }
            Format::Csv => {
                let values = self.csv_values(bytes)?;
                if header.is_some_and(|header| header.len() != values.len()) {
                    return Err(error("CSV column count differs from header"));
                }
                let fields = values
                    .into_iter()
                    .enumerate()
                    .map(|(index, value)| {
                        (
                            header
                                .map_or_else(|| index.to_string(), |header| header[index].clone()),
                            value,
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                self.map_record(index, &fields, Original::Text(text))
            }
        }
    }
}

fn reject(report: &mut ParseReport, bytes: &[u8]) {
    report.rejected = report.rejected.saturating_add(1);
    if report.samples.len() < 3 {
        report.samples.push(
            String::from_utf8_lossy(&bytes[..bytes.len().min(256)])
                .chars()
                .flat_map(char::escape_default)
                .take(256)
                .collect(),
        );
    }
}
