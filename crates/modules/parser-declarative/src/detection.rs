use crate::{
    DeclarativeParser,
    config::{Format, SAMPLE_BYTES},
    input::Frames,
    json_fields,
};
use irmind_app::{CancellationToken, ParserConfidence};
use std::{
    collections::BTreeSet,
    io::{BufReader, Cursor},
};

impl DeclarativeParser {
    /// Pure, bounded detection. File extensions are not evidence of a match.
    pub fn detect_sample(&self, sample: &[u8]) -> Option<ParserConfidence> {
        let sample = &sample[..sample.len().min(SAMPLE_BYTES)];
        let matches = if !self.definition.detect.header.is_empty() {
            let mut reader = csv::ReaderBuilder::new()
                .has_headers(false)
                .delimiter(self.definition.delimiter().ok()?)
                .from_reader(sample);
            reader.records().next()?.ok()?.iter().eq(self
                .definition
                .detect
                .header
                .iter()
                .map(String::as_str))
        } else if let Some(pattern) = &self.detection_regex {
            std::str::from_utf8(sample)
                .ok()?
                .lines()
                .take(16)
                .any(|line| pattern.is_match(line))
        } else {
            self.detect_fields(sample)?
        };
        matches
            .then(|| ParserConfidence::new(self.definition.detect.confidence).ok())
            .flatten()
    }

    fn detect_fields(&self, sample: &[u8]) -> Option<bool> {
        let required = self
            .definition
            .detect
            .required_fields
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let format = if self.definition.input.format == Format::Json {
            Format::Json
        } else {
            Format::Ndjson
        };
        let mut frames = Frames::new(BufReader::new(Cursor::new(sample)), format, SAMPLE_BYTES);
        let frame = frames.next(&CancellationToken::new()).ok()??;
        if frame.invalid {
            return None;
        }
        let text = std::str::from_utf8(&frame.bytes).ok()?;
        let values = json_fields::extract(text, &required, &self.definition.limits).ok()?;
        Some(required.iter().all(|field| values.contains_key(*field)))
    }
}
