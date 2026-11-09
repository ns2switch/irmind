//! Journald source decoding; interpretation belongs to its independent mapper.
use irmind_app::{
    AppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        DecodeAnnotationsV1, SourceFormatV1, SourceInput, SourceMetadata, SourceRecordV1,
        SourceValue,
        json::{SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{
    EventOrigin, EvidenceHash, IndexedInstant, IndexedTime, ParserLocation, Provenance, Tainted,
    TimePrecision,
};
use std::{collections::BTreeMap, io::BufReader};

pub struct JournalSourceDecoder;
impl SourceDecoder for JournalSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "parser-linux",
            version: "journald-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        let mut reader = BufReader::new(input.reader);
        let mut report = ParseReport {
            accepted: 0,
            rejected: 0,
            samples: Vec::new(),
        };
        let (mut index, mut offset) = (0u64, 0u64);
        loop {
            let (bytes, consumed) = super::bounds::line(&mut reader, input.metadata.cancel)?;
            if consumed == 0 {
                break;
            }
            if index >= 10_000_000 || offset + consumed > super::bounds::MAX_SOURCE {
                return Err(invalid());
            }
            if !bytes.iter().all(u8::is_ascii_whitespace) {
                let decoded = (consumed <= super::bounds::MAX_LINE as u64)
                    .then(|| record(input.metadata, &bytes, index, offset))
                    .transpose();
                match decoded {
                    Ok(Some(record)) => {
                        let location = ParserLocation::new(
                            input.metadata.source.reference(),
                            "parser-linux",
                            offset,
                        )
                        .map_err(|_| invalid())?;
                        let provenance = Provenance::new(
                            input.metadata.evidence_hash,
                            Some(index),
                            input.metadata.source.kind(),
                        )
                        .with_parser_location(location);
                        emit(Tainted::from_external(record, provenance))?;
                        report.accepted += 1;
                    }
                    _ => super::bounds::reject(&mut report, &bytes),
                }
            }
            offset += consumed;
            index += 1;
        }
        Ok(report)
    }
}
fn record(
    meta: SourceMetadata<'_>,
    bytes: &[u8],
    index: u64,
    offset: u64,
) -> Result<SourceRecordV1, AppError> {
    let raw = std::str::from_utf8(bytes)
        .map_err(|_| invalid())?
        .trim_end_matches(['\r', '\n']);
    let fields = decode_json_fields(
        raw.as_bytes(),
        SourceJsonLimits {
            bytes: super::bounds::MAX_LINE,
            ..SourceJsonLimits::default()
        },
    )
    .map_err(|_| invalid())?;
    let micros = fields
        .field("__REALTIME_TIMESTAMP")
        .and_then(SourceValue::as_text)
        .ok_or_else(invalid)?
        .parse::<i64>()
        .map_err(|_| invalid())?;
    let instant = IndexedInstant::new(micros, 0).map_err(|_| invalid())?;
    let time =
        IndexedTime::new(instant, TimePrecision::Microsecond, false).map_err(|_| invalid())?;
    let format = SourceFormatV1::try_new("journald-json", "journald-source-v1", BTreeMap::new())
        .map_err(|_| invalid())?;
    let origin = EventOrigin::try_new(
        EvidenceHash::from_bytes(meta.evidence_hash),
        index,
        Some(offset),
        "parser-linux",
        "journald-source-v1",
    )
    .map_err(|_| invalid())?;
    let annotations =
        DecodeAnnotationsV1::try_new(false, Vec::new(), Some(raw.into())).map_err(|_| invalid())?;
    SourceRecordV1::try_from_source(
        origin,
        meta.source.clone(),
        Some(time),
        format,
        fields,
        annotations,
    )
    .map_err(|_| invalid())
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn source_route_retains_original_names_types_and_exact_microseconds() {
        let bytes = b"{\"__REALTIME_TIMESTAMP\":\"1794096000123456\",\"_HOSTNAME\":\"synthetic\",\"_UID\":\"1000\",\"MESSAGE\":\"Failed is original text, not an outcome\"}\n";
        let cancel = irmind_app::CancellationToken::new();
        let mut received = Vec::new();
        let report = JournalSourceDecoder
            .decode_reader(
                SourceInput {
                    metadata: SourceMetadata {
                        source: &irmind_domain::SourceReferenceV1::file("journal.jsonl").unwrap(),
                        evidence_hash: irmind_app::sha256(bytes),
                        time_context: None,
                        cancel: &cancel,
                    },
                    reader: &mut std::io::Cursor::new(bytes),
                },
                &mut |r| {
                    received.push(r);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(report.accepted, 1);
        received[0].inspect(|r| {
            assert_eq!(
                r.timestamp().unwrap().instant().unix_micros(),
                1_794_096_000_123_456
            );
            assert_eq!(r.fields().field("_UID").unwrap().as_text(), Some("1000"));
            assert!(r.fields().field("outcome").is_none());
            assert!(
                r.annotations()
                    .raw()
                    .unwrap()
                    .contains("__REALTIME_TIMESTAMP")
            );
        });
        assert!(received[0].provenance().parser_location().is_some());
    }
}
