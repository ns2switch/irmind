//! Decode response framing only. UDM interpretation remains in the UDM mapping module.
use irmind_app::{
    AppError, ParseReport, ParserIdentity, SourceDecoder,
    source_mapping::{
        SourceInput,
        framed::{DecodedSourceFrame, SourceFrameEmitter},
        json::{SourceJsonLimits, decode_json_fields},
    },
};
use irmind_domain::{IndexedTime, SourceFormatV1, SourceRecordV1, SourceValue, Tainted};
use std::{collections::BTreeMap, io::Read as _};
pub struct ChronicleSourceDecoder;
impl SourceDecoder for ChronicleSourceDecoder {
    fn identity(&self) -> ParserIdentity<'_> {
        ParserIdentity {
            name: "siem-chronicle",
            version: "chronicle-source-v1",
        }
    }
    fn decode_reader(
        &self,
        input: SourceInput<'_>,
        emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
    ) -> Result<ParseReport, AppError> {
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut bytes = Vec::new();
        input
            .reader
            .take(5_000_001)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if input.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if bytes.len() > 5_000_000 {
            return Err(invalid());
        }
        let fields =
            decode_json_fields(&bytes, SourceJsonLimits::default()).map_err(|_| invalid())?;
        let (hits, detection) = match (fields.field("events"), fields.field("detections")) {
            (Some(SourceValue::Array(events)), None) => (events.as_slice(), false),
            (None, Some(SourceValue::Array(events))) => (events.as_slice(), true),
            (None, None) => (&[][..], false),
            _ => return Err(invalid()),
        };
        if hits.len() > 20 {
            return Err(invalid());
        }
        let mut report = ParseReport {
            accepted: 0,
            rejected: 0,
            samples: vec![],
        };
        let frames = SourceFrameEmitter::new(input.metadata, self.identity());
        for (ordinal, hit) in hits.iter().enumerate() {
            if input.metadata.cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let record = decode_hit(hit.clone(), detection).and_then(|frame| {
                frames.record_at(frame, None, report.accepted as u64, ordinal as u64)
            });
            match record {
                Ok(record) => {
                    emit(record)?;
                    report.accepted += 1;
                }
                Err(_) => {
                    report.rejected += 1;
                }
            }
        }
        Ok(report)
    }
}
fn decode_hit(fields: SourceValue, detection: bool) -> Result<DecodedSourceFrame, AppError> {
    let timestamp = if detection {
        fields.field("detectionTime")
    } else {
        fields
            .field("udm")
            .and_then(|v| v.field("metadata"))
            .and_then(|v| v.field("eventTimestamp"))
    }
    .and_then(SourceValue::as_text)
    .ok_or_else(invalid)?;
    let time = IndexedTime::from_rfc3339(timestamp, false).map_err(|_| invalid())?;
    let dataset = if detection {
        "chronicle-detection"
    } else {
        "chronicle-udm"
    };
    let format = SourceFormatV1::try_new(dataset, "chronicle-source-v1", BTreeMap::new())
        .map_err(|_| invalid())?;
    Ok(DecodedSourceFrame {
        fields,
        timestamp: Some(time),
        format,
    })
}
fn invalid() -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::SourceFormat)
}
