//! Batches amortize handoff without accumulating unbounded mapped output.
use super::{AppError, PreparedSourceRecord, RecordRow};
use irmind_domain::{SourceRecordV1, Tainted};
const INPUT_BYTES: usize = 8 * 1024 * 1024;
const OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const INPUT_RECORDS: usize = 256;
type Input = Tainted<SourceRecordV1>;
type Output<'a> = (PreparedSourceRecord<'a>, RecordRow);

#[derive(Default)]
pub(super) struct Inputs {
    records: Vec<Input>,
    bytes: usize,
}
impl Inputs {
    pub(super) fn push(&mut self, record: Input) -> Option<Vec<Input>> {
        let mut weight = 0;
        record.inspect(|source| weight = source.retained_bytes());
        let previous = if self.bytes.saturating_add(weight) > INPUT_BYTES {
            self.take()
        } else {
            None
        };
        self.bytes = self.bytes.saturating_add(weight);
        self.records.push(record);
        if previous.is_none() && (self.records.len() == INPUT_RECORDS || self.bytes >= INPUT_BYTES)
        {
            self.take()
        } else {
            previous
        }
    }
    pub(super) fn take(&mut self) -> Option<Vec<Input>> {
        if self.records.is_empty() {
            return None;
        }
        self.bytes = 0;
        Some(std::mem::take(&mut self.records))
    }
}

pub(super) fn prepare<'a>(
    sources: Vec<Input>,
    send: &mut dyn FnMut(Vec<Output<'a>>, bool) -> Result<(), AppError>,
    mut prepare: impl FnMut(Input) -> Result<Output<'a>, AppError>,
) -> Result<(), AppError> {
    let mut outputs = Vec::new();
    let mut bytes = 0usize;
    for source in sources {
        let mut source_bytes = 0;
        source.inspect(|record| source_bytes = record.retained_bytes());
        let item = match prepare(source) {
            Ok(item) => item,
            Err(error) => {
                flush(&mut outputs, bytes, send)?;
                return Err(error);
            }
        };
        // Source charge includes its bounded tree; the factor covers both the
        // validated projection and physical row, including escaped entities.
        let weight = source_bytes
            .saturating_add(item.1.estimated_bytes().saturating_mul(4))
            .saturating_add(65_536);
        if bytes.saturating_add(weight) > OUTPUT_BYTES {
            flush(&mut outputs, bytes, send)?;
            bytes = 0;
        }
        outputs.push(item);
        bytes = bytes.saturating_add(weight);
        if bytes >= OUTPUT_BYTES {
            flush(&mut outputs, bytes, send)?;
            bytes = 0;
        }
    }
    flush(&mut outputs, bytes, send)
}
fn flush<'a>(
    outputs: &mut Vec<Output<'a>>,
    bytes: usize,
    send: &mut dyn FnMut(Vec<Output<'a>>, bool) -> Result<(), AppError>,
) -> Result<(), AppError> {
    if !outputs.is_empty() {
        send(std::mem::take(outputs), bytes > OUTPUT_BYTES)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use irmind_domain::{
        DecodeAnnotationsV1, EventOrigin, EvidenceHash, Provenance, SourceFormatV1, SourceKind,
        SourceValue,
    };
    fn input(bytes: usize) -> Input {
        let record = SourceRecordV1::try_new(
            EventOrigin::try_new(
                EvidenceHash::from_bytes([3; 32]),
                0,
                None,
                "parser-json",
                "json-source-v1",
            )
            .unwrap(),
            "synthetic.ndjson",
            None,
            SourceFormatV1::try_new("json", "source-json-v1", std::collections::BTreeMap::new())
                .unwrap(),
            SourceValue::object(vec![(
                "message".into(),
                SourceValue::Text("x".repeat(bytes)),
            )])
            .unwrap(),
            DecodeAnnotationsV1::default(),
        )
        .unwrap();
        Tainted::from_external(record, Provenance::new([3; 32], Some(0), SourceKind::File))
    }
    #[test]
    fn handoff_batches_bound_record_count_and_large_source_memory() {
        for bytes in [1, 1024 * 1024, 4 * 1024 * 1024 - 4096] {
            let mut queue = Inputs::default();
            let mut batches = Vec::new();
            for _ in 0..300 {
                if let Some(batch) = queue.push(input(bytes)) {
                    batches.push(batch);
                }
                // Check and release each completed batch instead of retaining
                // the synthetic large-record corpus in the test itself.
                for batch in batches.drain(..) {
                    check(&batch);
                }
            }
            if let Some(batch) = queue.take() {
                check(&batch);
            }
            assert!(queue.take().is_none());
        }
    }
    fn check(batch: &[Input]) {
        assert!(!batch.is_empty() && batch.len() <= INPUT_RECORDS);
        let mut bytes = 0;
        for record in batch {
            record.inspect(|source| bytes += source.retained_bytes());
        }
        assert!(bytes <= INPUT_BYTES || batch.len() == 1);
    }
}
