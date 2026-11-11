//! Bounded CSV decoding shared by the original-field decoder.
use crate::{AppError, DeclarativeParser, error};
use std::collections::BTreeSet;

impl DeclarativeParser {
    pub(super) fn csv_header(&self, bytes: &[u8]) -> Result<Vec<String>, AppError> {
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

    pub(super) fn csv_values(&self, bytes: &[u8]) -> Result<Vec<String>, AppError> {
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
}
