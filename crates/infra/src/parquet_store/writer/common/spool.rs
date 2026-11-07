//! Store each peer vector once in the unsigned normalized spool. Recreate its
//! JSON cache before memory accounting and before any physical batch is built.
use super::row::{CommonRow, ObservationRow, typed_peers};
use crate::parquet_store::AppError;

#[derive(serde::Deserialize)]
pub(super) struct StoredCommonRow {
    payload: String,
    categories: u32,
    types: u32,
    outcome: u8,
    kind: u8,
    role_bits: u16,
    observations: Vec<ObservationRow>,
}
impl TryFrom<StoredCommonRow> for CommonRow {
    type Error = AppError;
    fn try_from(value: StoredCommonRow) -> Result<Self, Self::Error> {
        let co_observations = typed_peers(&value.observations)?;
        Ok(Self {
            payload: value.payload,
            categories: value.categories,
            types: value.types,
            outcome: value.outcome,
            kind: value.kind,
            role_bits: value.role_bits,
            observations: value.observations,
            co_observations,
        })
    }
}

#[cfg(test)]
mod tests;
