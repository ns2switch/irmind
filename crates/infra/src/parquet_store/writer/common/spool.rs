//! Store each peer vector once in the unsigned normalized spool. Recreate its
//! JSON cache before memory accounting and before any physical batch is built.
use super::row::{CommonRow, ObservationRow};
use crate::parquet_store::{AppError, storage};

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
        let co_observations = serde_json::to_string(&value.observations).map_err(storage)?;
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
