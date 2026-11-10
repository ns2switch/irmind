//! Read the already opened original; no temporary evidence copy is created.
use super::{
    AppError, ParseReport, SourceFileInput, SourceRecordV1, State, Tainted, invalid, limit,
};
use ::parquet::file::reader::{FileReader, SerializedFileReader};
pub(super) fn decode(
    input: &mut SourceFileInput<'_>,
    emit: &mut dyn FnMut(Tainted<SourceRecordV1>) -> Result<(), AppError>,
) -> Result<ParseReport, AppError> {
    let size = input.file.metadata().map_err(|_| invalid())?.len();
    if size > crate::parquet_input::MAX_PARQUET_BYTES {
        return Err(limit());
    }
    crate::parquet_input::validate_footer(input.file, size).map_err(|_| invalid())?;
    let reader = SerializedFileReader::new(input.file.try_clone().map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    crate::parquet_input::validate_row_groups(reader.metadata()).map_err(|_| limit())?;
    let rows = reader.get_row_iter(None).map_err(|_| invalid())?;
    let mut state = State::new(input.metadata, "ocsf-parquet");
    for row in rows {
        if state.metadata.cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        if state.seen >= 10_000_000 {
            return Err(limit());
        }
        let mut value = row.map_err(|_| invalid())?.to_json_value();
        value.sort_all_objects();
        let encoded = value.to_string();
        drop(value);
        state.record(encoded.as_bytes(), None, emit)?;
    }
    Ok(state.report)
}
