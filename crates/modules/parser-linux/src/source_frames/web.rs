use super::{
    Decoded, invalid,
    record::{member, object, text},
};
use irmind_app::source_mapping::SourceValue;
use irmind_app::{AppError, IndexedTime};
pub(super) fn decode(line: &str, index: u64, offset: u64) -> Result<Decoded, AppError> {
    let row = crate::web::fields(line)?;
    let timestamp = chrono::DateTime::parse_from_str(row.time, "%d/%b/%Y:%H:%M:%S %z")
        .map_err(|_| invalid())?;
    let timestamp =
        IndexedTime::from_rfc3339(&timestamp.to_rfc3339(), false).map_err(|_| invalid())?;
    let mut request = row.request.splitn(3, ' ');
    let fields = object(vec![
        ("remote_addr", text(row.ip)),
        ("remote_user", text(row.user)),
        ("time_local", text(row.time)),
        (
            "request",
            object(vec![
                ("raw", text(row.request)),
                ("method", text(request.next().ok_or_else(invalid)?)),
                ("target", text(request.next().ok_or_else(invalid)?)),
            ])?,
        ),
        (
            "status",
            SourceValue::Number(
                irmind_domain::SourceNumber::try_new(row.status).map_err(|_| invalid())?,
            ),
        ),
        ("raw", text(line)),
    ])?;
    Ok(Decoded {
        fields,
        timestamp,
        dataset: "http-access".into(),
        partial: false,
        members: vec![member(index, offset)],
        offset: Some(offset),
        raw: Some(line.into()),
    })
}
