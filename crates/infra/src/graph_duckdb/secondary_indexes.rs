use super::{AppError, Connection, params, storage};
use duckdb::Transaction;

const INDEXES: [(&str, &str); 2] = [
    (
        "events_time",
        "CREATE INDEX events_time ON events(event_time)",
    ),
    (
        "observations_entity",
        "CREATE INDEX observations_entity ON observations(kind,value)",
    ),
];

pub(super) fn ensure(db: &Connection) -> Result<(), AppError> {
    for (name, statement) in INDEXES {
        let existing: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM duckdb_indexes() WHERE index_name=?1",
                params![name],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if existing == 0 {
            db.execute_batch(statement).map_err(storage)?;
        }
    }
    Ok(())
}

pub(super) fn suspend(tx: &Transaction<'_>) -> Result<(), AppError> {
    let existing: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM duckdb_indexes() WHERE index_name IN ('events_time','observations_entity')",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if existing == 0 {
        return Ok(());
    }
    tx.execute_batch("DROP INDEX IF EXISTS events_time; DROP INDEX IF EXISTS observations_entity")
        .map_err(storage)
}
