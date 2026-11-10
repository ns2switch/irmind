//! Reject older database layouts before any schema mutation.
use super::{AppError, Connection, storage};
pub(super) fn validate_existing(db: &Connection) -> Result<(), AppError> {
    let tables: &[(&str, &[&str])] = &[
        (
            "PRAGMA table_info(cases)",
            &["id", "title", "scope", "severity", "sealed", "seal_pending"],
        ),
        (
            "PRAGMA table_info(audit)",
            &[
                "case_id",
                "seq",
                "at",
                "actor",
                "origin",
                "kind",
                "payload",
                "evidence",
                "prev",
                "hash",
                "sig",
                "public_key",
            ],
        ),
        ("PRAGMA table_info(evidence)", &["case_id", "hash"]),
        ("PRAGMA table_info(seal_intent)", &["case_id", "data"]),
        (
            "PRAGMA table_info(operational_audit)",
            &[
                "case_id",
                "seq",
                "at",
                "actor",
                "operation",
                "prev",
                "hash",
                "sig",
                "public_key",
            ],
        ),
        (
            "PRAGMA table_info(global_operational_audit)",
            &[
                "seq",
                "at",
                "actor",
                "operation",
                "prev",
                "hash",
                "sig",
                "public_key",
            ],
        ),
    ];
    let existing = tables
        .iter()
        .map(|(query, expected)| {
            let mut statement = db.prepare(query).map_err(storage)?;
            let fields = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(storage)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage)?;
            Ok((fields, *expected))
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    if existing.iter().all(|(fields, _)| fields.is_empty()) {
        return Ok(());
    }
    if existing.iter().any(|(fields, expected)| {
        fields.len() != expected.len()
            || expected
                .iter()
                .any(|name| !fields.iter().any(|field| field == name))
    }) {
        return Err(AppError::Fixed(
            irmind_app::FixedAppError::RetiredCaseFormat,
        ));
    }
    Ok(())
}
