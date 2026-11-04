use crate::{
    AppError, GraphRecord, IndexedGraphRecord, IndexedInstant, IndexedTime, TimePrecision,
};
use irmind_domain::Tainted;

pub type IndexedProjection = (Option<IndexedTime>, Option<u64>);

/// A module declares whether its documented naive form is UTC. Input stays bounded.
pub fn indexed_rfc3339(
    raw: &str,
    inferred: bool,
    assume_utc: bool,
) -> Result<IndexedTime, AppError> {
    if raw.len() > 64 || !raw.is_ascii() {
        return Err(AppError::Fixed(
            crate::FixedAppError::PolicyInvalidIndexedTimestamp,
        ));
    }
    let mut value = raw.trim().to_owned();
    if value.as_bytes().get(10) == Some(&b' ') {
        value.replace_range(10..11, "T");
    }
    if let Some(prefix) = value.strip_suffix(" UTC") {
        value = format!("{prefix}Z");
    }
    if let Some((clock, zone)) = value.rsplit_once(' ')
        && (zone.starts_with('+') || zone.starts_with('-'))
    {
        value = format!("{clock}{zone}");
    }
    if assume_utc
        && !value.ends_with('Z')
        && !value
            .get(19..)
            .is_some_and(|tail| tail.contains(['+', '-']))
    {
        value.push('Z');
    }
    IndexedTime::from_rfc3339(&value, inferred)
        .map_err(|_| AppError::Fixed(crate::FixedAppError::PolicyInvalidIndexedTimestamp))
}

/// A rejected time is a rejected record. Errors from the storage callback still abort.
pub fn parse_indexed_report(
    parse: impl FnOnce(
        &mut dyn FnMut(Tainted<GraphRecord>) -> Result<(), AppError>,
    ) -> Result<crate::ParseReport, AppError>,
    project: impl Fn(&GraphRecord) -> Result<IndexedProjection, AppError>,
    emit: &mut dyn FnMut(Tainted<IndexedGraphRecord>) -> Result<(), AppError>,
) -> Result<crate::ParseReport, AppError> {
    let mut rejected = 0usize;
    let mut samples = Vec::new();
    let mut report = parse(&mut |tainted| {
        let mut result = None;
        tainted.inspect(|record| {
            result = Some(
                project(record).map(|(time, source_offset)| IndexedGraphRecord {
                    record: record.clone(),
                    time,
                    source_offset,
                }),
            );
        });
        if let Ok(record) = result.ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyMissingIndexedRecord,
        ))? {
            emit(Tainted::from_external(record, tainted.provenance().clone()))
        } else {
            rejected += 1;
            if samples.len() < 3 {
                samples.push("timestamp cannot be represented exactly by the index".into());
            }
            Ok(())
        }
    })?;
    report.accepted = report
        .accepted
        .checked_sub(rejected)
        .ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyInvalidIndexedParserCount,
        ))?;
    report.rejected = report
        .rejected
        .checked_add(rejected as u64)
        .ok_or(AppError::Fixed(
            crate::FixedAppError::PolicyInvalidIndexedParserCount,
        ))?;
    report.samples.extend(samples);
    report.samples.truncate(3);
    Ok(report)
}

pub(crate) fn lift_legacy_indexed(
    tainted: &Tainted<GraphRecord>,
) -> Result<Tainted<IndexedGraphRecord>, AppError> {
    let mut result = None;
    tainted.inspect(|record| {
        result = Some((|| {
            let time = if record.at.is_empty() {
                None
            } else {
                let parsed = IndexedTime::from_rfc3339(&record.at, false).map_err(|_| {
                    AppError::Fixed(crate::FixedAppError::PolicyInvalidIndexedTimestamp)
                })?;
                let seconds = parsed.instant().unix_micros().div_euclid(1_000_000);
                let instant = IndexedInstant::new(seconds * 1_000_000, 0).map_err(|_| {
                    AppError::Fixed(crate::FixedAppError::PolicyInvalidIndexedTimestamp)
                })?;
                Some(
                    IndexedTime::new(instant, TimePrecision::Second, false).map_err(|_| {
                        AppError::Fixed(crate::FixedAppError::PolicyInvalidIndexedTimestamp)
                    })?,
                )
            };
            Ok(IndexedGraphRecord {
                record: record.clone(),
                time,
                source_offset: None,
            })
        })());
    });
    let record = result.ok_or(AppError::Fixed(
        crate::FixedAppError::PolicyMissingIndexedRecord,
    ))??;
    Ok(Tainted::from_external(record, tainted.provenance().clone()))
}

#[cfg(test)]
mod tests;
