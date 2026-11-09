use super::{
    AppError, BTreeMap, BTreeSet, EvidenceHash, FILE_SOURCES, ROW_GROUP, RecordBatch, RecordRow,
    invalid_source,
};
use crate::parquet_store::StringArray;

pub(super) fn stable_rows(
    rows: &mut [RecordRow],
    sources: &BTreeMap<String, String>,
) -> Result<(), AppError> {
    if rows.iter().any(|row| !sources.contains_key(&row.hash)) {
        return Err(invalid_source());
    }
    let mut invalid = false;
    rows.sort_by(|a, b| {
        irmind_domain::compare_record_keys(stable_key(a, sources), stable_key(b, sources), false)
            .unwrap_or_else(|_| {
                invalid = true;
                std::cmp::Ordering::Equal
            })
    });
    if invalid {
        Err(invalid_source())
    } else {
        Ok(())
    }
}
fn stable_key<'a>(
    row: &'a RecordRow,
    sources: &'a BTreeMap<String, String>,
) -> irmind_domain::StableRecordKey<'a> {
    irmind_domain::StableRecordKey {
        source: sources.get(&row.hash).map_or("", String::as_str),
        source_hash: &row.hash,
        ..row.sort_key()
    }
}
pub(super) fn bounded_rows(
    batch: &RecordBatch,
    start: usize,
    existing: Option<&BTreeSet<EvidenceHash>>,
    fits: impl Fn(&BTreeSet<EvidenceHash>) -> Result<bool, AppError>,
) -> Result<(usize, BTreeSet<EvidenceHash>), AppError> {
    let hashes = batch
        .column_by_name("source_hash")
        .and_then(|a| a.as_any().downcast_ref::<StringArray>())
        .ok_or_else(invalid_source)?;
    let mut borrowed = existing
        .into_iter()
        .flatten()
        .map(EvidenceHash::as_str)
        .collect::<BTreeSet<_>>();
    let mut added = BTreeSet::new();
    let mut end = start;
    while end < (start + ROW_GROUP).min(batch.num_rows()) {
        let raw = hashes.value(end);
        if !borrowed.contains(raw) {
            if borrowed.len() >= FILE_SOURCES {
                break;
            }
            let hash = EvidenceHash::parse(raw).map_err(|_| invalid_source())?;
            let candidate = existing
                .into_iter()
                .flatten()
                .cloned()
                .chain(added.iter().cloned())
                .chain(std::iter::once(hash.clone()))
                .collect();
            if !fits(&candidate)? {
                break;
            }
            borrowed.insert(raw);
            added.insert(hash);
        }
        end += 1;
    }
    Ok((end, added))
}
