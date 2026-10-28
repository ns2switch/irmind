use super::profile::{GraphInsertProfile, GraphPhase, measure};
use super::{AppError, CaseId, GraphRecord, GraphStore, Tainted, params, storage};
use duckdb::{OptionalExt, Transaction};
use irmind_app::{CancellationToken, EventParser};
use std::collections::BTreeSet;

mod batch;

const BATCH_RECORDS: usize = 2_048;
const BATCH_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn terms(text: &str) -> Result<BTreeSet<String>, AppError> {
    let mut terms = BTreeSet::new();
    for word in text.split(|character: char| !character.is_alphanumeric()) {
        if (2..=64).contains(&word.len()) {
            terms.insert(word.to_lowercase());
            if terms.len() > 2_048 {
                return Err(AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
                    irmind_app::AdapterPolicyError::TooManyGraphSearchTerms,
                )));
            }
        }
    }
    Ok(terms)
}

impl GraphStore {
    pub(crate) fn index_from_parser(
        &self,
        id: &CaseId,
        hash: &str,
        source: &str,
        bytes: &[u8],
        parser: &dyn EventParser,
        cancel: &CancellationToken,
    ) -> Result<usize, AppError> {
        let profile = self.profile.as_deref();
        let writer = measure(profile, GraphPhase::Connect, || self.writer(id))?;
        let mut db = writer.lock().map_err(storage)?;
        let tx = measure(profile, GraphPhase::Transaction, || {
            db.transaction().map_err(storage)
        })?;
        if let Some(count) = measure(profile, GraphPhase::IndexLookup, || {
            Self::indexed_count(&tx, hash)
        })? {
            let full_text: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM fts_indexed WHERE hash=?1",
                    params![hash],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if full_text != 1 {
                return Err(storage("graph text index is incomplete; run graph-rebuild"));
            }
            return usize::try_from(count).map_err(storage);
        }
        let mut pending = Vec::new();
        let mut pending_bytes = 0usize;
        let count = parser.parse_each(source, bytes, cancel, &mut |record| {
            let mut size = 0;
            record.inspect(|value| size = value.text.len());
            pending_bytes = pending_bytes.saturating_add(size);
            pending.push(record);
            if pending.len() >= BATCH_RECORDS || pending_bytes >= BATCH_BYTES {
                if cancel.is_cancelled() {
                    return Err(AppError::Cancelled);
                }
                batch::insert_batch(&tx, hash, &pending, cancel, profile)?;
                pending.clear();
                pending_bytes = 0;
            }
            Ok(())
        })?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        batch::insert_batch(&tx, hash, &pending, cancel, profile)?;
        measure(profile, GraphPhase::Finish, || {
            Self::finish_index(&tx, hash, count)
        })?;
        measure(profile, GraphPhase::Commit, || tx.commit().map_err(storage))?;
        Ok(count)
    }

    pub(crate) fn index_records(
        &self,
        id: &CaseId,
        hash: &str,
        records: &[Tainted<GraphRecord>],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let profile = self.profile.as_deref();
        let writer = measure(profile, GraphPhase::Connect, || self.writer(id))?;
        let mut db = writer.lock().map_err(storage)?;
        let tx = measure(profile, GraphPhase::Transaction, || {
            db.transaction().map_err(storage)
        })?;
        if measure(profile, GraphPhase::IndexLookup, || {
            Self::indexed_count(&tx, hash)
        })?
        .is_some()
        {
            return Ok(());
        }
        Self::insert_records(&tx, hash, records, cancel, profile)?;
        measure(profile, GraphPhase::Commit, || tx.commit().map_err(storage))?;
        Ok(())
    }

    fn indexed_count(tx: &Transaction<'_>, hash: &str) -> Result<Option<i64>, AppError> {
        tx.query_row(
            "SELECT records FROM indexed WHERE hash=?1",
            params![hash],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)
    }

    pub(super) fn insert_records(
        tx: &Transaction<'_>,
        hash: &str,
        records: &[Tainted<GraphRecord>],
        cancel: &CancellationToken,
        profile: Option<&GraphInsertProfile>,
    ) -> Result<(), AppError> {
        for pending in records.chunks(BATCH_RECORDS) {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            batch::insert_batch(tx, hash, pending, cancel, profile)?;
        }
        measure(profile, GraphPhase::Finish, || {
            Self::finish_index(tx, hash, records.len())
        })
    }

    fn finish_index(tx: &Transaction<'_>, hash: &str, count: usize) -> Result<(), AppError> {
        tx.execute(
            "INSERT INTO nodes (kind,value,first_seen,last_seen,count)
             SELECT kind,value,MIN(event_time),MAX(event_time),COUNT(*)
             FROM observations WHERE hash=?1 GROUP BY kind,value
             ON CONFLICT (kind,value) DO UPDATE SET
               first_seen=LEAST(nodes.first_seen,excluded.first_seen),
               last_seen=GREATEST(nodes.last_seen,excluded.last_seen),
               count=nodes.count+excluded.count",
            params![hash],
        )
        .map_err(storage)?;
        let count = i64::try_from(count).map_err(storage)?;
        tx.execute(
            "INSERT INTO indexed (hash,records) VALUES (?1,?2)",
            params![hash, count],
        )
        .map_err(storage)?;
        tx.execute("INSERT INTO fts_indexed (hash) VALUES (?1)", params![hash])
            .map_err(storage)?;
        Ok(())
    }
}
