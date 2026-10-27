use super::{AppError, CaseId, GraphRecord, GraphStore, Tainted, params, storage};
use duckdb::{OptionalExt, Transaction};
use irmind_app::{CancellationToken, EventParser};
use std::collections::BTreeSet;

pub(super) fn terms(text: &str) -> BTreeSet<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|word| (2..=64).contains(&word.len()))
        .map(str::to_lowercase)
        .take(2_048)
        .collect()
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
        let mut db = self.connect(id)?;
        let tx = db.transaction().map_err(storage)?;
        if let Some(count) = Self::indexed_count(&tx, hash)? {
            return usize::try_from(count).map_err(storage);
        }
        let count = parser.parse_each(source, bytes, cancel, &mut |record| {
            Self::insert_one(&tx, hash, &record)
        })?;
        Self::finish_index(&tx, hash, count)?;
        tx.commit().map_err(storage)?;
        Ok(count)
    }

    pub(crate) fn index_records(
        &self,
        id: &CaseId,
        hash: &str,
        records: &[Tainted<GraphRecord>],
        cancel: &CancellationToken,
    ) -> Result<(), AppError> {
        let mut db = self.connect(id)?;
        let tx = db.transaction().map_err(storage)?;
        if Self::indexed_count(&tx, hash)?.is_some() {
            return Ok(());
        }
        Self::insert_records(&tx, hash, records, cancel)?;
        tx.commit().map_err(storage)
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
    ) -> Result<(), AppError> {
        for (index, record) in records.iter().enumerate() {
            if index.is_multiple_of(256) && cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            Self::insert_one(tx, hash, record)?;
        }
        Self::finish_index(tx, hash, records.len())
    }

    fn finish_index(tx: &Transaction<'_>, hash: &str, count: usize) -> Result<(), AppError> {
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

    fn insert_one(
        tx: &Transaction<'_>,
        hash: &str,
        tainted: &Tainted<GraphRecord>,
    ) -> Result<(), AppError> {
        let mut outcome = Ok(());
        tainted.inspect(|record| outcome = Self::insert_record(tx, hash, record));
        outcome
    }

    fn insert_record(
        tx: &Transaction<'_>,
        hash: &str,
        record: &GraphRecord,
    ) -> Result<(), AppError> {
        let index = i64::try_from(record.index).map_err(storage)?;
        tx.execute(
            "INSERT INTO events (hash,record_index,event_time,event) VALUES (?1,?2,?3,?4)",
            params![hash, index, record.at, record.event],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO record_texts (hash,record_index,text) VALUES (?1,?2,?3)",
            params![hash, index, record.text],
        )
        .map_err(storage)?;
        Self::insert_terms(tx, hash, index, &record.text)?;
        Self::insert_entities(tx, hash, index, record)?;
        Self::insert_relations(tx, hash, index, record)
    }

    fn insert_terms(
        tx: &Transaction<'_>,
        hash: &str,
        index: i64,
        text: &str,
    ) -> Result<(), AppError> {
        for term in terms(text) {
            tx.execute(
                "INSERT INTO record_terms (term,hash,record_index) VALUES (?1,?2,?3)",
                params![term, hash, index],
            )
            .map_err(storage)?;
        }
        Ok(())
    }

    fn insert_entities(
        tx: &Transaction<'_>,
        hash: &str,
        index: i64,
        record: &GraphRecord,
    ) -> Result<(), AppError> {
        for (kind, value) in &record.entities {
            tx.execute(
                "INSERT INTO observations (hash,record_index,event_time,event,kind,value) VALUES (?1,?2,?3,?4,?5,?6)",
                params![hash, index, record.at, record.event, kind, value],
            )
            .map_err(storage)?;
            tx.execute(
                "INSERT INTO nodes (kind,value,first_seen,last_seen,count) VALUES (?1,?2,?3,?3,1)
                 ON CONFLICT (kind,value) DO UPDATE SET
                   first_seen=LEAST(nodes.first_seen,excluded.first_seen),
                   last_seen=GREATEST(nodes.last_seen,excluded.last_seen),
                   count=nodes.count+1",
                params![kind, value, record.at],
            )
            .map_err(storage)?;
        }
        Ok(())
    }

    fn insert_relations(
        tx: &Transaction<'_>,
        hash: &str,
        index: i64,
        record: &GraphRecord,
    ) -> Result<(), AppError> {
        for relation in &record.relations {
            tx.execute(
                "INSERT INTO relations (hash,record_index,event_time,from_kind,from_value,relation,to_kind,to_value) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![hash, index, record.at, relation.from_kind, relation.from_value, relation.relation, relation.to_kind, relation.to_value],
            )
            .map_err(storage)?;
        }
        Ok(())
    }
}
