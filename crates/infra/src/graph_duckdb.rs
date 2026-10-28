//! Derived, rebuildable graph index. The signed originals remain in the evidence store.

use duckdb::{Connection, OptionalExt, params};
use irmind_app::{AppError, GraphRecord, GraphRelation, TimelineEvent};
use irmind_domain::{CaseId, Tainted};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn storage(_error: impl std::fmt::Display) -> AppError {
    AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
        irmind_app::AdapterStorageError::DuckDBGraphOperationFailed,
    ))
}

mod format;
mod index;
mod profile;
mod secondary_indexes;
#[cfg(test)]
pub(crate) use profile::GraphInsertProfile;
mod queries;
mod verify;
use format::short;
use verify::{
    accumulate_graph_expectations, attach_graph_relations, read_observed_records,
    verify_graph_totals, verify_terms,
};
pub(crate) struct GraphStore {
    root: PathBuf,
    writers: Mutex<HashMap<CaseId, Arc<Mutex<Connection>>>>,
    profile: Option<std::sync::Arc<profile::GraphInsertProfile>>,
}

pub(crate) struct GraphReadConnection {
    connection: Connection,
    _writer: Arc<Mutex<Connection>>,
}

impl Deref for GraphReadConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

impl GraphStore {
    pub(crate) fn new(root: &Path) -> Result<Self, AppError> {
        fs::create_dir_all(root).map_err(storage)?;
        irmind_fs::private_dir(root).map_err(storage)?;
        Ok(Self {
            root: root.to_owned(),
            writers: Mutex::new(HashMap::new()),
            profile: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn attach_profile(&mut self, profile: std::sync::Arc<profile::GraphInsertProfile>) {
        self.profile = Some(profile);
    }

    pub(crate) fn connect(&self, id: &CaseId) -> Result<GraphReadConnection, AppError> {
        self.connect_inner(id, true)
    }

    fn connect_inner(
        &self,
        id: &CaseId,
        build_indexes: bool,
    ) -> Result<GraphReadConnection, AppError> {
        let writer = self.writer(id)?;
        let connection = {
            let db = writer.lock().map_err(storage)?;
            if build_indexes && Arc::strong_count(&writer) <= 2 {
                secondary_indexes::ensure(&db)?;
            }
            db.try_clone().map_err(storage)?
        };
        Ok(GraphReadConnection {
            connection,
            _writer: writer,
        })
    }

    fn open_new(&self, id: &CaseId) -> Result<Connection, AppError> {
        let path = self.root.join(format!("{}.duckdb", id.as_str()));
        let db = Connection::open(&path).map_err(storage)?;
        irmind_fs::private_file(&path).map_err(storage)?;
        db.execute_batch("SET checkpoint_threshold='256MB'")
            .map_err(storage)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS indexed (hash VARCHAR PRIMARY KEY, records BIGINT NOT NULL);
             CREATE TABLE IF NOT EXISTS events (
                hash VARCHAR NOT NULL, record_index BIGINT NOT NULL, event_time VARCHAR NOT NULL,
                event VARCHAR NOT NULL);
             CREATE TABLE IF NOT EXISTS observations (
                hash VARCHAR NOT NULL, record_index BIGINT NOT NULL, event_time VARCHAR NOT NULL,
                event VARCHAR NOT NULL, kind VARCHAR NOT NULL, value VARCHAR NOT NULL);
             CREATE TABLE IF NOT EXISTS nodes (
                kind VARCHAR NOT NULL, value VARCHAR NOT NULL, first_seen VARCHAR NOT NULL,
                last_seen VARCHAR NOT NULL, count BIGINT NOT NULL, PRIMARY KEY(kind, value));
             CREATE TABLE IF NOT EXISTS record_texts (
                hash VARCHAR NOT NULL, record_index BIGINT NOT NULL, text VARCHAR NOT NULL);
             CREATE TABLE IF NOT EXISTS record_terms (
                term VARCHAR NOT NULL, hash VARCHAR NOT NULL, record_index BIGINT NOT NULL);
             CREATE TABLE IF NOT EXISTS fts_indexed (hash VARCHAR PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS relations (
                hash VARCHAR NOT NULL, record_index BIGINT NOT NULL, event_time VARCHAR NOT NULL,
                from_kind VARCHAR NOT NULL, from_value VARCHAR NOT NULL, relation VARCHAR NOT NULL,
                to_kind VARCHAR NOT NULL, to_value VARCHAR NOT NULL);",
        )
        .map_err(storage)?;
        Ok(db)
    }

    fn writer(&self, id: &CaseId) -> Result<Arc<Mutex<Connection>>, AppError> {
        const MAX_IDLE_WRITERS: usize = 8;
        let mut writers = self.writers.lock().map_err(storage)?;
        if let Some(writer) = writers.get(id) {
            return Ok(Arc::clone(writer));
        }
        let writer = Arc::new(Mutex::new(self.open_new(id)?));
        let stale = if writers.len() >= MAX_IDLE_WRITERS {
            writers
                .iter()
                .find(|(_, writer)| Arc::strong_count(writer) == 1)
                .map(|(key, _)| key.clone())
                .and_then(|key| writers.remove(&key))
        } else {
            None
        };
        writers.insert(id.clone(), Arc::clone(&writer));
        drop(writers);
        drop(stale);
        Ok(writer)
    }

    pub(crate) fn rebuild<F>(
        &self,
        id: &CaseId,
        sources: &[(String, usize)],
        cancel: &irmind_app::CancellationToken,
        mut parse: F,
    ) -> Result<usize, AppError>
    where
        F: FnMut(&str) -> Result<Vec<Tainted<GraphRecord>>, AppError>,
    {
        let writer = self.writer(id)?;
        let mut db = writer.lock().map_err(storage)?;
        let tx = db.transaction().map_err(storage)?;
        if Arc::strong_count(&writer) <= 2 {
            secondary_indexes::suspend(&tx)?;
        }
        tx.execute_batch("DELETE FROM relations; DELETE FROM observations; DELETE FROM nodes; DELETE FROM record_terms; DELETE FROM fts_indexed; DELETE FROM record_texts; DELETE FROM events; DELETE FROM indexed;").map_err(storage)?;
        let mut total = 0usize;
        for (hash, expected) in sources {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let records = parse(hash)?;
            if records.len() != *expected {
                return Err(storage(format!("signed record count differs for {hash}")));
            }
            Self::insert_records(&tx, hash, &records, cancel, self.profile.as_deref())?;
            total = total
                .checked_add(records.len())
                .ok_or_else(|| storage("record count overflow"))?;
        }
        if Arc::strong_count(&writer) <= 2 {
            secondary_indexes::ensure(&tx)?;
        }
        tx.commit().map_err(storage)?;
        Ok(total)
    }

    pub(crate) fn verify<F>(
        &self,
        id: &CaseId,
        sources: &[(String, usize)],
        cancel: &irmind_app::CancellationToken,
        mut parse: F,
    ) -> Result<usize, AppError>
    where
        F: FnMut(&str) -> Result<Vec<Tainted<GraphRecord>>, AppError>,
    {
        let db = self.connect_inner(id, false)?;
        let mut indexed_statement = db
            .prepare("SELECT hash,records FROM indexed ORDER BY hash")
            .map_err(storage)?;
        let indexed = indexed_statement
            .query_map([], |row| {
                let count: i64 = row.get(1)?;
                Ok((row.get::<_, String>(0)?, count))
            })
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        if indexed.len() != sources.len()
            || indexed
                .iter()
                .zip(sources)
                .any(|((a, b), (c, d))| a != c || usize::try_from(*b).ok() != Some(*d))
        {
            return Err(storage(
                "indexed evidence manifest differs from signed graph events",
            ));
        }
        let mut expected_nodes: BTreeMap<(String, String), (String, String, i64)> = BTreeMap::new();
        let mut expected_relations = 0i64;
        let mut total = 0usize;
        for (hash, expected_count) in sources {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let expected = parse(hash)?;
            if expected.len() != *expected_count {
                return Err(storage(format!("signed record count differs for {hash}")));
            }
            verify_terms(&db, hash, &expected, cancel)?;
            let mut actual = read_observed_records(&db, hash, cancel)?;
            attach_graph_relations(&db, hash, &mut actual, cancel)?;
            let mut equal = actual.len() == expected.len();
            for (actual_record, expected_record) in actual.iter().zip(&expected) {
                expected_record.inspect(|record| equal &= actual_record == record);
            }
            if !equal {
                return Err(storage(format!(
                    "derived graph differs from signed evidence {hash}"
                )));
            }
            accumulate_graph_expectations(&expected, &mut expected_nodes, &mut expected_relations)?;
            total = total
                .checked_add(expected.len())
                .ok_or_else(|| storage("record count overflow"))?;
        }
        verify_graph_totals(&db, &expected_nodes, expected_relations, total)?;
        Ok(total)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod cancellation_tests;
