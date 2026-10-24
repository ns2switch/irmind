//! Derived, rebuildable graph index. The signed originals remain in the evidence store.

use duckdb::{Connection, OptionalExt, Transaction, params};
use irmind_app::{AppError, GraphRecord, GraphRelation, TimelineEvent};
use irmind_domain::CaseId;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

fn storage(error: impl std::fmt::Display) -> AppError {
    AppError::Storage(format!("DuckDB graph: {error}"))
}

fn short(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let prefix: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

pub struct GraphStore {
    root: PathBuf,
}

impl GraphStore {
    pub fn new(root: &Path) -> Result<Self, AppError> {
        fs::create_dir_all(root).map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(storage)?;
        }
        Ok(Self {
            root: root.to_owned(),
        })
    }

    pub(crate) fn connect(&self, id: &CaseId) -> Result<Connection, AppError> {
        let path = self.root.join(format!("{}.duckdb", id.as_str()));
        let db = Connection::open(&path).map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(storage)?;
        }
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS indexed (hash VARCHAR PRIMARY KEY, records BIGINT NOT NULL);
             CREATE TABLE IF NOT EXISTS events (
                hash VARCHAR NOT NULL, record_index BIGINT NOT NULL, event_time VARCHAR NOT NULL,
                event VARCHAR NOT NULL, PRIMARY KEY(hash, record_index));
             CREATE TABLE IF NOT EXISTS observations (
                hash VARCHAR NOT NULL, record_index BIGINT NOT NULL, event_time VARCHAR NOT NULL,
                event VARCHAR NOT NULL, kind VARCHAR NOT NULL, value VARCHAR NOT NULL,
                PRIMARY KEY(hash, record_index, kind, value));
             CREATE TABLE IF NOT EXISTS nodes (
                kind VARCHAR NOT NULL, value VARCHAR NOT NULL, first_seen VARCHAR NOT NULL,
                last_seen VARCHAR NOT NULL, count BIGINT NOT NULL, PRIMARY KEY(kind, value));
             CREATE TABLE IF NOT EXISTS record_texts (
                hash VARCHAR NOT NULL, record_index BIGINT NOT NULL, text VARCHAR NOT NULL,
                PRIMARY KEY(hash, record_index));
             CREATE TABLE IF NOT EXISTS relations (
                hash VARCHAR NOT NULL, record_index BIGINT NOT NULL, event_time VARCHAR NOT NULL,
                from_kind VARCHAR NOT NULL, from_value VARCHAR NOT NULL, relation VARCHAR NOT NULL,
                to_kind VARCHAR NOT NULL, to_value VARCHAR NOT NULL,
                PRIMARY KEY(hash, record_index, from_kind, from_value, relation, to_kind, to_value));",
        )
        .map_err(storage)?;
        for (name, statement) in [
            (
                "events_time",
                "CREATE INDEX events_time ON events(event_time)",
            ),
            (
                "observations_entity",
                "CREATE INDEX observations_entity ON observations(kind,value)",
            ),
        ] {
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
        Ok(db)
    }

    pub fn index_records(
        &self,
        id: &CaseId,
        hash: &str,
        records: &[GraphRecord],
    ) -> Result<(), AppError> {
        let mut db = self.connect(id)?;
        let tx = db.transaction().map_err(storage)?;
        let indexed: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM indexed WHERE hash=?1",
                params![hash],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if indexed != 0 {
            return Ok(());
        }
        Self::insert_records(&tx, hash, records)?;
        tx.commit().map_err(storage)
    }

    fn insert_records(
        tx: &Transaction<'_>,
        hash: &str,
        records: &[GraphRecord],
    ) -> Result<(), AppError> {
        for record in records {
            let index = i64::try_from(record.index)
                .map_err(|_| storage("record index exceeds DuckDB BIGINT"))?;
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
            for relation in &record.relations {
                tx.execute(
                    "INSERT INTO relations (hash,record_index,event_time,from_kind,from_value,relation,to_kind,to_value) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![hash, index, record.at, relation.from_kind, relation.from_value, relation.relation, relation.to_kind, relation.to_value],
                )
                .map_err(storage)?;
            }
        }
        let count = i64::try_from(records.len())
            .map_err(|_| storage("record count exceeds DuckDB BIGINT"))?;
        tx.execute(
            "INSERT INTO indexed (hash,records) VALUES (?1,?2)",
            params![hash, count],
        )
        .map_err(storage)?;
        Ok(())
    }

    pub fn rebuild<F>(
        &self,
        id: &CaseId,
        sources: &[(String, usize)],
        mut parse: F,
    ) -> Result<usize, AppError>
    where
        F: FnMut(&str) -> Result<Vec<GraphRecord>, AppError>,
    {
        let mut db = self.connect(id)?;
        let tx = db.transaction().map_err(storage)?;
        tx.execute_batch("DELETE FROM relations; DELETE FROM observations; DELETE FROM nodes; DELETE FROM record_texts; DELETE FROM events; DELETE FROM indexed;").map_err(storage)?;
        let mut total = 0usize;
        for (hash, expected) in sources {
            let records = parse(hash)?;
            if records.len() != *expected {
                return Err(storage(format!("signed record count differs for {hash}")));
            }
            Self::insert_records(&tx, hash, &records)?;
            total = total
                .checked_add(records.len())
                .ok_or_else(|| storage("record count overflow"))?;
        }
        tx.commit().map_err(storage)?;
        Ok(total)
    }

    pub fn verify<F>(
        &self,
        id: &CaseId,
        sources: &[(String, usize)],
        mut parse: F,
    ) -> Result<usize, AppError>
    where
        F: FnMut(&str) -> Result<Vec<GraphRecord>, AppError>,
    {
        let db = self.connect(id)?;
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
            let expected = parse(hash)?;
            if expected.len() != *expected_count {
                return Err(storage(format!("signed record count differs for {hash}")));
            }
            let mut statement = db
                .prepare(
                    "SELECT e.record_index,e.event_time,e.event,t.text,o.kind,o.value
                 FROM events e LEFT JOIN record_texts t
                   ON t.hash=e.hash AND t.record_index=e.record_index
                 LEFT JOIN observations o
                   ON o.hash=e.hash AND o.record_index=e.record_index
                 WHERE e.hash=?1 ORDER BY e.record_index,o.kind,o.value",
                )
                .map_err(storage)?;
            let rows = statement
                .query_map(params![hash], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                })
                .map_err(storage)?;
            let mut actual: Vec<GraphRecord> = Vec::new();
            for row in rows {
                let (index, at, event, text, kind, value) = row.map_err(storage)?;
                let index = usize::try_from(index).map_err(|_| storage("invalid record index"))?;
                if actual.last().is_none_or(|last| last.index != index) {
                    actual.push(GraphRecord {
                        index,
                        at,
                        event,
                        text: text.ok_or_else(|| {
                            storage("graph text index is incomplete; run graph-rebuild")
                        })?,
                        entities: Vec::new(),
                        relations: Vec::new(),
                    });
                }
                if let (Some(kind), Some(value)) = (kind, value)
                    && let Some(last) = actual.last_mut()
                {
                    last.entities.push((kind, value));
                }
            }
            let mut relation_statement = db
                .prepare("SELECT record_index,from_kind,from_value,relation,to_kind,to_value FROM relations WHERE hash=?1 ORDER BY record_index,from_kind,from_value,relation,to_kind,to_value")
                .map_err(storage)?;
            let relations = relation_statement
                .query_map(params![hash], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        GraphRelation {
                            from_kind: row.get(1)?,
                            from_value: row.get(2)?,
                            relation: row.get(3)?,
                            to_kind: row.get(4)?,
                            to_value: row.get(5)?,
                        },
                    ))
                })
                .map_err(storage)?;
            let mut by_record = BTreeMap::<usize, Vec<GraphRelation>>::new();
            for row in relations {
                let (index, relation) = row.map_err(storage)?;
                let index =
                    usize::try_from(index).map_err(|_| storage("invalid relation index"))?;
                by_record.entry(index).or_default().push(relation);
            }
            for record in &mut actual {
                record.relations = by_record.remove(&record.index).unwrap_or_default();
            }
            if !by_record.is_empty() {
                return Err(storage("relation references a missing graph record"));
            }
            if actual != expected {
                return Err(storage(format!(
                    "derived graph differs from signed evidence {hash}"
                )));
            }
            for record in &expected {
                expected_relations = expected_relations
                    .checked_add(i64::try_from(record.relations.len()).map_err(storage)?)
                    .ok_or_else(|| storage("relation count overflow"))?;
                for (kind, value) in &record.entities {
                    let node = expected_nodes
                        .entry((kind.clone(), value.clone()))
                        .or_insert_with(|| (record.at.clone(), record.at.clone(), 0));
                    if record.at < node.0 {
                        node.0.clone_from(&record.at);
                    }
                    if record.at > node.1 {
                        node.1.clone_from(&record.at);
                    }
                    node.2 += 1;
                }
            }
            total = total
                .checked_add(expected.len())
                .ok_or_else(|| storage("record count overflow"))?;
        }
        let mut node_statement = db
            .prepare("SELECT kind,value,first_seen,last_seen,count FROM nodes ORDER BY kind,value")
            .map_err(storage)?;
        let actual_nodes = node_statement
            .query_map([], |row| {
                Ok((
                    (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                    (
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                    ),
                ))
            })
            .map_err(storage)?
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map_err(storage)?;
        if actual_nodes != expected_nodes {
            return Err(storage("derived graph nodes differ from signed evidence"));
        }
        let (event_count, text_count, observation_count, relation_count): (i64, i64, i64, i64) = db
            .query_row(
                "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM record_texts),
                (SELECT COUNT(*) FROM observations),(SELECT COUNT(*) FROM relations)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(storage)?;
        let expected_events = i64::try_from(total).map_err(storage)?;
        let expected_observations: i64 = expected_nodes.values().map(|node| node.2).sum();
        if event_count != expected_events
            || text_count != expected_events
            || observation_count != expected_observations
            || relation_count != expected_relations
        {
            return Err(storage(
                "derived graph row counts differ from signed evidence",
            ));
        }
        Ok(total)
    }

    pub fn summary(&self, id: &CaseId) -> Result<String, AppError> {
        let db = self.connect(id)?;
        let records: i64 = db
            .query_row("SELECT COALESCE(SUM(records),0) FROM indexed", [], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        let mut statement = db
            .prepare("SELECT kind,value,count,first_seen,last_seen FROM nodes ORDER BY count DESC,kind,value LIMIT 20")
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok(format!(
                    "{} {} ({} observations; {} to {})",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?
                ))
            })
            .map_err(storage)?;
        let nodes = rows.collect::<Result<Vec<_>, _>>().map_err(storage)?;
        Ok(format!("{records} indexed records\n{}", nodes.join("\n")))
    }

    pub fn timeline(&self, id: &CaseId, limit: usize) -> Result<Vec<TimelineEvent>, AppError> {
        let db = self.connect(id)?;
        let count = i64::try_from(limit.min(1000)).map_err(storage)?;
        let mut statement = db
            .prepare(
                "SELECT event_time,event,hash,record_index FROM
                   (SELECT event_time,event,hash,record_index FROM events
                    ORDER BY event_time DESC,hash,record_index LIMIT ?1)
                 ORDER BY event_time,hash,record_index",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(params![count], |row| {
                let index: i64 = row.get(3)?;
                Ok(TimelineEvent {
                    at: row.get(0)?,
                    event: row.get(1)?,
                    evidence_hash: row.get(2)?,
                    record_index: usize::try_from(index)
                        .map_err(|_| duckdb::Error::InvalidQuery)?,
                })
            })
            .map_err(storage)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(storage)
    }

    pub fn entity_lookup(&self, id: &CaseId, kind: &str, value: &str) -> Result<String, AppError> {
        let db = self.connect(id)?;
        let info: Option<(String, String, i64)> = db
            .query_row(
                "SELECT first_seen,last_seen,count FROM nodes WHERE kind=?1 AND value=?2",
                params![kind, value],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        let Some((first, last, count)) = info else {
            return Ok(format!("{kind} {value}: not found in this case"));
        };
        let mut lines = vec![format!(
            "{kind} {value}: {count} observations; first={}; last={}",
            short(&first, 64),
            short(&last, 64)
        )];
        let mut statement = db
            .prepare(
                "SELECT event_time,event,hash,record_index FROM observations
                 WHERE kind=?1 AND value=?2
                 ORDER BY event_time DESC,hash,record_index LIMIT 5",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(params![kind, value], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(storage)?;
        for row in rows {
            let (at, event, hash, index) = row.map_err(storage)?;
            lines.push(format!(
                "source={hash}#{index} at={} event={}",
                short(&at, 64),
                short(&event, 160)
            ));
        }
        Ok(lines.join("\n"))
    }

    pub fn neighbors(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<String, AppError> {
        let db = self.connect(id)?;
        let count = i64::try_from(limit.min(20)).map_err(storage)?;
        let mut statement = db
            .prepare(
                "SELECT b.kind,b.value,COUNT(*) AS shared,MIN(b.event_time),MAX(b.event_time)
                 FROM observations a JOIN observations b
                   ON a.hash=b.hash AND a.record_index=b.record_index
                 WHERE a.kind=?1 AND a.value=?2 AND NOT (b.kind=?1 AND b.value=?2)
                 GROUP BY b.kind,b.value
                 ORDER BY shared DESC,b.kind,b.value LIMIT ?3",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(params![kind, value, count], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(storage)?;
        let mut lines = vec![format!(
            "Entities co-observed with {kind} {value} in the same source record:"
        )];
        for row in rows {
            let (neighbor_kind, neighbor_value, shared, first, last) = row.map_err(storage)?;
            let (hash, index): (String, i64) = db
                .query_row(
                    "SELECT b.hash,b.record_index FROM observations a JOIN observations b
                       ON a.hash=b.hash AND a.record_index=b.record_index
                     WHERE a.kind=?1 AND a.value=?2 AND b.kind=?3 AND b.value=?4
                     ORDER BY b.event_time,b.hash,b.record_index LIMIT 1",
                    params![kind, value, neighbor_kind, neighbor_value],
                    |source| Ok((source.get(0)?, source.get(1)?)),
                )
                .map_err(storage)?;
            lines.push(format!(
                "{neighbor_kind} {neighbor_value}: {shared} shared records; first={}; last={}; source={hash}#{index}",
                short(&first, 64),
                short(&last, 64)
            ));
        }
        let mut relations = db.prepare(
            "SELECT direction,relation,other_kind,other_value,COUNT(*),MIN(event_time),MAX(event_time),MIN(hash || '#' || CAST(record_index AS VARCHAR)) FROM (
                SELECT 'out' AS direction,relation,to_kind AS other_kind,to_value AS other_value,event_time,hash,record_index FROM relations WHERE from_kind=?1 AND from_value=?2
                UNION ALL
                SELECT 'in' AS direction,relation,from_kind AS other_kind,from_value AS other_value,event_time,hash,record_index FROM relations WHERE to_kind=?1 AND to_value=?2
             ) GROUP BY direction,relation,other_kind,other_value ORDER BY direction,relation,other_kind,other_value LIMIT ?3"
        ).map_err(storage)?;
        let relation_rows = relations
            .query_map(params![kind, value, count], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(storage)?;
        for row in relation_rows {
            let (direction, relation, other_kind, other_value, count, first, last, source) =
                row.map_err(storage)?;
            lines.push(format!("semantic {direction} {relation} {other_kind} {other_value}: {count} events; first={}; last={}; source={source}", short(&first, 64), short(&last, 64)));
        }
        if lines.len() == 1 {
            lines.push("no co-observed entities".into());
        }
        Ok(lines.join("\n"))
    }

    pub fn entity_timeline(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
        limit: usize,
    ) -> Result<String, AppError> {
        let db = self.connect(id)?;
        let count = i64::try_from(limit.min(20)).map_err(storage)?;
        let mut statement = db
            .prepare(
                "SELECT event_time,event,hash,record_index FROM
                   (SELECT event_time,event,hash,record_index FROM observations
                    WHERE kind=?1 AND value=?2
                    ORDER BY event_time DESC,hash,record_index LIMIT ?3)
                 ORDER BY event_time,hash,record_index",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(params![kind, value, count], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(storage)?;
        let mut lines = vec![format!("Recent activity for {kind} {value}:")];
        for row in rows {
            let (at, event, hash, index) = row.map_err(storage)?;
            lines.push(format!(
                "{} {} source={hash}#{index}",
                short(&at, 64),
                short(&event, 160)
            ));
        }
        if lines.len() == 1 {
            lines.push("no activity".into());
        }
        Ok(lines.join("\n"))
    }

    pub fn has_record(&self, id: &CaseId, hash: &str, index: usize) -> Result<bool, AppError> {
        let db = self.connect(id)?;
        let index = i64::try_from(index).map_err(storage)?;
        let exists: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM events WHERE hash=?1 AND record_index=?2",
                params![hash, index],
                |row| row.get(0),
            )
            .map_err(storage)?;
        Ok(exists == 1)
    }

    pub fn text_search(&self, id: &CaseId, query: &str, limit: usize) -> Result<String, AppError> {
        let db = self.connect(id)?;
        let (events, texts, empty): (i64, i64, i64) = db
            .query_row(
                "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM record_texts),
                (SELECT COUNT(*) FROM record_texts WHERE text='')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(storage)?;
        if events != texts || empty != 0 {
            return Err(storage("graph text index is incomplete; run graph-rebuild"));
        }
        let count = i64::try_from(limit).map_err(storage)?;
        let mut statement = db
            .prepare(
                "SELECT e.event_time,e.event,e.hash,e.record_index
                 FROM events e JOIN record_texts t
                   ON t.hash=e.hash AND t.record_index=e.record_index
             WHERE contains(lower(t.text),lower(?1))
             ORDER BY e.event_time DESC,e.hash,e.record_index LIMIT ?2",
            )
            .map_err(storage)?;
        let rows = statement
            .query_map(params![query, count], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(storage)?;
        let mut lines = vec![format!("Indexed JSON record matches for {query}:")];
        for row in rows {
            let (at, event, hash, index) = row.map_err(storage)?;
            lines.push(format!(
                "{} {} source={hash}#{index}",
                short(&at, 64),
                short(&event, 160)
            ));
        }
        if lines.len() == 1 {
            lines.push("no indexed matches".into());
        }
        Ok(lines.join("\n"))
    }

    pub fn path(
        &self,
        id: &CaseId,
        from: (&str, &str),
        to: (&str, &str),
    ) -> Result<String, AppError> {
        let start = (from.0.to_owned(), from.1.to_owned());
        let goal = (to.0.to_owned(), to.1.to_owned());
        let db = self.connect(id)?;
        let present: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM nodes WHERE kind=?1 AND value=?2",
                params![from.0, from.1],
                |row| row.get(0),
            )
            .map_err(storage)?;
        if present == 0 {
            return Ok("starting entity is not indexed in this case".into());
        }
        if start == goal {
            return Ok(format!("{} {} is the same entity", from.0, from.1));
        }
        let mut queue = VecDeque::from([(start.clone(), 0usize)]);
        let mut visited = HashSet::from([start.clone()]);
        let mut previous: HashMap<(String, String), ((String, String), String)> = HashMap::new();
        let mut expanded = 0usize;
        let mut truncated = false;
        while let Some((current, depth)) = queue.pop_front() {
            if depth >= 3 {
                continue;
            }
            if expanded >= 200 {
                truncated = true;
                break;
            }
            expanded += 1;
            let mut statement = db
                .prepare(
                    "SELECT b.kind,b.value,MIN(b.hash || '#' || CAST(b.record_index AS VARCHAR))
                 FROM observations a JOIN observations b
                    ON a.hash=b.hash AND a.record_index=b.record_index
                 WHERE a.kind=?1 AND a.value=?2 AND NOT (b.kind=?1 AND b.value=?2)
                 GROUP BY b.kind,b.value ORDER BY b.kind,b.value LIMIT 51",
                )
                .map_err(storage)?;
            let rows = statement
                .query_map(params![current.0, current.1], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(storage)?;
            let candidates = rows.collect::<Result<Vec<_>, _>>().map_err(storage)?;
            if candidates.len() > 50 {
                truncated = true;
            }
            for (kind, value, source) in candidates.into_iter().take(50) {
                let next = (kind, value);
                if !visited.insert(next.clone()) {
                    continue;
                }
                previous.insert(next.clone(), (current.clone(), source));
                if next == goal {
                    let mut steps = Vec::new();
                    let mut cursor = goal.clone();
                    while cursor != start {
                        let Some((parent, source)) = previous.get(&cursor) else {
                            return Err(storage("incomplete graph path"));
                        };
                        steps.push(format!(
                            "{} {} --[co-observed in {source}]--> {} {}",
                            parent.0, parent.1, cursor.0, cursor.1
                        ));
                        cursor = parent.clone();
                    }
                    steps.reverse();
                    return Ok(steps.join("\n"));
                }
                queue.push_back((next, depth + 1));
            }
        }
        if truncated {
            Ok("no path found within 3 hops / 200 expanded entities / 50 neighbors per entity; search was truncated".into())
        } else {
            Ok("no co-observation path found within 3 hops".into())
        }
    }
}
