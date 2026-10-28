use super::{
    AppError, CaseId, Connection, GraphStore, OptionalExt, TimelineEvent, params, short, storage,
};

impl GraphStore {
    pub(crate) fn summary(&self, id: &CaseId) -> Result<String, AppError> {
        let db = self.connect_inner(id, false)?;
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

    pub(crate) fn timeline(
        &self,
        id: &CaseId,
        limit: usize,
    ) -> Result<Vec<TimelineEvent>, AppError> {
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

    pub(crate) fn entity_lookup(
        &self,
        id: &CaseId,
        kind: &str,
        value: &str,
    ) -> Result<String, AppError> {
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

    pub(crate) fn neighbors(
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
        Self::append_semantic_neighbors(&db, kind, value, count, &mut lines)?;
        if lines.len() == 1 {
            lines.push("no co-observed entities".into());
        }
        Ok(lines.join("\n"))
    }

    fn append_semantic_neighbors(
        db: &Connection,
        kind: &str,
        value: &str,
        count: i64,
        lines: &mut Vec<String>,
    ) -> Result<(), AppError> {
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
        Ok(())
    }

    pub(crate) fn entity_timeline(
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
}
