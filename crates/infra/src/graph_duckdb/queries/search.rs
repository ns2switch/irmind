impl GraphStore {
    pub(crate) fn has_record(
        &self,
        id: &CaseId,
        hash: &str,
        index: usize,
    ) -> Result<bool, AppError> {
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

    pub(crate) fn text_search(
        &self,
        id: &CaseId,
        query: &str,
        limit: usize,
    ) -> Result<String, AppError> {
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

    pub(crate) fn path(
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
            let candidates = Self::path_candidates(&db, &current)?;
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
    fn path_candidates(
        db: &Connection,
        current: &(String, String),
    ) -> Result<Vec<(String, String, String)>, AppError> {
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
        rows.collect::<Result<Vec<_>, _>>().map_err(storage)
    }
}
