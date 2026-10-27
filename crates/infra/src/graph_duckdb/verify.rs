use super::{AppError, BTreeMap, Connection, GraphRecord, GraphRelation, Tainted, params, storage};
use std::collections::BTreeSet;

pub(super) fn fts_markers_complete(db: &Connection) -> Result<bool, AppError> {
    let missing: i64 = db
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM indexed i LEFT JOIN fts_indexed f ON f.hash=i.hash WHERE f.hash IS NULL)
              + (SELECT COUNT(*) FROM fts_indexed f LEFT JOIN indexed i ON i.hash=f.hash WHERE i.hash IS NULL)",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    Ok(missing == 0)
}

pub(super) fn verify_terms(
    db: &Connection,
    hash: &str,
    expected: &[Tainted<GraphRecord>],
    cancel: &irmind_app::CancellationToken,
) -> Result<(), AppError> {
    let mut expected_terms = BTreeSet::new();
    for tainted in expected {
        let mut outcome = Ok(());
        tainted.inspect(|record| {
            outcome = i64::try_from(record.index)
                .map_err(storage)
                .and_then(|index| {
                    for term in super::index::terms(&record.text)? {
                        expected_terms.insert((term, index));
                    }
                    Ok(())
                });
        });
        outcome?;
    }
    let mut statement = db
        .prepare(
            "SELECT term,record_index FROM record_terms WHERE hash=?1 ORDER BY term,record_index",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map(params![hash], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(storage)?;
    let mut actual_terms = BTreeSet::new();
    for (index, row) in rows.enumerate() {
        if index.is_multiple_of(256) && cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        actual_terms.insert(row.map_err(storage)?);
    }
    if actual_terms != expected_terms {
        return Err(storage(
            "graph full-text index differs from signed evidence",
        ));
    }
    Ok(())
}

pub(super) fn verify_graph_totals(
    db: &Connection,
    expected_nodes: &BTreeMap<(String, String), (String, String, i64)>,
    expected_relations: i64,
    total: usize,
) -> Result<(), AppError> {
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
    if actual_nodes != *expected_nodes {
        return Err(storage("derived graph nodes differ from signed evidence"));
    }
    let (event_count, text_count, observation_count, relation_count, indexed, full_text): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM record_texts),
                (SELECT COUNT(*) FROM observations),(SELECT COUNT(*) FROM relations),
                (SELECT COUNT(*) FROM indexed),(SELECT COUNT(*) FROM fts_indexed)",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .map_err(storage)?;
    let expected_events = i64::try_from(total).map_err(storage)?;
    let expected_observations: i64 = expected_nodes.values().map(|node| node.2).sum();
    if event_count != expected_events
        || text_count != expected_events
        || observation_count != expected_observations
        || relation_count != expected_relations
        || indexed != full_text
        || !fts_markers_complete(db)?
    {
        return Err(storage(
            "derived graph row counts differ from signed evidence",
        ));
    }
    Ok(())
}

pub(super) fn accumulate_graph_expectations(
    expected: &[Tainted<GraphRecord>],
    expected_nodes: &mut BTreeMap<(String, String), (String, String, i64)>,
    expected_relations: &mut i64,
) -> Result<(), AppError> {
    for record in expected {
        let mut outcome = Ok(());
        record.inspect(|record| {
            outcome = (|| {
                *expected_relations = (*expected_relations)
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
                Ok(())
            })();
        });
        outcome?;
    }
    Ok(())
}

pub(super) fn attach_graph_relations(
    db: &Connection,
    hash: &str,
    actual: &mut [GraphRecord],
    cancel: &irmind_app::CancellationToken,
) -> Result<(), AppError> {
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
    for (batch_index, row) in relations.enumerate() {
        if batch_index % 256 == 0 && cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (index, relation) = row.map_err(storage)?;
        let index = usize::try_from(index).map_err(|_| storage("invalid relation index"))?;
        by_record.entry(index).or_default().push(relation);
    }
    for record in actual {
        record.relations = by_record.remove(&record.index).unwrap_or_default();
    }
    if !by_record.is_empty() {
        return Err(storage("relation references a missing graph record"));
    }
    Ok(())
}

pub(super) fn read_observed_records(
    db: &Connection,
    hash: &str,
    cancel: &irmind_app::CancellationToken,
) -> Result<Vec<GraphRecord>, AppError> {
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
    for (batch_index, row) in rows.enumerate() {
        if batch_index % 256 == 0 && cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let (index, at, event, text, kind, value) = row.map_err(storage)?;
        let index = usize::try_from(index).map_err(|_| storage("invalid record index"))?;
        if actual.last().is_none_or(|last| last.index != index) {
            actual.push(GraphRecord {
                index,
                at,
                event,
                text: text
                    .ok_or_else(|| storage("graph text index is incomplete; run graph-rebuild"))?,
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
    Ok(actual)
}
