use super::{
    AppError, CancellationToken, CaseId, ParquetArtifactV1, ParquetStore, PathBuf, storage,
};
use duckdb::{Connection, Row, params_from_iter};
use irmind_app::LargeCaseStore;
use irmind_app::TimelineEvent;
use irmind_domain::GraphQueryFilter;
use std::fmt::Write as _;
use std::sync::mpsc::{self, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

mod path;

const QUERY_DEADLINE: Duration = Duration::from_secs(10);
const MAX_QUERY_FILES: usize = 8192;
const MAX_NEIGHBOR_RECORDS: usize = 4096;

struct QueryDeadline {
    stop: Sender<()>,
    thread: Option<JoinHandle<()>>,
}

impl QueryDeadline {
    fn start(db: &Connection, cancel: CancellationToken, time_limit: Duration) -> Self {
        let interrupt = db.interrupt_handle();
        let (stop, receive) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let start = Instant::now();
            loop {
                if cancel.is_cancelled() || start.elapsed() >= time_limit {
                    interrupt.interrupt();
                    break;
                }
                if receive.recv_timeout(Duration::from_millis(50)).is_ok() {
                    break;
                }
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for QueryDeadline {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl ParquetStore {
    fn verified_paths(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        cancel: &CancellationToken,
    ) -> Result<Vec<PathBuf>, AppError> {
        if artifacts.len() > MAX_QUERY_FILES {
            return Err(AppError::Policy(
                "too many Parquet partitions; narrow the query".into(),
            ));
        }
        let case_dir = self.case_dir(id)?;
        let mut paths = Vec::with_capacity(artifacts.len());
        for artifact in artifacts {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            self.verify_artifact(id, artifact, cancel)?;
            paths.push(case_dir.join(&artifact.path));
        }
        Ok(paths)
    }

    pub(crate) fn search_artifacts(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        term: &str,
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        if term.trim().is_empty() || term.len() > 128 || !(1..=20).contains(&limit) {
            return Err(AppError::Policy("invalid Parquet search arguments".into()));
        }
        if artifacts.is_empty() {
            return Ok("no indexed matches".into());
        }
        let count = limit.to_string();
        let rows = self.query_rows(
            id, artifacts, filter,
            ("SELECT event_time,event,source_hash,record_index FROM {events} WHERE contains(lower(text), lower(?)) ORDER BY event_time DESC,source_hash,record_index LIMIT CAST(? AS BIGINT)", &[term, &count]), cancel,
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, u64>(3)?)),
        )?;
        let mut output = Vec::new();
        for row in rows {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let (at, event, hash, index) = row;
            let at = at.chars().take(32).collect::<String>();
            let event = event.chars().take(160).collect::<String>();
            output.push(format!("{at} {event} source={hash}#{index}"));
        }
        if output.is_empty() {
            Ok("no indexed matches".into())
        } else {
            Ok(output.join("\n"))
        }
    }

    pub(crate) fn timeline_artifacts(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<Vec<TimelineEvent>, AppError> {
        let count = limit.min(100).to_string();
        self.query_rows(id, artifacts, filter,
            ("SELECT event_time,event,source_hash,record_index FROM {events} ORDER BY event_time DESC,source_hash,record_index LIMIT CAST(? AS BIGINT)", &[&count]), cancel,
            |row| Ok(TimelineEvent {
                at: row.get(0)?, event: row.get(1)?, evidence_hash: row.get(2)?,
                record_index: usize::try_from(row.get::<_, u64>(3)?).map_err(|_| duckdb::Error::InvalidParameterName("record index overflow".into()))?,
            }),
        )
    }

    pub(crate) fn entity_timeline_artifacts(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let (kind, value) = entity;
        let count = limit.min(20).to_string();
        let rows = self.query_rows(id, artifacts, filter,
            ("SELECT event_time,event,source_hash,record_index FROM {entities} WHERE entity_kind=? AND entity_value=? ORDER BY event_time DESC LIMIT CAST(? AS BIGINT)", &[kind,value,&count]), cancel,
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, u64>(3)?)),
        )?;
        if rows.is_empty() {
            return Ok("no entity activity in Parquet".into());
        }
        Ok(rows
            .into_iter()
            .map(|(at, event, hash, index)| format!("{at} {event} source={hash}#{index}"))
            .collect::<Vec<_>>()
            .join("\n"))
    }

    pub(crate) fn entity_artifacts(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        kind: &str,
        value: &str,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let rows = self.query_rows(id, artifacts, filter,
            ("SELECT COUNT(*),MIN(event_time),MAX(event_time) FROM {entities} WHERE entity_kind=? AND entity_value=?", &[kind, value]), cancel,
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Option<String>>(1)?, row.get::<_, Option<String>>(2)?)),
        )?;
        let Some((count, first, last)) = rows.into_iter().next() else {
            return Ok("entity not found in Parquet".into());
        };
        Ok(format!(
            "{kind} {value}: count={count}; first={}; last={}",
            first.unwrap_or_default(),
            last.unwrap_or_default()
        ))
    }

    pub(crate) fn neighbors_artifacts(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        entity: (&str, &str),
        limit: usize,
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let (kind, value) = entity;
        let count = limit.min(20).to_string();
        let target_limit = (MAX_NEIGHBOR_RECORDS + 1).to_string();
        let sample_limit = MAX_NEIGHBOR_RECORDS.to_string();
        let rows = self.query_rows(id, artifacts, filter,
            ("WITH records AS NOT MATERIALIZED (SELECT * FROM {entities}), targets AS MATERIALIZED (SELECT source_hash,record_index FROM records WHERE entity_kind=? AND entity_value=? LIMIT CAST(? AS BIGINT)), bounded AS (SELECT source_hash,record_index FROM targets LIMIT CAST(? AS BIGINT)) SELECT n.entity_kind,n.entity_value,COUNT(*),(SELECT COUNT(*) FROM targets)>CAST(? AS BIGINT) FROM records n JOIN bounded USING (source_hash,record_index) WHERE (n.entity_kind<>? OR n.entity_value<>?) GROUP BY 1,2 ORDER BY 3 DESC,1,2 LIMIT CAST(? AS BIGINT)", &[kind, value, &target_limit, &sample_limit, &sample_limit, kind, value, &count]), cancel,
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, u64>(2)?, row.get::<_, bool>(3)?)),
        )?;
        if rows.is_empty() {
            return Ok("no neighbors in the bounded Parquet query; refine the entity".into());
        }
        let sampled = rows[0].3;
        let mut output = rows
            .into_iter()
            .map(|(k, v, n, _)| format!("{k} {v} co-observed {n} times"))
            .collect::<Vec<_>>()
            .join("\n");
        if sampled {
            write!(
                output,
                "\nPartial result: sampled {MAX_NEIGHBOR_RECORDS} matching records; refine the entity to narrow the search."
            )
            .map_err(storage)?;
        }
        Ok(output)
    }

    pub(crate) fn raw_artifact(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        hash: &str,
        index: usize,
        cancel: &CancellationToken,
    ) -> Result<Option<String>, AppError> {
        let index = index.to_string();
        let rows = self.query_rows(id, artifacts, &GraphQueryFilter::default(),
            ("SELECT text FROM {events} WHERE source_hash=? AND record_index=CAST(? AS UBIGINT) LIMIT 1", &[hash, &index]), cancel, |row| row.get::<_, String>(0))?;
        Ok(rows.into_iter().next())
    }

    pub(crate) fn summary_artifacts(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        cancel: &CancellationToken,
    ) -> Result<String, AppError> {
        let rows = self.query_rows(
            id,
            artifacts,
            &GraphQueryFilter::default(),
            (
                "SELECT COUNT(*),MIN(event_time),MAX(event_time) FROM {events}",
                &[],
            ),
            cancel,
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )?;
        let Some((count, first, last)) = rows.into_iter().next() else {
            return Ok("no Parquet records".into());
        };
        Ok(format!(
            "Parquet records={count}; first={}; last={}",
            first.unwrap_or_default(),
            last.unwrap_or_default()
        ))
    }

    fn query_rows<T>(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        template: (&str, &[&str]),
        cancel: &CancellationToken,
        map: impl FnMut(&Row<'_>) -> duckdb::Result<T>,
    ) -> Result<Vec<T>, AppError> {
        self.query_rows_limited(
            id,
            artifacts,
            filter,
            (template.0, template.1, QUERY_DEADLINE),
            cancel,
            map,
        )
    }

    fn query_rows_limited<T>(
        &self,
        id: &CaseId,
        artifacts: &[ParquetArtifactV1],
        filter: &GraphQueryFilter,
        template: (&str, &[&str], Duration),
        cancel: &CancellationToken,
        mut map: impl FnMut(&Row<'_>) -> duckdb::Result<T>,
    ) -> Result<Vec<T>, AppError> {
        let (sql, arguments, time_limit) = template;
        if artifacts.is_empty() {
            return Ok(Vec::new());
        }
        let (marker, schema) = if sql.contains("{events}") {
            ("{events}", "irmind-events-v2")
        } else if sql.contains("{entities}") {
            ("{entities}", "irmind-entities-v1")
        } else {
            return Err(AppError::Policy("invalid Parquet query template".into()));
        };
        let selected = artifacts
            .iter()
            .filter(|artifact| {
                artifact.schema_version == schema && partition_matches(artifact, filter)
            })
            .cloned()
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Ok(Vec::new());
        }
        let verify_started = Instant::now();
        let paths = self.verified_paths(id, &selected, cancel)?;
        if let Some(profile) = &self.profile {
            profile.record_query_verify(verify_started.elapsed());
        }
        let sql_started = Instant::now();
        let db = Connection::open_in_memory().map_err(storage)?;
        db.execute_batch("SET threads=2; SET memory_limit='512MB'")
            .map_err(storage)?;
        let _deadline = QueryDeadline::start(&db, cancel.clone(), time_limit);
        let placeholders = vec!["?"; paths.len()].join(",");
        let relation = if filter.time_range().is_some() {
            format!(
                "(SELECT * FROM read_parquet([{placeholders}]) WHERE event_time>=? AND event_time<=?)"
            )
        } else {
            format!("read_parquet([{placeholders}])")
        };
        let statement = sql.replace(marker, &relation);
        let mut params = paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        if let Some((from, to)) = filter.time_range() {
            params.push(from.to_owned());
            params.push(to.to_owned());
        }
        params.extend(arguments.iter().map(|value| (*value).to_owned()));
        let mut query = db.prepare(&statement).map_err(storage)?;
        let rows = query
            .query_map(params_from_iter(params.iter()), |row| map(row))
            .map_err(storage)?;
        let mut output = Vec::new();
        for row in rows {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            output.push(row.map_err(storage)?);
        }
        if let Some(profile) = &self.profile {
            profile.record_query_sql(sql_started.elapsed());
        }
        Ok(output)
    }
}

fn partition_matches(artifact: &ParquetArtifactV1, filter: &GraphQueryFilter) -> bool {
    filter.time_range().is_none_or(|(from, to)| {
        artifact.partition_date.len() == 10
            && artifact.partition_date.as_str() >= &from[..10]
            && artifact.partition_date.as_str() <= &to[..10]
    }) && filter
        .account_or_project()
        .is_none_or(|value| artifact.partition_account == super::writer::safe_partition(value))
        && filter
            .region()
            .is_none_or(|value| artifact.partition_region == super::writer::safe_partition(value))
}
