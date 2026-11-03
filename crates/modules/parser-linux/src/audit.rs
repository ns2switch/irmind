use super::{AppError, GraphRecord, bad, record::Record};
use chrono::DateTime;
use std::collections::BTreeMap;
mod arguments;
mod encoding;
mod fields;
use fields::Line;

const MAX_GROUPS: usize = 64;
const MAX_GROUP_BYTES: usize = 256 * 1024;
const MAX_GROUP_RECORDS: usize = 128;
const END_OF_EVENT_SECONDS: i64 = 2;
type Key = (String, i64, u32, u64);
#[derive(Default)]
pub(super) struct AuditState {
    groups: BTreeMap<Key, Group>,
}
struct Group {
    lines: Vec<String>,
    bytes: usize,
    index: usize,
    offset: u64,
    locations: Vec<(usize, u64)>,
}
pub(super) struct Completed {
    pub(super) record: GraphRecord,
    pub(super) offset: u64,
}
pub(super) fn detect(line: &str) -> bool {
    Line::parse(line).is_ok()
}
impl AuditState {
    pub(super) fn push(
        &mut self,
        text: &str,
        index: usize,
        offset: u64,
    ) -> Result<Vec<Completed>, AppError> {
        let line = Line::parse(text)?;
        let key = (
            line.field("node").unwrap_or("").to_owned(),
            line.seconds,
            line.nanos,
            line.serial,
        );
        if text.len() > MAX_GROUP_BYTES
            || self.groups.get(&key).is_some_and(|group| {
                group.lines.len() >= MAX_GROUP_RECORDS || group.bytes + text.len() > MAX_GROUP_BYTES
            })
        {
            return Err(bad("audit event exceeds its record or byte limit"));
        }
        let expired = self
            .groups
            .keys()
            .filter(|key| line.seconds.saturating_sub(key.1) > END_OF_EVENT_SECONDS)
            .cloned()
            .collect::<Vec<_>>();
        let mut ready = Vec::new();
        for old in expired {
            if let Some(group) = self.groups.remove(&old) {
                ready.push(finish(&old, &group, true)?);
            }
        }
        if !self.groups.contains_key(&key)
            && self.groups.len() >= MAX_GROUPS
            && let Some((old, group)) = self.groups.pop_first()
        {
            ready.push(finish(&old, &group, true)?);
        }
        let group = self.groups.entry(key.clone()).or_insert_with(|| Group {
            lines: vec![],
            bytes: 0,
            index,
            offset,
            locations: vec![],
        });
        group.bytes += text.len();
        group.lines.push(text.to_owned());
        group.locations.push((index, offset));
        if line.field("type") == Some("EOE")
            && let Some(group) = self.groups.remove(&key)
        {
            ready.push(finish(&key, &group, false)?);
        }
        Ok(ready)
    }
    pub(super) fn finish(&mut self) -> Result<Vec<Completed>, AppError> {
        std::mem::take(&mut self.groups)
            .into_iter()
            .map(|(key, group)| finish(&key, &group, true))
            .collect()
    }
}
fn finish(key: &Key, group: &Group, partial: bool) -> Result<Completed, AppError> {
    let raw = group.lines.join("\n");
    let Collected {
        combined,
        arguments,
        syscall,
        sockaddr,
        execution,
        core,
        paths,
    } = collect(group)?;
    let (argv, argv_complete) = arguments.finish();
    let command = argv.join(" ");
    let at = DateTime::from_timestamp(key.1, key.2)
        .ok_or_else(|| bad("invalid audit event timestamp"))?;
    let mut record = Record::new(
        at,
        if execution {
            "process_execute"
        } else {
            "audit_event"
        },
        &raw,
    );
    record.host = (!key.0.is_empty()).then_some(key.0.as_str());
    record.partial = partial || !core || (execution && !argv_complete);
    record.user = combined.get("uid").map(AsRef::as_ref);
    record.auid = combined.get("auid").map(AsRef::as_ref);
    record.pid = combined.get("pid").map(AsRef::as_ref);
    record.process = combined
        .get("exe")
        .or_else(|| combined.get("comm"))
        .map(AsRef::as_ref);
    record.cwd = combined.get("cwd").map(AsRef::as_ref);
    record.path = combined.get("name").map(AsRef::as_ref);
    let socket = sockaddr.and_then(encoding::socket);
    record.socket_ip = socket.as_ref().map(|(ip, _)| ip.as_str());
    record.socket_port = socket.as_ref().map(|(_, port)| port.as_str());
    record.command_line = (!command.is_empty()).then_some(command.as_str());
    record.outcome = match combined.get("success").map(AsRef::as_ref) {
        Some("yes") => "success",
        Some("no") => "failure",
        _ => "unknown",
    };
    let mut graph = record.graph(group.index)?;
    graph.entities.extend(
        paths
            .iter()
            .filter(|path| !path.is_empty() && path.len() <= 4096)
            .map(|path| ("path".into(), path.to_string())),
    );
    graph.entities.sort();
    graph.entities.dedup();
    graph.text = serde_json::to_string(&AuditRecord {
        event: record,
        serial: key.3,
        syscall,
        sockaddr,
        original_records: group.lines.len(),
        arguments: &argv,
        arguments_complete: execution.then_some(argv_complete),
        record_locations: &group.locations,
        paths: &paths,
    })
    .map_err(|_| bad("cannot normalize audit event"))?;
    Ok(Completed {
        record: graph,
        offset: group.offset,
    })
}

#[derive(serde::Serialize)]
struct AuditRecord<'a> {
    event: Record<'a>,
    serial: u64,
    syscall: Option<&'a str>,
    sockaddr: Option<&'a str>,
    original_records: usize,
    arguments: &'a [String],
    arguments_complete: Option<bool>,
    record_locations: &'a [(usize, u64)],
    paths: &'a [std::borrow::Cow<'a, str>],
}

struct Collected<'a> {
    combined: BTreeMap<&'a str, std::borrow::Cow<'a, str>>,
    arguments: arguments::Arguments<'a>,
    execution: bool,
    core: bool,
    paths: Vec<std::borrow::Cow<'a, str>>,
    syscall: Option<&'a str>,
    sockaddr: Option<&'a str>,
}
fn collect(group: &Group) -> Result<Collected<'_>, AppError> {
    let mut combined = BTreeMap::new();
    let mut arguments = arguments::Arguments::default();
    let mut syscall = None;
    let mut sockaddr = None;
    let mut execution = false;
    let mut core = false;
    let mut paths = Vec::new();
    for text in &group.lines {
        let line = Line::parse(text)?;
        if line.field("type") == Some("SYSCALL") {
            syscall = line.field("syscall");
            core = true;
        }
        if line.field("type") == Some("SOCKADDR") {
            sockaddr = line.field("saddr");
        }
        if line.field("type") == Some("PATH")
            && let Some(path) = line.decoded("name")
        {
            paths.push(path);
        }
        if line.field("type") == Some("EXECVE") {
            arguments.add(&line);
            execution = true;
        }

        for (&name, &value) in &line.fields {
            let decoded = if matches!(name, "exe" | "comm" | "cwd" | "name") {
                line.decoded(name)
                    .unwrap_or(std::borrow::Cow::Borrowed(value))
            } else {
                std::borrow::Cow::Borrowed(value)
            };
            combined.insert(name, decoded);
        }
    }
    Ok(Collected {
        combined,
        arguments,
        execution,
        core,
        paths,
        syscall,
        sockaddr,
    })
}
