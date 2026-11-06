use super::bad;
use irmind_app::{AppError, GraphRecord, GraphRelation, IndexedGraphRecord, indexed_rfc3339};
use irmind_domain::{IndexedTime, ParserLocation, Provenance, SourceKind, Tainted, TimePrecision};
use serde_json::{Value, json};

fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) if text.len() <= 8192 => Some(text.clone()),
        Value::Number(v) => Some(v.to_string()),
        _ => None,
    }
}
fn event_name(channel: &str, id: u64) -> &'static str {
    let rows: &[(u64, &str)] = if channel.contains("Sysmon") {
        &[
            (1, "process_start"),
            (3, "network_connect"),
            (7, "image_load"),
            (8, "remote_thread"),
            (10, "process_access"),
            (11, "file_create"),
            (12, "registry_create"),
            (13, "registry_set"),
            (22, "dns_query"),
            (23, "file_delete"),
        ]
    } else {
        &[
            (4624, "logon_success"),
            (4625, "logon_failure"),
            (4634, "logoff"),
            (4648, "explicit_credentials"),
            (4672, "privileged_logon"),
            (4688, "process_start"),
            (4697, "service_install"),
            (4698, "scheduled_task_create"),
            (4720, "user_create"),
            (4732, "group_add"),
            (4768, "kerberos_tgt"),
            (4769, "kerberos_service_ticket"),
            (4776, "credential_validation"),
            (1102, "log_cleared"),
            (7045, "service_install"),
            (4103, "command_trace"),
            (4104, "script_block"),
        ]
    };
    rows.iter()
        .find(|(n, _)| *n == id)
        .map_or("windows_event", |(_, name)| *name)
}

pub(super) fn record(
    source: &str,
    hash: [u8; 32],
    index: u64,
    record_id: u64,
    offset: u64,
    timestamp: &str,
    event: &Value,
) -> Result<Tainted<IndexedGraphRecord>, AppError> {
    let parsed = indexed_rfc3339(timestamp, false, false)?;
    if !parsed.instant().submicro_nanos().is_multiple_of(100) {
        return Err(bad("invalid EVTX timestamp precision"));
    }
    let time = IndexedTime::new(parsed.instant(), TimePrecision::Nanosecond, false)
        .map_err(|_| bad("invalid EVTX timestamp precision"))?;
    let system = event
        .pointer("/Event/System")
        .ok_or_else(|| bad("EVTX event has no System fields"))?;
    let id = scalar(system.get("EventID"))
        .or_else(|| scalar(system.pointer("/EventID/#text")))
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| bad("invalid Windows event id"))?;
    let channel = scalar(system.get("Channel")).unwrap_or_default();
    let host = scalar(system.get("Computer"));
    let fields = Fields::extract(event, host.clone());
    let action = event_name(&channel, id);
    let at = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| bad("invalid EVTX timestamp"))?
        .to_utc()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let (entities, relations) = fields.graph();
    let Fields {
        user,
        process,
        command,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        ..
    } = &fields;
    let mut text = json!({"at":at,"timestamp":timestamp,"timestamp_source":"evtx-record-header","timestamp_unit":"100ns","event_id":id,"record_id":record_id,"channel":channel,"host":host,"user":user,"process":process,"command_line":command,"source_ip":source_ip,"source_port":source_port,"destination_ip":destination_ip,"destination_port":destination_port,"action":action,"outcome":if id==4625 {"failure"}else if id==4624 {"success"}else{"unknown"},"attributes":event});
    text.sort_all_objects();
    let record = GraphRecord {
        index: usize::try_from(index).map_err(|_| bad("EVTX record index overflow"))?,
        at,
        event: action.into(),
        text: text.to_string(),
        entities,
        relations,
    };
    let location = ParserLocation::new(source, "parser-evtx", offset)
        .map_err(|_| bad("invalid EVTX provenance"))?;
    let provenance =
        Provenance::new(hash, Some(index), SourceKind::File).with_parser_location(location);
    Ok(Tainted::from_external(
        IndexedGraphRecord {
            record,
            time: Some(time),
            source_offset: Some(offset),
        },
        provenance,
    ))
}

struct Fields {
    host: Option<String>,
    user: Option<String>,
    process: Option<String>,
    command: Option<String>,
    source_ip: Option<String>,
    destination_ip: Option<String>,
    source_port: Option<String>,
    destination_port: Option<String>,
    file: Option<String>,
}
impl Fields {
    fn extract(event: &Value, host: Option<String>) -> Self {
        let fields = event
            .pointer("/Event/EventData")
            .or_else(|| event.pointer("/Event/UserData"));
        let field = |names: &[&str]| names.iter().find_map(|name| lookup(fields, name));
        let user = field(&["TargetUserName", "SubjectUserName", "User", "UserName"]);
        let process = field(&["Image", "NewProcessName", "ProcessName", "Application"]);
        let command = field(&["CommandLine", "ProcessCommandLine"]);
        let source_ip = field(&["SourceIp", "IpAddress", "SourceAddress"]);
        let destination_ip = field(&["DestinationIp", "DestinationAddress"]);
        let source_port = field(&["SourcePort", "IpPort"]);
        let destination_port = field(&["DestinationPort"]);
        let file = field(&["TargetFilename", "FileName", "TargetObject"]);
        Self {
            host,
            user,
            process,
            command,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            file,
        }
    }
    fn graph(&self) -> (Vec<(String, String)>, Vec<GraphRelation>) {
        let Self {
            host,
            user,
            process,
            command,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            file,
        } = self;
        let mut entities = Vec::new();
        for (kind, value) in [
            ("host", host.as_ref()),
            ("user", user.as_ref()),
            ("process", process.as_ref()),
            ("command_line", command.as_ref()),
            ("ip", source_ip.as_ref()),
            ("ip", destination_ip.as_ref()),
            ("port", source_port.as_ref()),
            ("port", destination_port.as_ref()),
            ("file", file.as_ref()),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty() && value.len() <= 4096) {
                entities.push((kind.to_owned(), value.clone()));
            }
        }
        entities.sort();
        entities.dedup();
        let mut relations = Vec::new();
        for (from_kind, from, to_kind, to, relation) in [
            (
                "ip",
                source_ip.as_ref(),
                "host",
                host.as_ref(),
                "connected_to",
            ),
            ("user", user.as_ref(), "host", host.as_ref(), "observed_on"),
            (
                "host",
                host.as_ref(),
                "process",
                process.as_ref(),
                "executed",
            ),
        ] {
            if let (Some(from), Some(to)) = (from, to) {
                relations.push(GraphRelation {
                    from_kind: from_kind.into(),
                    from_value: from.clone(),
                    relation: relation.into(),
                    to_kind: to_kind.into(),
                    to_value: to.clone(),
                });
            }
        }
        (entities, relations)
    }
}

fn lookup(fields: Option<&Value>, name: &str) -> Option<String> {
    let fields = fields?;
    if let Some(value) = scalar(fields.get(name)) {
        return Some(value);
    }
    let data = fields.get("Data")?;
    let one = |value: &Value| {
        let key = value
            .get("#attributes")
            .and_then(|a| a.get("Name"))
            .or_else(|| value.get("@Name"));
        if key.and_then(Value::as_str) == Some(name) {
            scalar(value.get("#text"))
        } else {
            None
        }
    };
    if let Some(rows) = data.as_array() {
        rows.iter().find_map(one)
    } else {
        one(data)
    }
}
