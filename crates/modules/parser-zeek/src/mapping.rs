use chrono::{DateTime, SecondsFormat, Utc};
use irmind_app::{AppError, GraphRecord, GraphRelation};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct JsonRow<'a> {
    ts: Option<serde_json::Number>,
    #[serde(borrow)]
    uid: Option<&'a str>,
    #[serde(borrow, rename = "id.orig_h")]
    orig_h: Option<&'a str>,
    #[serde(borrow, rename = "id.resp_h")]
    resp_h: Option<&'a str>,
    #[serde(rename = "id.orig_p")]
    orig_p: Option<serde_json::Number>,
    #[serde(rename = "id.resp_p")]
    resp_p: Option<serde_json::Number>,
    #[serde(borrow)]
    query: Option<&'a str>,
    #[serde(borrow)]
    host: Option<&'a str>,
    #[serde(borrow)]
    method: Option<&'a str>,
    #[serde(borrow)]
    uri: Option<&'a str>,
    #[serde(borrow)]
    server_name: Option<&'a str>,
    #[serde(borrow)]
    fuid: Option<&'a str>,
    #[serde(borrow)]
    filename: Option<&'a str>,
    #[serde(borrow)]
    fingerprint: Option<&'a str>,
    #[serde(borrow)]
    note: Option<&'a str>,
    #[serde(borrow)]
    name: Option<&'a str>,
    #[serde(borrow)]
    user_agent: Option<&'a str>,
}

#[derive(Default)]
struct Fields<'a> {
    uid: Option<&'a str>,
    orig_h: Option<&'a str>,
    resp_h: Option<&'a str>,
    orig_p: Option<&'a str>,
    resp_p: Option<&'a str>,
    query: Option<&'a str>,
    host: Option<&'a str>,
    server_name: Option<&'a str>,
    fuid: Option<&'a str>,
    filename: Option<&'a str>,
    fingerprint: Option<&'a str>,
    note: Option<&'a str>,
    name: Option<&'a str>,
    user_agent: Option<&'a str>,
}

pub(super) fn detect_json(sample: &[u8]) -> Option<u8> {
    let first = sample
        .split(|byte| *byte == b'\n')
        .find(|line| !line.is_empty())?;
    let row: JsonRow<'_> = serde_json::from_slice(first).ok()?;
    row.ts.as_ref()?;
    if row.uid.is_some() && row.orig_h.is_some() {
        Some(95)
    } else if row.fingerprint.is_some() || row.fuid.is_some() || row.note.is_some() {
        Some(80)
    } else {
        None
    }
}

pub(super) fn from_json(source: &str, line: &[u8], index: usize) -> Result<GraphRecord, AppError> {
    let row: JsonRow<'_> = serde_json::from_slice(line).map_err(|_| bad())?;
    let at = epoch_to_utc(&row.ts.as_ref().ok_or_else(bad)?.to_string())?;
    let kind = infer_kind(source, &row);
    let orig_p = row.orig_p.as_ref().map(ToString::to_string);
    let resp_p = row.resp_p.as_ref().map(ToString::to_string);
    let fields = Fields {
        uid: row.uid,
        orig_h: row.orig_h,
        resp_h: row.resp_h,
        orig_p: orig_p.as_deref(),
        resp_p: resp_p.as_deref(),
        query: row.query,
        host: row.host,
        server_name: row.server_name,
        fuid: row.fuid,
        filename: row.filename,
        fingerprint: row.fingerprint,
        note: row.note,
        name: row.name,
        user_agent: row.user_agent,
    };
    let text = std::str::from_utf8(line)
        .map_err(|_| bad())?
        .trim_end()
        .to_owned();
    Ok(build_record(index, at, kind, text, &fields))
}

pub(super) fn from_tsv(
    path: &str,
    headers: &[String],
    line: &[u8],
    index: usize,
) -> Result<GraphRecord, AppError> {
    let text = std::str::from_utf8(line).map_err(|_| bad())?.trim_end();
    let cells = text.split('\t').collect::<Vec<_>>();
    if cells.len() != headers.len() {
        return Err(bad());
    }
    let values = headers
        .iter()
        .zip(cells)
        .map(|(name, value)| (name.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    let field = |name| {
        values
            .get(name)
            .copied()
            .filter(|value| !matches!(*value, "-" | "(empty)" | ""))
    };
    let raw_time = field("ts").ok_or_else(bad)?;
    let at = epoch_to_utc(raw_time)?;
    let fields = Fields {
        uid: field("uid"),
        orig_h: field("id.orig_h"),
        resp_h: field("id.resp_h"),
        orig_p: field("id.orig_p"),
        resp_p: field("id.resp_p"),
        query: field("query"),
        host: field("host"),
        server_name: field("server_name"),
        fuid: field("fuid"),
        filename: field("filename"),
        fingerprint: field("fingerprint"),
        note: field("note"),
        name: field("name"),
        user_agent: field("user_agent"),
    };
    let mut normalized = values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect::<BTreeMap<_, _>>();
    normalized.insert("provider".into(), "zeek".into());
    normalized.insert("log_type".into(), path.into());
    normalized.insert("source_timestamp".into(), raw_time.into());
    let text = serde_json::to_string(&normalized).map_err(|_| bad())?;
    Ok(build_record(index, at, path, text, &fields))
}

fn infer_kind<'a>(source: &'a str, row: &JsonRow<'_>) -> &'a str {
    for kind in [
        "conn", "dns", "http", "ssl", "files", "x509", "notice", "weird",
    ] {
        if source
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with(kind))
        {
            return kind;
        }
    }
    if row.query.is_some() {
        "dns"
    } else if row.method.is_some() || row.uri.is_some() {
        "http"
    } else if row.server_name.is_some() {
        "ssl"
    } else if row.fuid.is_some() {
        "files"
    } else if row.fingerprint.is_some() {
        "x509"
    } else if row.note.is_some() {
        "notice"
    } else if row.name.is_some() {
        "weird"
    } else {
        "conn"
    }
}

fn epoch_to_utc(raw: &str) -> Result<String, AppError> {
    let (seconds, fraction) = raw.split_once('.').unwrap_or((raw, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 9
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(bad());
    }
    let seconds = seconds.parse::<i64>().map_err(|_| bad())?;
    let nanos = if fraction.is_empty() {
        0
    } else {
        let mut padded = fraction.to_owned();
        padded.extend(std::iter::repeat_n('0', 9 - fraction.len()));
        padded.parse::<u32>().map_err(|_| bad())?
    };
    let at = DateTime::<Utc>::from_timestamp(seconds, nanos).ok_or_else(bad)?;
    Ok(at.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

fn build_record(
    index: usize,
    at: String,
    kind: &str,
    text: String,
    fields: &Fields<'_>,
) -> GraphRecord {
    let mut entities = Vec::new();
    for (entity_kind, value) in [
        ("uid", fields.uid),
        ("ip", fields.orig_h),
        ("ip", fields.resp_h),
        ("port", fields.orig_p),
        ("port", fields.resp_p),
        ("domain", fields.query),
        ("host", fields.host),
        ("domain", fields.server_name),
        ("file", fields.filename),
        ("fuid", fields.fuid),
        ("certificate", fields.fingerprint),
        ("finding", fields.note),
        ("finding", fields.name),
        ("user_agent", fields.user_agent),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty() && value.len() <= 4096) {
            entities.push((entity_kind.into(), value.into()));
        }
    }
    entities.sort();
    entities.dedup();
    let mut relations = Vec::new();
    if let Some(uid) = fields.uid {
        for (other_kind, value, relation) in [
            ("ip", fields.orig_h, "originated_from"),
            ("ip", fields.resp_h, "responded_at"),
            ("domain", fields.query, "queried"),
            ("domain", fields.server_name, "connected_to"),
            ("fuid", fields.fuid, "transferred"),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty() && value.len() <= 4096) {
                relations.push(GraphRelation {
                    from_kind: "uid".into(),
                    from_value: uid.into(),
                    relation: relation.into(),
                    to_kind: other_kind.into(),
                    to_value: value.into(),
                });
            }
        }
    }
    GraphRecord {
        index,
        at,
        event: format!("zeek_{kind}"),
        text,
        entities,
        relations,
    }
}

fn bad() -> AppError {
    AppError::Policy("invalid Zeek record".into())
}
