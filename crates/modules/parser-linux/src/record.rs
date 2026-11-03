use super::{AppError, GraphRecord, bad};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct Record<'a> {
    pub(super) timestamp: String,
    pub(super) timestamp_inferred: bool,
    pub(super) host: Option<&'a str>,
    pub(super) user: Option<&'a str>,
    pub(super) authentication_method: Option<&'a str>,
    pub(super) url: Option<&'a str>,
    pub(super) http_method: Option<&'a str>,
    pub(super) target_user: Option<&'a str>,
    pub(super) auid: Option<&'a str>,
    pub(super) process: Option<&'a str>,
    pub(super) pid: Option<&'a str>,
    pub(super) command_line: Option<&'a str>,
    pub(super) socket_ip: Option<&'a str>,
    pub(super) socket_port: Option<&'a str>,
    pub(super) source_ip: Option<&'a str>,
    pub(super) source_port: Option<&'a str>,
    pub(super) destination_ip: Option<&'a str>,
    pub(super) destination_port: Option<&'a str>,
    pub(super) cwd: Option<&'a str>,
    pub(super) path: Option<&'a str>,
    pub(super) action: &'a str,
    pub(super) outcome: &'a str,
    pub(super) partial: bool,
    pub(super) raw: &'a str,
}
impl<'a> Record<'a> {
    pub(super) fn new(at: DateTime<Utc>, action: &'a str, raw: &'a str) -> Self {
        Self {
            timestamp: at.to_rfc3339_opts(SecondsFormat::AutoSi, true),
            timestamp_inferred: false,
            host: None,
            user: None,
            target_user: None,
            authentication_method: None,
            url: None,
            http_method: None,
            auid: None,
            process: None,
            pid: None,
            command_line: None,
            source_ip: None,
            socket_ip: None,
            socket_port: None,
            source_port: None,
            destination_ip: None,
            destination_port: None,
            cwd: None,
            path: None,
            action,
            outcome: "unknown",
            partial: false,
            raw,
        }
    }
    pub(super) fn graph(&self, index: usize) -> Result<GraphRecord, AppError> {
        let at = DateTime::parse_from_rfc3339(&self.timestamp)
            .map_err(|_| invalid())?
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        irmind_domain::UtcTimestamp::parse(&at).map_err(|_| invalid())?;
        let mut entities = Vec::new();
        for (kind, value) in [
            ("host", self.host),
            ("user", self.user),
            ("user", self.target_user),
            ("user", self.auid),
            ("process", self.process),
            ("pid", self.pid),
            ("command_line", self.command_line),
            ("ip", self.socket_ip),
            ("ip", self.source_ip),
            ("ip", self.destination_ip),
            ("path", self.path),
            ("path", self.cwd),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty() && value.len() <= 4096) {
                if kind == "ip" && value.parse::<std::net::IpAddr>().is_err() {
                    continue;
                }
                entities.push((kind.into(), value.into()));
            }
        }
        entities.sort();
        entities.dedup();
        Ok(GraphRecord {
            index,
            at,
            event: self.action.into(),
            text: serde_json::to_string(self).map_err(|_| invalid())?,
            entities,
            relations: Vec::new(),
        })
    }
}
fn invalid() -> AppError {
    bad("invalid normalized Linux record")
}
