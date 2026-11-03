use super::{AppError, LinuxParser, bad, record::Record, time::Calendar};
use chrono::{DateTime, Utc};

pub(super) struct Header<'a> {
    pub(super) time: &'a str,
    pub(super) host: &'a str,
    app: &'a str,
    pid: Option<&'a str>,
    message: &'a str,
    pub(super) classic: bool,
}
pub(super) fn header(line: &str) -> Option<Header<'_>> {
    let line = if line.starts_with('<') {
        let (pri, rest) = line.strip_prefix('<')?.split_once('>')?;
        if pri.len() > 3 || pri.parse::<u8>().ok()? > 191 {
            return None;
        }
        rest
    } else {
        line
    };
    let classic = super::time::month(line).is_some();
    let (time, rest) = if classic {
        (
            line.get(..15)?,
            line.get(16..)
                .filter(|_| line.as_bytes().get(15) == Some(&b' '))?,
        )
    } else {
        line.split_once(' ')?
    };
    let (host, tagged) = rest.split_once(' ')?;
    let (tag, message) = tagged.split_once(':')?;
    let (app, pid) = if let Some((app, pid)) = tag.split_once('[') {
        (app, Some(pid.strip_suffix(']')?))
    } else {
        (tag, None)
    };
    if host.is_empty() || host.len() > 255 || app.is_empty() || app.len() > 128 {
        return None;
    }
    Some(Header {
        time,
        host,
        app,
        pid,
        message: message.trim_start(),
        classic,
    })
}
pub(super) fn detect(line: &str) -> bool {
    if line.starts_with('<') {
        return false;
    }
    let Some(header) = header(line) else {
        return false;
    };
    let valid_time = if header.classic {
        irmind_app::ParserTimeContext::new(2000, 0, true, irmind_app::ParserTimeBasis::Analyst)
            .ok()
            .and_then(|context| Calendar::new(context).candidate(header.time).ok())
            .is_some()
    } else {
        DateTime::parse_from_rfc3339(header.time).is_ok()
    };
    valid_time
        && matches!(
            header.app,
            "sshd" | "sudo" | "su" | "useradd" | "usermod" | "CRON" | "crond" | "cron"
        )
}
pub(super) fn parse(
    parser: &LinuxParser,
    source: &str,
    line: &str,
    index: usize,
    calendar: &mut Option<Calendar>,
) -> Result<super::GraphRecord, AppError> {
    let header = header(line).ok_or_else(invalid)?;
    let mut candidate = None;
    let at = if header.classic {
        let Some(current) = *calendar else {
            return Err(AppError::ParserTimeContextRequired {
                source_name: source.into(),
                requirement: super::time::requirement(parser, source, line.as_bytes())?
                    .ok_or_else(invalid)?,
                suggestions: vec![],
            });
        };
        let (next, at) = current.candidate(header.time)?;
        candidate = Some(next);
        at
    } else {
        DateTime::parse_from_rfc3339(header.time)
            .map_err(|_| invalid())?
            .with_timezone(&Utc)
    };
    let mut record = Record::new(at, header.app, line);
    record.host = Some(header.host);
    record.process = Some(header.app);
    record.pid = header.pid;
    record.timestamp_inferred = header.classic;
    map(&header, &mut record);
    let graph = record.graph(index)?;
    if let Some(candidate) = candidate {
        *calendar = Some(candidate);
    }
    Ok(graph)
}
fn map<'a>(header: &Header<'a>, row: &mut Record<'a>) {
    let body = header.message;
    match header.app {
        "sshd" => {
            row.action = if ["Accepted ", "Failed ", "Invalid user "]
                .iter()
                .any(|prefix| body.starts_with(prefix))
            {
                "ssh_login"
            } else {
                "ssh_session"
            };
            row.outcome = if body.starts_with("Accepted ") {
                "success"
            } else if body.starts_with("Failed ") || body.starts_with("Invalid user ") {
                "failure"
            } else {
                "unknown"
            };
            row.authentication_method =
                if body.starts_with("Accepted ") || body.starts_with("Failed ") {
                    body.split_ascii_whitespace().nth(1)
                } else {
                    None
                };
            row.user = after(body, "for ")
                .or_else(|| body.strip_prefix("Invalid user "))
                .map(|rest| rest.strip_prefix("invalid user ").unwrap_or(rest))
                .and_then(|rest| rest.split_ascii_whitespace().next());
            row.source_ip =
                after(body, "from ").and_then(|rest| rest.split_ascii_whitespace().next());
            row.source_port =
                after(body, "port ").and_then(|rest| rest.split_ascii_whitespace().next());
        }
        "sudo" => {
            row.action = if body.contains("COMMAND=") {
                "sudo_command"
            } else {
                "sudo_session"
            };
            row.user = body.split_once(" :").map(|(user, _)| user.trim());
            row.target_user = item(body, "USER=");
            row.cwd = item(body, "PWD=");
            row.command_line = after(body, "COMMAND=");
        }
        "su" => {
            row.action = "su_session";
            row.target_user =
                after(body, "for user ").and_then(|rest| rest.split_ascii_whitespace().next());
            row.user = after(body, "by ").and_then(|rest| rest.split(['(', ' ']).next());
        }
        "useradd" => {
            row.action = "user_add";
            row.user = after(body, "name=").and_then(|rest| rest.split([',', ' ']).next());
        }
        "usermod" => {
            row.action = "user_modify";
            row.user = body
                .split_once('\'')
                .and_then(|(_, rest)| rest.split_once('\''))
                .map(|(user, _)| user);
        }
        "CRON" | "cron" | "crond" => {
            row.action = "cron_command";
            row.user = body
                .strip_prefix('(')
                .and_then(|rest| rest.split_once(')'))
                .map(|(user, _)| user);
            row.command_line = after(body, "CMD (").and_then(|rest| rest.strip_suffix(')'));
        }
        _ => {}
    }
}
fn after<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.split_once(prefix).map(|(_, rest)| rest)
}
fn item<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    after(text, key).map(|value| value.split(';').next().unwrap_or(value).trim())
}
fn invalid() -> AppError {
    bad("invalid Linux authentication record")
}
