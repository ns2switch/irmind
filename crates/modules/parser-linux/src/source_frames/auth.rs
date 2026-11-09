use super::{
    Decoded, SourceMetadata, invalid,
    record::{member, object, text},
};
use crate::time::Calendar;
use irmind_app::source_mapping::SourceValue;
use irmind_app::{AppError, IndexedTime};
use irmind_domain::TimePrecision;

pub(super) fn decode(
    meta: SourceMetadata<'_>,
    line: &str,
    index: u64,
    offset: u64,
    calendar: &mut Option<Calendar>,
) -> Result<Decoded, AppError> {
    let header = crate::auth::header(line).ok_or_else(invalid)?;
    let (timestamp, next) = if header.classic {
        let Some(current) = *calendar else {
            return Err(AppError::ParserTimeContextRequired {
                source_name: meta.source.reference().into(),
                requirement: crate::time::requirement(
                    &crate::LinuxParser::default(),
                    meta.source.reference(),
                    line.as_bytes(),
                )?
                .ok_or_else(invalid)?,
                suggestions: vec![],
            });
        };
        let (next, at) = current.candidate(header.time)?;
        let parsed = IndexedTime::from_rfc3339(&at.to_rfc3339(), true).map_err(|_| invalid())?;
        (
            IndexedTime::new(parsed.instant(), TimePrecision::Second, true)
                .map_err(|_| invalid())?,
            Some(next),
        )
    } else {
        (
            IndexedTime::from_rfc3339(header.time, false).map_err(|_| invalid())?,
            None,
        )
    };
    let fields = object(vec![
        (
            "syslog",
            object(vec![
                ("timestamp", text(header.time)),
                ("hostname", text(header.host)),
                ("appname", text(header.app)),
                ("procid", header.pid.map_or(SourceValue::Null, text)),
                ("msg", text(header.message)),
            ])?,
        ),
        (header.app, tokens(header.app, header.message)?),
    ])?;
    if let Some(next) = next {
        *calendar = Some(next);
    }
    Ok(Decoded {
        fields,
        timestamp,
        dataset: header.app.into(),
        partial: false,
        members: vec![member(index, offset)],
        offset: Some(offset),
        raw: Some(line.into()),
    })
}
fn tokens(app: &str, message: &str) -> Result<SourceValue, AppError> {
    let mut fields = Vec::new();
    if app == "sshd" {
        let mut words = message.split_ascii_whitespace();
        if let Some(verb) = words.next() {
            fields.push(("verb", text(verb)));
        }
        if (message.starts_with("Accepted ") || message.starts_with("Failed "))
            && let Some(method) = words.next()
        {
            fields.push(("method", text(method)));
        }
        let user = message
            .split_once(" for ")
            .map(|(_, r)| r)
            .or_else(|| message.strip_prefix("Invalid user "))
            .map(|r| r.strip_prefix("invalid user ").unwrap_or(r))
            .and_then(|r| r.split_ascii_whitespace().next());
        if let Some(user) = user {
            fields.push(("user", text(user)));
        }
        for (key, marker) in [("from", " from "), ("port", " port ")] {
            if let Some(word) = message
                .split_once(marker)
                .and_then(|(_, s)| s.split_ascii_whitespace().next())
            {
                fields.push((key, text(word)));
            }
        }
    } else if app == "sudo"
        && let Some((user, rest)) = message.split_once(" : ")
    {
        fields.push(("user", text(user.trim())));
        let prefix = rest.split_once("COMMAND=").map_or(rest, |(p, command)| {
            fields.push(("COMMAND", text(command)));
            p
        });
        for (key, value) in prefix
            .split(';')
            .filter_map(|item| item.trim().split_once('='))
        {
            if matches!(key, "USER" | "PWD" | "TTY") {
                fields.push((key, text(value.trim())));
            }
        }
    }
    pam(message, &mut fields);
    object(fields)
}
fn pam<'a>(message: &'a str, fields: &mut Vec<(&'a str, SourceValue)>) {
    if message.contains(": authentication failure;") {
        fields.push(("pam_transition", text("authentication failure")));
        let tail = message
            .split_once("authentication failure;")
            .map_or("", |(_, r)| r);
        for item in tail.split_ascii_whitespace() {
            if let Some((key, value)) = item.split_once('=') {
                match key {
                    "logname" => fields.push(("pam_actor", text(value))),
                    "user" => fields.push(("pam_target", text(value))),
                    "rhost" => fields.push(("pam_rhost", text(value))),
                    _ => {}
                }
            }
        }
    }
    for transition in ["opened", "closed"] {
        let marker = format!(": session {transition} for user ");
        if let Some((_, rest)) = message.split_once(&marker) {
            fields.push(("pam_transition", text(transition)));
            if let Some(user) = rest.split(['(', ' ']).next() {
                fields.push(("pam_target", text(user)));
            }
            if let Some((_, actor)) = rest.split_once(" by ")
                && let Some(user) = actor.split(['(', ' ']).next()
            {
                fields.push(("pam_actor", text(user)));
            }
        }
    }
}
