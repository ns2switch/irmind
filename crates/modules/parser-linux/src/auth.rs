use super::time::Calendar;
use chrono::DateTime;

pub(super) struct Header<'a> {
    pub(super) time: &'a str,
    pub(super) host: &'a str,
    pub(super) app: &'a str,
    pub(super) pid: Option<&'a str>,
    pub(super) message: &'a str,
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
