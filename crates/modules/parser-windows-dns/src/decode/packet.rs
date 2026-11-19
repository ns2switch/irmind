pub(super) struct Packet<'a> {
    pub(super) date: &'a str,
    pub(super) clock: &'a str,
    pub(super) meridiem: &'a str,
    pub(super) thread: &'a str,
    pub(super) pointer: &'a str,
    pub(super) transport: &'a str,
    pub(super) direction: &'a str,
    pub(super) remote: &'a str,
    pub(super) xid: &'a str,
    pub(super) message: &'a str,
    pub(super) opcode: &'a str,
    pub(super) flags: &'a str,
    pub(super) rcode: &'a str,
    pub(super) qtype: &'a str,
    name: &'a str,
    pub(super) trailing: Option<&'a str>,
}

impl<'a> Packet<'a> {
    pub(super) fn parse(line: &'a str) -> Option<Self> {
        let (prefix, rest) = line.split_once('[')?;
        let (flags, suffix) = rest.split_once(']')?;
        let (head, message, opcode) = prefix_fields(prefix)?;
        let [
            date,
            clock,
            meridiem,
            thread,
            pointer,
            transport,
            direction,
            remote,
            xid,
        ] = head;
        let mut values = suffix.trim_ascii().splitn(2, char::is_whitespace);
        let qtype = values.next()?.trim_ascii();
        let name_and_rest = values.next()?.trim_ascii_start();
        // DNS labels carry their lengths and may include whitespace. The root
        // terminator, not whitespace, ends the original name.
        let (name, trailing) = dns_name_end(name_and_rest)?;
        let rcode = flags.split_ascii_whitespace().next_back()?;
        if !qtype
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || qtype.is_empty()
            || qtype.len() > 32
            || !rcode.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || rcode.len() > 32
            || flags.len() > 128
        {
            return None;
        }
        Some(Self {
            date,
            clock,
            meridiem,
            thread,
            pointer,
            transport,
            direction,
            remote,
            xid,
            message,
            opcode,
            flags,
            rcode,
            qtype,
            name,
            trailing,
        })
    }

    pub(super) fn day(&self) -> Option<u8> {
        self.date.split('/').nth(1)?.parse().ok()
    }

    pub(super) fn year(&self) -> Option<u16> {
        let year = self.date.split('/').nth(2)?;
        (year.len() == 4).then(|| year.parse().ok()).flatten()
    }

    pub(super) fn datetime(&self, offset: &str) -> Option<String> {
        let [month, day, year] = exact_parts(self.date, '/')?;
        let [hour, minute, second] = exact_parts(self.clock, ':')?;
        if !(1..=12).contains(&hour)
            || !matches!(self.meridiem, "AM" | "PM")
            || self.year().is_none()
        {
            return None;
        }
        let hour24 = hour % 12 + if self.meridiem == "PM" { 12 } else { 0 };
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour24:02}:{minute:02}:{second:02}{offset}"
        ))
    }

    pub(super) const fn original_name(&self) -> &str {
        self.name
    }

    pub(super) fn domain(&self) -> Option<String> {
        let mut labels = String::new();
        let mut raw = self.name;
        while let Some((length, rest)) = label_length(raw) {
            if length == 0 {
                return if labels.is_empty() {
                    Some(".".into())
                } else {
                    Some(labels)
                };
            }
            let label = rest.get(..length)?;
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
            {
                return None;
            }
            labels.push_str(label);
            labels.push('.');
            raw = rest.get(length..)?;
        }
        None
    }
}

fn exact_parts(text: &str, separator: char) -> Option<[u16; 3]> {
    let mut parts = text.split(separator);
    let parsed = [
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    ];
    parts.next().is_none().then_some(parsed)
}

fn prefix_fields(prefix: &str) -> Option<([&str; 9], &str, &str)> {
    let mut parts = prefix.split_ascii_whitespace();
    let [
        date,
        clock,
        meridiem,
        thread,
        tag,
        pointer,
        transport,
        direction,
        remote,
        xid,
    ] = std::array::from_fn(|_| parts.next().unwrap_or_default());
    if tag != "PACKET"
        || !matches!(transport, "UDP" | "TCP")
        || !matches!(direction, "Rcv" | "Snd")
        || u16::from_str_radix(xid, 16).is_err()
        || remote.parse::<std::net::IpAddr>().is_err()
    {
        return None;
    }
    let first = parts.next()?;
    let (message, opcode) = if first == "R" {
        ("R", parts.next()?)
    } else {
        ("request", first)
    };
    if parts.next().is_some()
        || !(1..=8).contains(&opcode.len())
        || !opcode.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((
        [
            date, clock, meridiem, thread, pointer, transport, direction, remote, xid,
        ],
        message,
        opcode,
    ))
}

fn label_length(raw: &str) -> Option<(usize, &str)> {
    let (length, next) = raw.strip_prefix('(')?.split_once(')')?;
    if length.is_empty() || length.len() > 2 || !length.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let length = length.parse::<usize>().ok()?;
    (length <= 63).then_some((length, next))
}

fn dns_name_end(raw: &str) -> Option<(&str, Option<&str>)> {
    let mut rest = raw;
    loop {
        let (length, next) = label_length(rest)?;
        if length == 0 {
            let end = raw.len() - next.len();
            if end > 1024 || !next.starts_with(char::is_whitespace) && !next.is_empty() {
                return None;
            }
            let trailing = next.trim_ascii();
            return Some((&raw[..end], (!trailing.is_empty()).then_some(trailing)));
        }
        rest = next.get(length..)?;
    }
}
