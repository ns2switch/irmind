use crate::{Error, NaiveDate, NaiveDateTime, NaiveTime, Timelike, invalid};
use time::format_description::OwnedFormatItem as Item;
#[derive(Clone, Copy, Debug)]
pub enum SecondsFormat {
    Secs,
    Millis,
    Micros,
    Nanos,
    AutoSi,
}
pub struct Formatted(pub(crate) Result<String, Error>);
impl std::fmt::Display for Formatted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Ok(v) => f.write_str(v),
            Err(_) => Err(std::fmt::Error),
        }
    }
}
enum Piece {
    Native(Item),
    Fraction { dot: bool, digits: Option<u8> },
    Zone,
    Offset { colon: bool },
}
fn pieces(format: &str) -> Result<Vec<Piece>, Error> {
    if format.len() > 4096 {
        return Err(invalid());
    }
    let mut result = Vec::new();
    let mut start = 0;
    let bytes = format.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'%') {
            i += 2;
            continue;
        }
        let tail = &format[i..];
        let special = if tail.starts_with("%.f") {
            Some((
                3,
                Piece::Fraction {
                    dot: true,
                    digits: None,
                },
            ))
        } else if tail.starts_with("%f") {
            Some((
                2,
                Piece::Fraction {
                    dot: false,
                    digits: None,
                },
            ))
        } else if tail.starts_with("%Z") {
            Some((2, Piece::Zone))
        } else if tail.starts_with("%:z") {
            Some((3, Piece::Offset { colon: true }))
        } else if tail.starts_with("%z") {
            Some((2, Piece::Offset { colon: false }))
        } else {
            let mut found = None;
            for n in [3u8, 6, 9] {
                if tail.starts_with(&format!("%.{n}f")) {
                    found = Some((
                        4,
                        Piece::Fraction {
                            dot: true,
                            digits: Some(n),
                        },
                    ));
                    break;
                }
                if tail.starts_with(&format!("%{n}f")) {
                    found = Some((
                        3,
                        Piece::Fraction {
                            dot: false,
                            digits: Some(n),
                        },
                    ));
                    break;
                }
            }
            found
        };
        if let Some((len, item)) = special {
            if start < i {
                result.push(native(&format[start..i])?);
            }
            result.push(item);
            i += len;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < format.len() {
        result.push(native(&format[start..])?);
    }
    Ok(result)
}
fn native(raw: &str) -> Result<Piece, Error> {
    time::format_description::parse_strftime_owned(raw)
        .map(Piece::Native)
        .map_err(|e| Error(e.to_string()))
}
pub fn validate_format(format: &str) -> Result<(), Error> {
    pieces(format).map(|_| ())
}
fn parse(
    raw: &str,
    fmt: &str,
) -> Result<(time::parsing::Parsed, bool, Option<crate::FixedOffset>), Error> {
    if raw.len() > 1_048_576 {
        return Err(invalid());
    }
    let mut input = raw.as_bytes();
    let mut parsed = time::parsing::Parsed::new();
    let mut offset = None;
    for piece in pieces(fmt)? {
        match piece {
            Piece::Native(item) => {
                input = parsed
                    .parse_item(input, &item)
                    .map_err(|e| Error(e.to_string()))?;
            }
            Piece::Fraction { dot, digits } => {
                if dot {
                    if input.first() != Some(&b'.') {
                        if digits.is_none() {
                            continue;
                        }
                        return Err(invalid());
                    }
                    input = &input[1..];
                }
                let count = input.iter().take_while(|b| b.is_ascii_digit()).count();
                let wanted = digits.map_or(count, usize::from);
                if wanted == 0 || wanted > 9 || count < wanted || (dot && count > 9) {
                    return Err(invalid());
                }
                let number = std::str::from_utf8(&input[..wanted])
                    .map_err(|_| invalid())?
                    .parse::<u32>()
                    .map_err(|_| invalid())?;
                let nanos = if dot || digits.is_some() {
                    number * 10u32.pow(9 - u32::try_from(wanted).map_err(|_| invalid())?)
                } else {
                    number
                };
                parsed.set_subsecond(nanos).ok_or_else(invalid)?;
                input = &input[wanted..];
            }
            Piece::Offset { colon } => {
                if input.first() == Some(&b'Z') {
                    offset = crate::FixedOffset::east_opt(0);
                    input = &input[1..];
                    continue;
                }
                let size = if colon || input.get(3) == Some(&b':') {
                    6
                } else {
                    5
                };
                let zone = std::str::from_utf8(input.get(..size).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
                offset = Some(zone.parse()?);
                input = &input[size..];
            }
            Piece::Zone => {
                let count = input.iter().take_while(|b| b.is_ascii_alphabetic()).count();
                if !matches!(input.get(..count), Some(b"UTC" | b"GMT" | b"Z")) {
                    return Err(invalid());
                }
                offset = crate::FixedOffset::east_opt(0);
                input = &input[count..];
            }
        }
    }
    if !input.is_empty() {
        return Err(invalid());
    }
    let leap = parsed.second() == Some(60);
    if leap {
        parsed.set_second(59).ok_or_else(invalid)?;
    }
    Ok((parsed, leap, offset))
}
pub(crate) fn parse_naive(raw: &str, fmt: &str) -> Result<NaiveDateTime, Error> {
    let (parsed, leap, _) = parse(raw, fmt)?;
    let value = time::PrimitiveDateTime::try_from(parsed).map_err(|e| Error(e.to_string()))?;
    let mut result = NaiveDateTime::from_native(value).ok_or_else(invalid)?;
    result.time.leap = leap;
    Ok(result)
}
pub(crate) fn parse_time(raw: &str, fmt: &str) -> Result<NaiveTime, Error> {
    let (parsed, leap, _) = parse(raw, fmt)?;
    Ok(NaiveTime {
        value: time::Time::try_from(parsed).map_err(|e| Error(e.to_string()))?,
        leap,
    })
}
pub(crate) fn parse_date(raw: &str, fmt: &str) -> Result<NaiveDate, Error> {
    let (parsed, _, _) = parse(raw, fmt)?;
    let date = NaiveDate(time::Date::try_from(parsed).map_err(|e| Error(e.to_string()))?);
    if date < NaiveDate::MIN || date > NaiveDate::MAX {
        return Err(invalid());
    }
    Ok(date)
}
pub(crate) fn parse_offset(
    raw: &str,
    fmt: &str,
) -> Result<(NaiveDateTime, crate::FixedOffset), Error> {
    let (parsed, leap, zone) = parse(raw, fmt)?;
    let value = time::PrimitiveDateTime::try_from(parsed).map_err(|e| Error(e.to_string()))?;
    let offset = match zone {
        Some(v) => v,
        None => crate::FixedOffset::east_opt(
            time::UtcOffset::try_from(parsed)
                .map_err(|e| Error(e.to_string()))?
                .whole_seconds(),
        )
        .ok_or_else(invalid)?,
    };
    let mut result = NaiveDateTime::from_native(value).ok_or_else(invalid)?;
    result.time.leap = leap;
    Ok((result, offset))
}
fn fraction(nanos: u32, digits: Option<u8>, dot: bool) -> String {
    let nanos = nanos % 1_000_000_000;
    let precision = digits.unwrap_or(if !dot {
        9
    } else if nanos == 0 {
        0
    } else if nanos.is_multiple_of(1_000_000) {
        3
    } else if nanos.is_multiple_of(1000) {
        6
    } else {
        9
    });
    if precision == 0 {
        return String::new();
    }
    let v = nanos / 10u32.pow(9 - u32::from(precision));
    format!(
        "{}{:0width$}",
        if dot { "." } else { "" },
        v,
        width = usize::from(precision)
    )
}
fn render(
    fmt: &str,
    nanos: u32,
    zone: Option<&str>,
    offset: Option<crate::FixedOffset>,
    mut native_format: impl FnMut(&Item) -> Result<String, Error>,
) -> Formatted {
    Formatted((|| {
        let mut result = String::new();
        for item in pieces(fmt)? {
            match item {
                Piece::Native(item) => result.push_str(&native_format(&item)?),
                Piece::Fraction { dot, digits } => result.push_str(&fraction(nanos, digits, dot)),
                Piece::Zone => result.push_str(zone.ok_or_else(invalid)?),
                Piece::Offset { colon } => {
                    let o = offset.ok_or_else(invalid)?.to_string();
                    result.push_str(&if colon { o } else { o.replace(':', "") });
                }
            }
        }
        Ok(result)
    })())
}
pub(crate) fn date(value: NaiveDate, fmt: &str) -> Formatted {
    render(fmt, 0, None, None, |f| {
        value.0.format(f).map_err(|e| Error(e.to_string()))
    })
}
pub(crate) fn clock(value: NaiveTime, fmt: &str) -> Formatted {
    render(fmt, value.nanosecond(), None, None, |f| {
        value.value.format(f).map_err(|e| Error(e.to_string()))
    })
}
pub(crate) fn naive(value: NaiveDateTime, fmt: &str) -> Formatted {
    render(fmt, value.nanosecond(), None, None, |f| {
        value.native().format(f).map_err(|e| Error(e.to_string()))
    })
}
pub(crate) fn zoned(
    value: NaiveDateTime,
    offset: crate::FixedOffset,
    name: &str,
    fmt: &str,
) -> Formatted {
    render(fmt, value.nanosecond(), Some(name), Some(offset), |f| {
        value
            .native()
            .assume_offset(offset.0)
            .format(f)
            .map_err(|e| Error(e.to_string()))
    })
}
pub(crate) fn date_text(year: i32, month: u32, day: u32) -> String {
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else {
        format!("{year:+05}")
    };
    format!("{year}-{month:02}-{day:02}")
}
pub(crate) fn clock_text(value: NaiveTime, precision: SecondsFormat) -> String {
    let digits = match precision {
        SecondsFormat::Secs => Some(0),
        SecondsFormat::Millis => Some(3),
        SecondsFormat::Micros => Some(6),
        SecondsFormat::Nanos => Some(9),
        SecondsFormat::AutoSi => None,
    };
    format!(
        "{:02}:{:02}:{:02}{}",
        value.hour(),
        value.minute(),
        value.second() + u32::from(value.leap),
        fraction(value.nanosecond(), digits, true)
    )
}

pub fn has_timezone(format: &str) -> bool {
    let b = format.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            i += 1;
            if b.get(i) == Some(&b'%') {
                i += 1;
                continue;
            }
            if b.get(i) == Some(&b':') || b.get(i) == Some(&b'#') {
                i += 1;
            }
            if matches!(b.get(i), Some(b'z' | b'Z' | b'+')) {
                return true;
            }
        }
        i += 1;
    }
    false
}
