//! Bounded unit normalization before Jiff's duration parser. Months and years
//! keep the SDK's fixed-duration meanings; they never consult a calendar.
use std::time::Duration;

pub fn parse_config_duration(input: &str) -> Option<Duration> {
    if input.len() > 4096 {
        return None;
    }
    let mut rest = input.trim();
    let mut total = 0u128;
    let mut terms = 0;
    while !rest.is_empty() {
        terms += 1;
        if terms > 128 {
            return None;
        }
        let n = rest.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        let integer = rest[..n].parse::<u64>().ok()?;
        rest = &rest[n..];
        let mut fraction = None;
        if let Some(tail) = rest.strip_prefix('.') {
            let n = tail.bytes().take_while(u8::is_ascii_digit).count();
            if n == 0 || n > 19 {
                return None;
            }
            fraction = Some((
                tail[..n].parse::<u64>().ok()?,
                10u64.checked_pow(u32::try_from(n).ok()?)?,
            ));
            rest = &tail[n..];
        }
        rest = rest.trim_start();
        let end = rest
            .char_indices()
            .take_while(|(_, c)| c.is_ascii_alphabetic() || *c == 'µ')
            .last()
            .map(|(i, c)| i + c.len_utf8())?;
        let scale = unit_scale(&rest[..end])?;
        rest = rest[end..].trim_start();
        // Preserve the old checked u64 unit multiplication and fractional
        // precision rejection, including integral seconds for hours or longer.
        let whole = if scale >= 1_000_000_000 {
            u128::from(integer.checked_mul(scale / 1_000_000_000)?) * 1_000_000_000
        } else {
            u128::from(integer.checked_mul(scale)?)
        };
        let extra = if let Some((n, d)) = fraction {
            if scale == 1 {
                return None;
            }
            let multiplier = if scale >= 3_600_000_000_000 {
                scale / 1_000_000_000
            } else {
                scale
            };
            let v = n.checked_mul(multiplier)?;
            if v % d != 0 {
                return None;
            }
            u128::from(v / d)
                * if scale >= 3_600_000_000_000 {
                    1_000_000_000
                } else {
                    1
                }
        } else {
            0
        };
        total = total.checked_add(whole)?.checked_add(extra)?;
        if total / 1_000_000_000 > u128::from(u64::MAX) {
            return None;
        }
    }
    if terms == 0 {
        return None;
    }
    let normalized = format!("{}.{:09}s", total / 1_000_000_000, total % 1_000_000_000);
    jiff::fmt::friendly::SpanParser::new()
        .parse_unsigned_duration(normalized)
        .ok()
}

fn unit_scale(unit: &str) -> Option<u64> {
    Some(match unit {
        "nanos" | "nsec" | "ns" => 1,
        "usec" | "us" | "µs" => 1_000,
        "millis" | "msec" | "ms" => 1_000_000,
        "seconds" | "second" | "secs" | "sec" | "s" => 1_000_000_000,
        "minutes" | "minute" | "min" | "mins" | "m" => 60_000_000_000,
        "hours" | "hour" | "hr" | "hrs" | "h" => 3_600_000_000_000,
        "days" | "day" | "d" => 86_400_000_000_000,
        "weeks" | "week" | "wk" | "wks" | "w" => 604_800_000_000_000,
        "months" | "month" | "M" => 2_630_016_000_000_000,
        "years" | "year" | "yr" | "yrs" | "y" => 31_557_600_000_000_000,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_unit_meanings_and_aliases_are_preserved() {
        for text in ["60s", "60 s", "60 seconds", "1m", "1 minute"] {
            assert_eq!(parse_config_duration(text), Some(Duration::from_mins(1)));
        }
        for (text, seconds) in [
            ("1month", 2_630_016),
            ("1M", 2_630_016),
            ("1.5 years", 47_336_400),
            ("1h30m", 5400),
        ] {
            assert_eq!(
                parse_config_duration(text),
                Some(Duration::from_secs(seconds))
            );
        }
        assert_eq!(
            parse_config_duration("1millis 2usec 3nanos"),
            Some(Duration::from_nanos(1_002_003))
        );
        assert_eq!(
            parse_config_duration("0.000000001s"),
            Some(Duration::from_nanos(1))
        );
    }
    #[test]
    fn duration_precision_sign_size_and_overflow_are_not_silently_clipped() {
        for bad in [
            "",
            "-1s",
            "0.5ns",
            "0.0000000001s",
            "18446744073709551616s",
            "18446744073709551615h",
            "1.000000000000000000001s",
            "1e9s",
            "1fortnight",
        ] {
            assert!(parse_config_duration(bad).is_none(), "{bad}");
        }
        assert!(parse_config_duration(&"1s ".repeat(2000)).is_none());
        assert_eq!(parse_config_duration("0s"), Some(Duration::ZERO));
    }
}
