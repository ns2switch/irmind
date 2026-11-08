use irmind_domain::{IndexedInstant, IndexedTime, TimePrecision};

/// Historical role-free views may display seconds. Typed time remains exact and
/// is the only value used for new ordering, partitioning and physical timestamps.
pub(super) fn valid_display_time(display: &str, actual: Option<IndexedTime>) -> bool {
    let Some(actual) = actual else {
        return display.is_empty();
    };
    if display.len() > 128 {
        return false;
    }
    let Ok(shown) = IndexedTime::from_rfc3339(display, actual.inferred()) else {
        return false;
    };
    if shown.precision().code() > actual.precision().code() {
        return false;
    }
    let micros = actual.instant().unix_micros();
    let (micros, nanos) = match shown.precision() {
        TimePrecision::Second => (micros.div_euclid(1_000_000) * 1_000_000, 0),
        TimePrecision::Millisecond => (micros.div_euclid(1000) * 1000, 0),
        TimePrecision::Microsecond => (micros, 0),
        TimePrecision::Nanosecond => (micros, actual.instant().submicro_nanos()),
        TimePrecision::Unknown => return false,
    };
    IndexedInstant::new(micros, nanos).is_ok_and(|instant| instant == shown.instant())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn coarse_compatibility_time_does_not_change_precise_source_time() {
        let actual = IndexedTime::from_rfc3339("2026-01-02T03:04:05.123456789Z", false).unwrap();
        for value in [
            "2026-01-02T03:04:05Z",
            "2026-01-02T03:04:05.123Z",
            "2026-01-02T03:04:05.123456Z",
            "2026-01-02T03:04:05.123456789Z",
        ] {
            assert!(valid_display_time(value, Some(actual)));
        }
        assert!(!valid_display_time("2026-01-02T03:04:06Z", Some(actual)));
        assert!(!valid_display_time(
            "2026-01-02T03:04:05.124Z",
            Some(actual)
        ));
        assert!(!valid_display_time("not-a-time", Some(actual)));
        assert!(!valid_display_time("2026-01-02T03:04:05Z", None));
        assert!(valid_display_time("", None));
    }
}
