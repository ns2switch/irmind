use super::*;

#[test]
fn exact_fractional_time_never_uses_float_or_trailing_zero_inference() {
    for (input, micros, residual, precision, display) in [
        ("0", 0, 0, TimePrecision::Second, "1970-01-01T00:00:00Z"),
        (
            "0.000",
            0,
            0,
            TimePrecision::Millisecond,
            "1970-01-01T00:00:00.000Z",
        ),
        (
            "0.000000",
            0,
            0,
            TimePrecision::Microsecond,
            "1970-01-01T00:00:00.000000Z",
        ),
        (
            "0.0000000",
            0,
            0,
            TimePrecision::Nanosecond,
            "1970-01-01T00:00:00.000000000Z",
        ),
        (
            "-0.0000001",
            -1,
            900,
            TimePrecision::Nanosecond,
            "1969-12-31T23:59:59.999999900Z",
        ),
        (
            "-1.000000001",
            -1_000_001,
            999,
            TimePrecision::Nanosecond,
            "1969-12-31T23:59:58.999999999Z",
        ),
        (
            "1793750400.123456789",
            1_793_750_400_123_456,
            789,
            TimePrecision::Nanosecond,
            "2026-11-04T00:00:00.123456789Z",
        ),
    ] {
        let time = IndexedTime::from_epoch_decimal(input, false).unwrap();
        assert_eq!(time.instant().unix_micros(), micros, "{input}");
        assert_eq!(time.instant().submicro_nanos(), residual);
        assert_eq!(time.precision(), precision);
        assert_eq!(time.to_rfc3339(), display);
        assert_eq!(IndexedTime::from_rfc3339(display, false), Ok(time));
    }
}

#[test]
fn utc_offsets_cross_midnight_and_calendar_range_is_checked() {
    let time = IndexedTime::from_rfc3339("2026-01-01T00:30:00.1234567+01:00", true).unwrap();
    assert_eq!(time.to_rfc3339(), "2025-12-31T23:30:00.123456700Z");
    assert_eq!(time.instant().utc_date(), "2025-12-31");
    assert!(time.inferred());
    for input in [
        "0001-01-01T00:00:00Z",
        "9999-12-31T23:59:59.999999999Z",
        "2000-02-29T12:00:00Z",
    ] {
        let time = IndexedTime::from_rfc3339(input, false).unwrap();
        assert_eq!(time.to_rfc3339(), input);
    }
    for input in [
        "0001-01-01T00:00:00+00:01",
        "9999-12-31T23:59:59-00:01",
        "0000-01-01T00:00:00Z",
        "2026-02-29T00:00:00Z",
        "2026-01-01T00:00:60Z",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00:00-00:00",
        "2026-01-01T00:00:00+24:00",
        "2026-01-01T00:00:00+01:60",
        "2026-01-01T00:00:00.1234567890Z",
        "2026-01-01T00:00:00.Z",
        "2026-01-01T00:00:00.xZ",
        "éééééééééééééééééééé",
    ] {
        assert!(IndexedTime::from_rfc3339(input, false).is_err(), "{input}");
    }
}

#[test]
fn checked_time_bounds_and_precision_reject_overflow_and_lost_digits() {
    for input in [
        "",
        "NaN",
        "inf",
        "1e9",
        "+1",
        "1.",
        ".1",
        "1.1234567890",
        "--1",
        "99999999999999999999999999999999999999",
        "-62135596800.000000001",
        "253402300800",
    ] {
        assert!(
            IndexedTime::from_epoch_decimal(input, false).is_err(),
            "{input}"
        );
    }
    assert!(IndexedInstant::new(IndexedInstant::MIN_MICROS - 1, 0).is_err());
    assert!(IndexedInstant::new(IndexedInstant::MAX_MICROS + 1, 0).is_err());
    assert!(IndexedInstant::new(0, 1000).is_err());
    let fine = IndexedInstant::new(1, 1).unwrap();
    assert!(IndexedTime::new(fine, TimePrecision::Microsecond, false).is_err());
    assert!(IndexedTime::new(fine, TimePrecision::Second, false).is_err());
    assert!(IndexedTime::new(fine, TimePrecision::Unknown, false).is_ok());
    for code in 0..=4 {
        assert_eq!(TimePrecision::from_code(code).unwrap().code(), code);
    }
    assert!(TimePrecision::from_code(5).is_err());
}

#[test]
fn civil_conversion_round_trips_a_complete_gregorian_cycle() {
    for year in 1600..2000 {
        for month in 1..=12 {
            let text = format!("{year:04}-{month:02}-01T00:00:00Z");
            let time = IndexedTime::from_rfc3339(&text, false).unwrap();
            assert_eq!(time.to_rfc3339(), text);
        }
    }
    let before = IndexedTime::from_rfc3339("1969-12-31T23:59:59.999999900Z", false).unwrap();
    let after = IndexedTime::from_rfc3339("1970-01-01T00:00:00Z", false).unwrap();
    assert!(before.instant() < after.instant());
}
