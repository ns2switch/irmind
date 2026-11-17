use super::*;
#[test]
fn rfc3339_preserves_fraction_groups_offsets_and_leap_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let ordinary = DateTime::parse_from_rfc3339("2026-01-01T00:00:00.1234Z")?;
    assert_eq!(
        ordinary.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        "2026-01-01T00:00:00.123400Z"
    );
    assert_eq!(
        ordinary.timestamp_nanos_opt(),
        Some(1_767_225_600_123_400_000)
    );
    let leap = DateTime::parse_from_rfc3339("2016-12-31T23:59:60.123456789Z")?;
    assert_eq!(leap.timestamp(), 1_483_228_799);
    assert_eq!(leap.timestamp_subsec_nanos(), 1_123_456_789);
    assert_eq!(leap.timestamp_nanos_opt(), Some(1_483_228_800_123_456_789));
    assert_eq!(
        leap.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        "2016-12-31T23:59:60.123456789Z"
    );
    assert_eq!(
        DateTime::parse_from_rfc3339("2026-01-01T01:00:00+01:00")?.timestamp(),
        1_767_225_600
    );
    Ok(())
}
#[test]
fn civil_bounds_and_negative_fractions_match_reference() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(NaiveDate::MIN.to_string(), "-262143-01-01");
    assert_eq!(NaiveDate::MAX.to_string(), "+262142-12-31");
    assert_eq!(NaiveDateTime::default().to_string(), "1970-01-01 00:00:00");
    let t = DateTime::from_timestamp_micros(-1).ok_or("invalid fixture")?;
    assert_eq!(
        t.to_rfc3339_opts(SecondsFormat::Micros, true),
        "1969-12-31T23:59:59.999999Z"
    );
    assert!(DateTime::parse_from_rfc3339("2026-02-30T00:00:00Z").is_err());
    Ok(())
}

#[test]
fn frozen_synthetic_reference_keeps_offsets_formats_and_nanoseconds()
-> Result<(), Box<dyn std::error::Error>> {
    let reference: serde_json::Value =
        serde_json::from_str(include_str!("../tests/fixtures/calendar-reference.json"))?;
    for row in reference["rfc3339"]
        .as_array()
        .ok_or("missing date fixtures")?
    {
        let raw = row["input"].as_str().ok_or("missing input")?;
        let at = DateTime::parse_from_rfc3339(raw)?;
        assert_eq!(serde_json::json!(at.timestamp()), row["seconds"], "{raw}");
        assert_eq!(
            serde_json::json!(at.timestamp_subsec_nanos()),
            row["nanoseconds"],
            "{raw}"
        );
        assert_eq!(
            serde_json::json!(at.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
            row["rfc3339"],
            "{raw}"
        );
        assert_eq!(
            serde_json::json!(
                at.with_timezone(&Utc)
                    .to_rfc3339_opts(SecondsFormat::AutoSi, true)
            ),
            row["utc"],
            "{raw}"
        );
    }
    for row in reference["format"]
        .as_array()
        .ok_or("missing format fixtures")?
    {
        let at = NaiveDateTime::parse_from_str(
            row["input"].as_str().ok_or("missing input")?,
            "%Y-%m-%d %H:%M:%S%.f",
        )?;
        assert_eq!(
            serde_json::json!(
                at.format(row["pattern"].as_str().ok_or("missing pattern")?)
                    .to_string()
            ),
            row["output"]
        );
    }
    Ok(())
}

#[test]
fn malformed_offsets_and_nonrepresentable_durations_are_rejected() {
    for offset in [
        "+0:030",
        "+00::3",
        "+24:00",
        "-00:60",
        "+0\u{1b}[0",
        "+000:0",
        "+00:00:60",
        "../UTC",
        "EST",
    ] {
        assert!(offset.parse::<FixedOffset>().is_err(), "{offset:?}");
    }
    for text in [
        "2026-01-01T00:00:00+0:030",
        "2026-01-01T00:00:00+24:00",
        "2026-02-29T00:00:00Z",
        "2026-01-01T00:00:00.1234567890Z",
    ] {
        assert!(DateTime::parse_from_rfc3339(text).is_err(), "{text}");
    }
    assert!(Duration::from_std(std::time::Duration::from_secs(u64::MAX)).is_err());
}

#[test]
fn english_log_months_remain_case_insensitive() -> Result<(), Box<dyn std::error::Error>> {
    for name in ["Nov", "nov", "NOV"] {
        let raw = format!("2026 {name} 17 12:34:56");
        assert_eq!(
            NaiveDateTime::parse_from_str(&raw, "%Y %b %e %H:%M:%S")?.to_string(),
            "2026-11-17 12:34:56"
        );
    }
    Ok(())
}
