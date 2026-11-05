#![allow(clippy::unwrap_used)]
use super::*;
use parquet::data_type::ByteArray;

#[test]
fn bounds_are_conservative_for_submicroseconds_unknowns_and_equal_times() {
    let stats = Statistics::int64(Some(-1), Some(42), None, Some(0), false);
    let newest = statistic_bound(&stats, 2, true);
    let oldest = statistic_bound(&stats, 2, false);
    assert_eq!(
        newest,
        TimeBound::Known(Some(IndexedInstant::new(42, 999).unwrap()))
    );
    assert_eq!(
        oldest,
        TimeBound::Known(Some(IndexedInstant::new(-1, 0).unwrap()))
    );
    assert!(!newest.cannot_beat(Some(IndexedInstant::new(42, 900).unwrap()), true));
    assert!(newest.cannot_beat(Some(IndexedInstant::new(43, 0).unwrap()), true));
    assert!(oldest.cannot_beat(Some(IndexedInstant::new(-2, 0).unwrap()), false));
    assert!(!oldest.cannot_beat(Some(IndexedInstant::new(-1, 0).unwrap()), false));
    assert!(TimeBound::Known(None).cannot_beat(Some(IndexedInstant::new(0, 0).unwrap()), true));
    assert!(!TimeBound::Unbounded.cannot_beat(Some(IndexedInstant::new(0, 0).unwrap()), true));
}

#[test]
fn legacy_mixed_unknown_time_and_inexact_statistics_never_hide_events() {
    let mixed = Statistics::byte_array(
        Some(ByteArray::from("")),
        Some(ByteArray::from("2026-11-01T00:00:00Z")),
        None,
        Some(0),
        false,
    );
    assert_eq!(statistic_bound(&mixed, 2, false), TimeBound::Unbounded);
    assert!(matches!(
        statistic_bound(&mixed, 2, true),
        TimeBound::Known(Some(_))
    ));
    let unknown = Statistics::byte_array(
        Some(ByteArray::from("")),
        Some(ByteArray::from("")),
        None,
        Some(0),
        false,
    );
    assert_eq!(statistic_bound(&unknown, 2, false), TimeBound::Known(None));
    let inexact = Statistics::Int64(
        parquet::file::statistics::ValueStatistics::new(
            Some(0_i64),
            Some(42_i64),
            None,
            Some(0),
            false,
        )
        .with_max_is_exact(false),
    );
    assert_eq!(statistic_bound(&inexact, 2, true), TimeBound::Unbounded);
    let missing = Statistics::int64(None, None, None, None, false);
    assert_eq!(statistic_bound(&missing, 2, true), TimeBound::Unbounded);
    let nulls = Statistics::int64(None, None, None, Some(2), false);
    assert_eq!(statistic_bound(&nulls, 2, true), TimeBound::Known(None));
}
