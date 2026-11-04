use super::{IndexedInstant, IndexedTime, TimePrecision};

fn civil(instant: IndexedInstant) -> (i64, i64, i64) {
    // Inverse proleptic Gregorian calculation for the checked years 0001–9999.
    let days = instant.micros.div_euclid(86_400_000_000) + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = month_from_march + if month_from_march < 10 { 3 } else { -9 };
    (year + i64::from(month <= 2), month, day)
}

pub(super) fn date(instant: IndexedInstant) -> String {
    let (year, month, day) = civil(instant);
    format!("{year:04}-{month:02}-{day:02}")
}

pub(super) fn format(time: IndexedTime) -> String {
    let instant = time.instant;
    let seconds = instant.micros.div_euclid(1_000_000).rem_euclid(86_400);
    let hour = seconds / 3600;
    let minute = seconds / 60 % 60;
    let second = seconds % 60;
    let nanos = instant.micros.rem_euclid(1_000_000) * 1000 + i64::from(instant.submicro_nanos);
    let fraction = match time.precision {
        TimePrecision::Second => String::new(),
        TimePrecision::Millisecond => format!(".{:03}", nanos / 1_000_000),
        TimePrecision::Microsecond => format!(".{:06}", nanos / 1000),
        TimePrecision::Nanosecond | TimePrecision::Unknown => format!(".{nanos:09}"),
    };
    format!(
        "{}T{hour:02}:{minute:02}:{second:02}{fraction}Z",
        date(instant)
    )
}
