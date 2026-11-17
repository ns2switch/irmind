use irmind_app::IndexedTime;
use std::time::{SystemTime, UNIX_EPOCH};

fn timestamp(seconds: u64) -> Option<String> {
    IndexedTime::from_epoch_decimal(&seconds.to_string(), false)
        .ok()
        .map(IndexedTime::to_rfc3339)
}

pub(crate) fn created(seconds: u64) -> String {
    timestamp(seconds).map_or_else(
        || format!("UTC epoch {seconds}"),
        |text| format!("{} {} UTC", &text[..10], &text[11..19]),
    )
}

pub(crate) fn recent(seconds: u64) -> String {
    timestamp(seconds).map_or_else(
        || "unknown".into(),
        |text| {
            let months = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            let month = usize::from(text.as_bytes()[5] - b'0') * 10
                + usize::from(text.as_bytes()[6] - b'0');
            format!(
                "{} {} {} {} UTC",
                &text[8..10],
                months[month - 1],
                &text[..4],
                &text[11..16]
            )
        },
    )
}

pub(crate) fn clock() -> String {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "UTC unavailable".into();
    };
    let seconds = duration.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02} UTC",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_labels_preserve_the_current_display_bytes_and_boundaries() {
        assert_eq!(created(100), "1970-01-01 00:01:40 UTC");
        assert_eq!(recent(100), "01 Jan 1970 00:01 UTC");
        assert_eq!(created(253_402_300_799), "9999-12-31 23:59:59 UTC");
        assert_eq!(recent(253_402_300_800), "unknown");
        assert_eq!(created(u64::MAX), format!("UTC epoch {}", u64::MAX));
    }
}
