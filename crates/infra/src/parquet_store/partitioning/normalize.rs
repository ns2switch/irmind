use unicode_normalization::{UNICODE_VERSION, UnicodeNormalization};

pub(super) fn policy_id() -> String {
    let (major, minor, patch) = UNICODE_VERSION;
    format!("nfkc-unicode-{major}.{minor}.{patch}-ascii-v1")
}

/// Bounded bucketing copy. The actual value remains unchanged in every row.
pub(in crate::parquet_store) fn normalize(raw: &str) -> Option<String> {
    if raw.is_empty() || raw.len() > 512 || raw.chars().any(forbidden) {
        return None;
    }
    let mut out = String::new();
    for ch in raw.nfkc() {
        if out.len() >= 128
            || !ch.is_ascii()
            || !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '@' | '-'))
        {
            return None;
        }
        out.push(ch.to_ascii_lowercase());
    }
    out.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        .then_some(out)
}

fn forbidden(ch: char) -> bool {
    ch.is_control()
        || ch.is_whitespace()
        || matches!(ch,
        '/' | '\\' | '?' | '#' | '%' | '\0' | '\u{ad}' | '\u{61c}' | '\u{180e}'
        | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{206f}' | '\u{feff}')
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_upgrade_requires_a_new_reviewed_policy() {
        assert_eq!(UNICODE_VERSION, (18, 0, 0));
        assert_eq!(policy_id(), irmind_domain::ARTIFACT_V2_PARTITION_POLICY);
    }
    #[test]
    fn normalization_is_bounded_and_never_produces_a_path() {
        assert_eq!(normalize("ＨＯＳＴ-Ａ"), Some("host-a".into()));
        assert_eq!(normalize("HOST-A"), normalize("host-a"));
        for value in [
            "../host",
            "a/b",
            "a\\b",
            "https://host",
            "a\u{202e}b",
            "a\u{200b}b",
            "a\n",
            "..",
            "é",
        ] {
            assert_eq!(normalize(value), None, "{value:?}");
        }
        assert_eq!(normalize(&"a".repeat(129)), None);
    }
}
