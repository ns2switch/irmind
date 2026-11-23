//! Literal text common to previews and report renderers.

pub(super) fn defang(ch: char) -> Option<&'static str> {
    match ch {
        '.' | '\u{3002}' | '\u{ff0e}' | '\u{ff61}' => Some("[.]"),
        ':' | '\u{ff1a}' => Some("[:]"),
        '@' | '\u{ff20}' => Some("[@]"),
        _ => None,
    }
}

pub(super) fn needs_visible_escape(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{00ad}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}'
        )
}

pub(super) fn render_report_literal(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for ch in value.chars() {
        if needs_visible_escape(ch) {
            append_markdown(&mut safe, &ch.escape_unicode().to_string());
        } else if let Some(defanged) = defang(ch) {
            append_markdown(&mut safe, defanged);
        } else {
            append_char(&mut safe, ch);
        }
    }
    safe
}

fn append_markdown(target: &mut String, value: &str) {
    for ch in value.chars() {
        append_char(target, ch);
    }
}

fn append_char(target: &mut String, ch: char) {
    if ch.is_ascii_punctuation() {
        target.push('\\');
    }
    target.push(ch);
}

#[cfg(test)]
mod tests {
    #[test]
    fn markup_and_autolinks_stay_literal() {
        let literal = super::render_report_literal("[click](https://example.invalid) <b>\u{202e}");
        assert!(literal.contains(r"\[click\]"));
        assert!(literal.contains(r"https\[\:\]\/\/example\[\.\]invalid"));
        assert!(!literal.contains("<b>"));
        assert!(!literal.contains('\u{202e}'));
    }
}
