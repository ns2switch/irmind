use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub(crate) fn width(lines: &[String], available: u16) -> u16 {
    let desired = lines
        .iter()
        .map(|line| UnicodeWidthStr::width(line.as_str()).saturating_add(3))
        .max()
        .unwrap_or(2);
    u16::try_from(desired)
        .unwrap_or(u16::MAX)
        .min(available.max(1))
}

pub(crate) fn clip(line: &str, max_width: usize) -> String {
    if UnicodeWidthStr::width(line) <= max_width {
        return line.to_owned();
    }
    if max_width == 0 {
        return String::new();
    }
    let budget = max_width - 1;
    let mut used = 0;
    let mut fitting_end = 0;
    let mut word_end = None;
    for (index, ch) in line.char_indices() {
        let next = used + UnicodeWidthChar::width(ch).unwrap_or(0);
        if next > budget {
            break;
        }
        used = next;
        fitting_end = index + ch.len_utf8();
        if ch.is_whitespace() {
            word_end = Some(index);
        }
    }
    let end = word_end.filter(|end| *end > 0).unwrap_or(fitting_end);
    format!("{}…", line[..end].trim_end())
}

#[cfg(test)]
mod tests {
    use super::{clip, width};

    #[test]
    fn menu_width_fits_description_and_clips_on_word_boundary() {
        let rows = vec!["/model — Choose and test an AI model".to_owned()];
        assert_eq!(usize::from(width(&rows, 80)), rows[0].chars().count() + 3);
        assert_eq!(clip(&rows[0], 26), "/model — Choose and test…");
        assert_eq!(clip("LongUnbreakableWord", 5), "Long…");
    }
}
