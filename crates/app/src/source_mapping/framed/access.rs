//! Original whitespace fields with provider-delimited text left uninterpreted.

/// Split one bounded access-log row. The bracketed column is used only for
/// providers which put a timezone inside square brackets in that column.
pub fn access_log_fields(mut row: &str, bracketed: Option<usize>) -> Option<Vec<&str>> {
    if row.len() > 65_536 {
        return None;
    }
    let mut fields = Vec::new();
    while !row.trim_ascii_start().is_empty() {
        row = row.trim_ascii_start();
        if fields.len() == 64 {
            return None;
        }
        if bracketed == Some(fields.len()) {
            let (value, rest) = row.strip_prefix('[')?.split_once(']')?;
            if !rest.is_empty() && !rest.as_bytes()[0].is_ascii_whitespace() {
                return None;
            }
            row = rest;
            fields.push(value);
        } else if let Some(rest) = row.strip_prefix('"') {
            let end = closing_quote(rest)?;
            let suffix = rest.get(end + 1..)?;
            if !suffix.is_empty() && !suffix.as_bytes()[0].is_ascii_whitespace() {
                return None;
            }
            fields.push(&rest[..end]);
            row = suffix;
        } else {
            let end = row
                .find(|ch: char| ch.is_ascii_whitespace())
                .unwrap_or(row.len());
            let value = &row[..end];
            if value.contains('"') {
                return None;
            }
            fields.push(value);
            row = &row[end..];
        }
    }
    Some(fields)
}

fn closing_quote(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, byte) in s.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'"' => return Some(index),
            b'\\' => escaped = true,
            _ => {}
        }
    }
    None
}

/// Preserve the request target and spacing inside it without URL decoding.
pub fn request_line(text: &str) -> Option<(&str, &str, Option<&str>)> {
    let (method, remainder) = text.split_once(' ')?;
    if method.is_empty()
        || method == "-"
        || method.len() > 32
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^`_|~".contains(&byte))
        || remainder.is_empty()
    {
        return None;
    }
    if let Some((target, version)) = remainder.rsplit_once(' ') {
        let version = version.strip_prefix("HTTP/")?;
        if target.is_empty()
            || version.is_empty()
            || version.len() > 8
            || !version
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return None;
        }
        Some((method, target, Some(version)))
    } else {
        Some((method, remainder, None))
    }
}

/// Get the path and the original query substring. The full target remains
/// available in the record, including delimiters, fragments and escape bytes.
pub fn request_path(target: &str) -> (&str, Option<&str>) {
    let origin_form = target
        .split_once("://")
        .filter(|(scheme, _)| {
            !scheme.is_empty() && scheme.bytes().all(|byte| byte.is_ascii_alphabetic())
        })
        .map_or(target, |(_, remainder)| {
            remainder
                .find(['/', '?'])
                .map_or("", |position| &remainder[position..])
        });
    match origin_form.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (origin_form, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extended_fields_keep_escapes_and_require_exact_delimiters() {
        assert_eq!(
            access_log_fields(r#"a [one two] "method \"abc" next"#, Some(1)),
            Some(vec!["a", "one two", r#"method \"abc"#, "next"])
        );
        assert!(access_log_fields(r#"a "no"separator 200"#, None).is_none());
        assert_eq!(
            request_path("https://example.test/a%2Fb?q=%2522"),
            ("/a%2Fb", Some("q=%2522"))
        );
        assert_eq!(
            request_path("/next?raw=http://site.example/"),
            ("/next", Some("raw=http://site.example/"))
        );
    }
}
