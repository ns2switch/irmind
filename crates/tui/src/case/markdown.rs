use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
};
use unicode_width::UnicodeWidthChar;

fn segment(style: Style, text: &str) -> Span<'static> {
    Span::styled(text.to_owned(), style)
}

fn inline_segments(text: &str, base: Style, markdown: bool) -> Vec<Span<'static>> {
    if !markdown {
        return vec![segment(base, text)];
    }
    let mut remaining = text;
    let mut spans = Vec::new();
    while !remaining.is_empty() {
        if let Some(rest) = remaining.strip_prefix("**")
            && let Some(end) = rest.find("**")
        {
            spans.push(segment(base.add_modifier(Modifier::BOLD), &rest[..end]));
            remaining = &rest[end + 2..];
            continue;
        }
        if let Some(rest) = remaining.strip_prefix('`')
            && let Some(end) = rest.find('`')
        {
            spans.push(segment(
                base.add_modifier(Modifier::UNDERLINED),
                &rest[..end],
            ));
            remaining = &rest[end + 1..];
            continue;
        }
        let next = [remaining.find("**"), remaining.find('`')]
            .into_iter()
            .flatten()
            .filter(|position| *position > 0)
            .min()
            .unwrap_or(remaining.len());
        let end = if next == 0 { 1 } else { next };
        spans.push(segment(base, &remaining[..end]));
        remaining = &remaining[end..];
    }
    if spans.is_empty() {
        spans.push(segment(base, ""));
    }
    spans
}

fn flush_span(spans: &mut Vec<Span<'static>>, buffer: &mut String, style: Style) {
    if !buffer.is_empty() {
        spans.push(Span::styled(std::mem::take(buffer), style));
    }
}

fn wrap_segments(segments: Vec<Span<'static>>, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut spans = Vec::new();
    let mut buffer = String::new();
    let mut current_style = Style::default();
    let mut used = 0usize;
    for part in segments {
        let style = part.style;
        if style != current_style {
            flush_span(&mut spans, &mut buffer, current_style);
            current_style = style;
        }
        for ch in part.content.chars() {
            let cells = UnicodeWidthChar::width(ch).unwrap_or(0);
            if used + cells > width && used > 0 {
                flush_span(&mut spans, &mut buffer, current_style);
                lines.push(Line::from(std::mem::take(&mut spans)));
                used = 0;
            }
            buffer.push(ch);
            used += cells;
        }
    }
    flush_span(&mut spans, &mut buffer, current_style);
    lines.push(Line::from(spans));
    lines
}

pub(super) fn render(text: &str, width: usize, markdown: bool) -> Vec<Line<'static>> {
    let mut output = Vec::new();
    let mut code_block = false;
    for raw in text.split('\n') {
        if markdown && raw.trim_start().starts_with("```") {
            code_block = !code_block;
            let label = if code_block { "┌ code" } else { "└" };
            output.extend(wrap_segments(
                vec![segment(
                    Style::default().add_modifier(Modifier::BOLD),
                    label,
                )],
                width,
            ));
            continue;
        }
        let (prefix, body, style) = if markdown && !code_block {
            if let Some(body) = raw.strip_prefix("### ") {
                ("", body, Style::default().add_modifier(Modifier::BOLD))
            } else if let Some(body) = raw.strip_prefix("## ") {
                ("", body, Style::default().add_modifier(Modifier::BOLD))
            } else if let Some(body) = raw.strip_prefix("# ") {
                ("", body, Style::default().add_modifier(Modifier::BOLD))
            } else if let Some(body) = raw.strip_prefix("- ").or_else(|| raw.strip_prefix("* ")) {
                ("• ", body, Style::default())
            } else {
                ("", raw, Style::default())
            }
        } else {
            ("", raw, Style::default())
        };
        let mut spans = Vec::new();
        if !prefix.is_empty() {
            spans.push(segment(style, prefix));
        }
        spans.extend(inline_segments(body, style, markdown && !code_block));
        output.extend(wrap_segments(spans, width));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_preserves_visible_links_and_styles_basic_tokens() {
        let lines = render(
            "# Title\n- **bold** and `code` [link](https://example.test)",
            80,
            true,
        );
        let text = lines
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Title"));
        assert!(text.contains("• bold and code [link](https://example.test)"));
        assert!(
            lines[0].spans[0]
                .style
                .add_modifier
                .contains(Modifier::BOLD)
        );
    }

    #[test]
    fn wrapping_uses_terminal_cell_width() {
        let lines = render("ab界cd", 4, false);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].to_string(), "ab界");
        assert_eq!(lines[1].to_string(), "cd");
    }
}
