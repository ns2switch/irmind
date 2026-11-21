use crate::theme::Theme;
use irmind_app::{StatusBarTemplate, StatusColor, StatusSegment};
use ratatui::{
    style::Style,
    text::{Line, Span},
};
use std::collections::BTreeMap;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

pub(crate) mod editor;
#[cfg(test)]
mod tests;

#[derive(Clone, Default)]
pub(crate) struct StatusData {
    values: BTreeMap<StatusSegment, String>,
    pub warnings: Vec<String>,
}
impl StatusData {
    pub(crate) fn insert(&mut self, segment: StatusSegment, value: impl Into<String>) {
        let value = value.into();
        if !value.is_empty() {
            self.values.insert(segment, flat(&value));
        }
    }
    pub(crate) fn preview() -> Self {
        use StatusSegment::{
            CallBudget, CaseTitle, Clock, CloudBudget, CloudBytes, Cost, Keystore, Model, Provider,
            QueryRetainedBytes, QueryRetainedRows, QueryScanBytes, Seal, Severity, Sources,
            Subagents, TokenBudget, TokenPercent, Tokens, ToolCalls, Version,
        };
        let mut data = Self::default();
        for (segment, value) in [
            (CaseTitle, "Preview case"),
            (Severity, "medium"),
            (Seal, "open"),
            (Model, "Example local model"),
            (Provider, "Local"),
            (Tokens, "120000 tok"),
            (TokenBudget, "of 2000000 tok"),
            (TokenPercent, "6% tokens"),
            (ToolCalls, "24 calls"),
            (CallBudget, "of 1000 calls"),
            (CloudBytes, "0 B cloud"),
            (CloudBudget, "cloud limit 1 GiB"),
            (QueryScanBytes, "10485760 / 67108864 B billed"),
            (QueryRetainedRows, "12 / 2000 query rows"),
            (QueryRetainedBytes, "8192 / 4194304 B retained"),
            (Cost, "cost $0.10 (example)"),
            (Subagents, "2 active children"),
            (Sources, "8 sources"),
            (Keystore, "file/file"),
            (Version, env!("CARGO_PKG_VERSION")),
            (Clock, "12:34 UTC"),
        ] {
            data.insert(segment, value);
        }
        data
    }
}
fn flat(value: &str) -> String {
    crate::case::escape_display(&value.chars().take(4096).collect::<String>()).replace('\n', "\\n")
}
pub(crate) fn clip(value: &str, cells: usize) -> String {
    if value.width() <= cells {
        return value.into();
    }
    if cells == 0 {
        return String::new();
    }
    let mut result = String::new();
    let mut used = 0;
    for ch in value.chars() {
        let width = ch.width().unwrap_or(0);
        if used + width > cells - 1 {
            break;
        }
        result.push(ch);
        used += width;
    }
    result.push('…');
    result
}
fn style(color: StatusColor, theme: Theme) -> Style {
    Style::default().fg(match color {
        StatusColor::Text => theme.text,
        StatusColor::Muted => theme.muted,
        StatusColor::Accent => theme.accent,
        StatusColor::Warning => theme.warning,
        StatusColor::Error => theme.error,
        StatusColor::Success => theme.success,
    })
}
pub(crate) fn render(
    template: &StatusBarTemplate,
    data: &StatusData,
    cells: usize,
    theme: Theme,
) -> Line<'static> {
    if template.validate().is_err() {
        return render(&StatusBarTemplate::default(), data, cells, theme);
    }
    let separator = &template.separator;
    let warning = flat(&data.warnings.join(separator));
    let mut spans = Vec::new();
    let available = if warning.is_empty() {
        cells
    } else {
        let warning = clip(&warning, cells);
        let used = warning.width();
        spans.push(Span::styled(warning, theme.warning()));
        cells.saturating_sub(used + separator.width())
    };
    let mut items = template
        .segments
        .iter()
        .enumerate()
        .filter_map(|(index, item)| {
            let value = data.values.get(&item.segment)?;
            let limit = match item.segment {
                StatusSegment::CaseTitle => 24,
                StatusSegment::Model => 64,
                _ => 128,
            };
            Some((index, item, clip(value, limit)))
        })
        .collect::<Vec<_>>();
    while items.len() > 1 && width(&items, separator) > available {
        let victim = items
            .iter()
            .enumerate()
            .min_by_key(|(_, (index, item, _))| (item.priority, usize::MAX - *index))
            .map(|(position, _)| position);
        if let Some(victim) = victim {
            items.remove(victim);
        }
    }
    for (_, item, label) in items {
        if available == 0 {
            break;
        }
        if !spans.is_empty() {
            spans.push(Span::styled(separator.clone(), theme.muted()));
        }
        spans.push(Span::styled(
            clip(&label, available),
            style(item.color, theme),
        ));
    }
    Line::from(spans)
}
fn width(items: &[(usize, &irmind_app::StatusItem, String)], separator: &str) -> usize {
    items.iter().map(|(_, _, text)| text.width()).sum::<usize>()
        + items.len().saturating_sub(1) * separator.width()
}

pub(crate) struct FooterView<'a> {
    pub template: &'a StatusBarTemplate,
    pub data: &'a StatusData,
}
impl StatusData {
    pub(crate) fn extend(&mut self, other: Self) {
        self.values.extend(other.values);
    }
}
pub(crate) fn frame_data(view: &crate::case::CaseFrame<'_>) -> StatusData {
    use StatusSegment::{
        Activity, Approvals, CaseTitle, Cost, Detections, Model, Provider, Tokens,
    };
    let mut data = StatusData::default();
    data.insert(CaseTitle, view.title);
    let (model, provider) = model_labels(view.model);
    data.insert(Model, model);
    if let Some(provider) = provider {
        data.insert(Provider, provider);
    }
    data.insert(
        Tokens,
        view.tokens.map_or_else(
            || "tokens unavailable".into(),
            |value| format!("{value} tok"),
        ),
    );
    if !view.cost.is_empty() && !matches!(view.cost, "n/a" | "cost n/a") {
        data.insert(Cost, view.cost);
    }
    if view.pending != 0 {
        data.insert(
            Approvals,
            format!(
                "{} approval{} pending",
                view.pending,
                if view.pending == 1 { "" } else { "s" }
            ),
        );
    }
    if view.detections != 0 {
        data.insert(
            Detections,
            format!(
                "{} detection{}",
                view.detections,
                if view.detections == 1 { "" } else { "s" }
            ),
        );
    }
    let mut activity = view.status.to_owned();
    for marker in [
        "FULL INSTANCE SCOPE",
        "SCOPE LIMITED",
        "OVR",
        "BUDGET ≥80%",
        "BUDGET SETUP",
    ] {
        if view.status.contains(marker) {
            data.warnings.push(if marker.starts_with("BUDGET") {
                format!("{marker} · /budget")
            } else {
                marker.into()
            });
            activity = activity.replace(marker, "");
        }
    }
    let activity = activity
        .split('·')
        .map(str::trim)
        .filter(|part| !matches!(*part, "" | "idle" | "/budget"))
        .collect::<Vec<_>>()
        .join(" · ");
    data.insert(Activity, activity);
    data
}
pub(crate) fn model_labels(descriptor: &str) -> (String, Option<&'static str>) {
    if let Some((module, rest)) = descriptor
        .strip_prefix("module=")
        .and_then(|s| s.split_once(";model="))
    {
        let model = rest
            .rsplit_once(";endpoint_sha256=")
            .map_or(rest, |(model, _)| model);
        let provider = match module {
            "llm-openai-compatible" => Some("OpenAI-compatible"),
            "llm-anthropic" => Some("Anthropic"),
            "llm-deepseek" => Some("DeepSeek"),
            "llm-openrouter" => Some("OpenRouter"),
            _ => None,
        };
        return (model.into(), provider);
    }
    (descriptor.into(), None)
}
