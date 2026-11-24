use crate::case::command_registry;
use crate::case::state::{CaseState, ParserPrompt, panel_findings_for};
use crate::case::{Engine, Result, escape_display};
use irmind_app::{ApprovalRequest, ApprovalSource, Finding};
use std::collections::BTreeMap;

pub(super) fn panel_text(state: &CaseState) -> String {
    match state.tab {
        0 => state
            .timeline
            .iter()
            .map(|event| {
                format!(
                    "{} {}\n{}#{}",
                    event.at, event.event, event.evidence_hash, event.record_index
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n"),
        1 => format!(
            "{} evidence items\n\n{}",
            state.hashes.len(),
            state.hashes.join("\n")
        ),
        2 => audit_panel(state),
        3 => format!(
            "Title: {}\nSeverity: {}\nScope: {}\nSealed: {}",
            state.case.title,
            state.case.severity.as_str(),
            state.case.scope,
            state.case.sealed
        ),
        4 => approval_panel(
            &state.approvals,
            &state.approval_sources,
            state.selected_approval,
        ),
        _ => entity_panel(&state.findings, state.tab, state.selected_finding),
    }
}

pub(crate) fn approval_panel(
    approvals: &[ApprovalRequest],
    sources: &BTreeMap<String, ApprovalSource>,
    selected: usize,
) -> String {
    approvals
        .iter()
        .enumerate()
        .map(|(index, request)| {
            let source = sources.get(&request.id).map_or_else(
                || "Source fragment unavailable".to_owned(),
                |source| {
                    format!(
                        "Untrusted {:?} fragment {}\n{}",
                        source.provenance.source_kind(),
                        irmind_app::hex(source.provenance.evidence_hash()),
                        source.excerpt,
                    )
                },
            );
            format!(
                "{} [TAINTED] {}\n{:?} {} {:?}\n{}\n",
                if index == selected { '>' } else { ' ' },
                request.id,
                request.mode,
                request.tool.as_str(),
                request.args,
                source,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn entity_panel(findings: &[Finding], tab: usize, selected: usize) -> String {
    panel_findings_for(findings, tab)
        .iter()
        .enumerate()
        .map(|(index, finding)| {
            let status = if finding.confirmed {
                "confirmed"
            } else if finding.dismissed {
                "dismissed"
            } else {
                "proposed"
            };
            format!(
                "{} {} {:?} {}\n{}\n[evidence: {}]{}",
                if index == selected { '>' } else { ' ' },
                finding.id,
                finding.kind,
                status,
                finding.value,
                finding.evidence_hash,
                if finding.source_query_limited {
                    "\nSource query reached a local limit. More results may exist."
                } else {
                    ""
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn audit_panel(state: &CaseState) -> String {
    let mut lines = state
        .entries
        .iter()
        .rev()
        .take(12)
        .map(|entry| {
            format!(
                "#{} {} / {}: {}",
                entry.seq,
                entry.actor.as_storage(),
                entry.origin,
                entry.kind
            )
        })
        .collect::<Vec<_>>();
    lines.extend(state.operations.iter().rev().take(6).map(|entry| {
        format!(
            "operation #{} {}: cancelled {}",
            entry.seq,
            entry.actor.as_storage(),
            entry.operation
        )
    }));
    lines.join("\n")
}

pub(super) fn overlay_text(
    state: &CaseState,
    engine: &Engine<'_>,
    parser_body: ratatui::layout::Rect,
) -> Result<Option<String>> {
    if let Some(help) = &state.help {
        return Ok(Some(engine.guard.screen(help)?.text));
    }
    if let Some(editor) = &state.budget.editor {
        return Ok(Some(engine.guard.screen(&editor.text())?.text));
    }
    if let Some(prompt) = &state.cluster_prompt {
        return prompt
            .screened_text(engine.guard.as_ref())
            .map(Some)
            .map_err(Into::into);
    }
    if let Some(prompt) = &state.time_prompt {
        return prompt
            .screened_text(engine.guard.as_ref())
            .map(Some)
            .map_err(Into::into);
    }
    if let Some(prompt) = &state.parser_prompt {
        return parser_prompt_text(prompt, parser_body, |text| {
            Ok(engine.guard.screen(text)?.text)
        })
        .map(Some);
    }
    if let Some(picker) = &state.picker {
        let mut lines = vec![
            format!("Select evidence · {}", picker.current.display()),
            "Enter opens directory or ingests file · Backspace parent · Esc close".into(),
        ];
        for (index, path) in picker
            .entries
            .iter()
            .enumerate()
            .skip(picker.selected.saturating_sub(8))
            .take(16)
        {
            lines.push(format!(
                "{} {}",
                if index == picker.selected { '>' } else { ' ' },
                path.file_name()
                    .map_or_else(|| "?".into(), |name| name.to_string_lossy().into_owned())
            ));
        }
        return Ok(Some(engine.guard.screen(&lines.join("\n"))?.text));
    }
    if let Some(confirm) = &state.confirmation {
        return Ok(Some(format!(
            "{}\n\n{} 1. Cancel   {} 2. Confirm\n↑/↓ choose · Enter select · Esc cancel",
            escape_display(confirm.detail()),
            if state.confirmation_option == 0 {
                ">"
            } else {
                " "
            },
            if state.confirmation_option == 1 {
                ">"
            } else {
                " "
            },
        )));
    }
    if let Some(search) = &state.palette {
        let listed = command_registry::matches_with_skills(search, &state.skill_commands)
            .iter()
            .take(12)
            .map(|command| format!("/{} · {}", command.name, command.description))
            .collect::<Vec<_>>();
        return Ok(Some(
            engine
                .guard
                .screen(&format!(
                    "Command palette · {search}\n{}\nEnter run first match · Esc close",
                    listed.join("\n")
                ))?
                .text,
        ));
    }
    Ok(None)
}

pub(in crate::case) fn parser_prompt_text(
    prompt: &ParserPrompt,
    body: ratatui::layout::Rect,
    screen: impl FnOnce(&str) -> Result<String>,
) -> Result<String> {
    let page = ParserPrompt::page_size(body.height);
    let end_limit = prompt.candidates.len();
    let start = prompt
        .selected
        .saturating_sub(page / 2)
        .min(end_limit.saturating_sub(page));
    let end = start.saturating_add(page).min(end_limit);
    let mut lines = Vec::new();
    if body.height >= 7 {
        lines.push(format!("Choose parser for {}", prompt.source));
        lines.push(if end_limit == 0 {
            "No parser candidates are available.".into()
        } else if prompt.candidates[0].1 == 0 {
            "Detection found no positive match. Choose only if you know the format.".into()
        } else {
            "Detection is ambiguous or has low confidence.".into()
        });
        lines.push(format!(
            "{}{} options{}",
            if start > 0 { "↑ more · " } else { "" },
            end_limit,
            if end < end_limit { " · ↓ more" } else { "" }
        ));
    }
    for (offset, (name, confidence)) in prompt.candidates[start..end].iter().enumerate() {
        let index = start + offset;
        lines.push(format!(
            "{} {}. {} · {}% confidence",
            if index == prompt.selected { '>' } else { ' ' },
            index + 1,
            name,
            confidence
        ));
    }
    if body.height >= 7 {
        lines.push(
            prompt
                .candidates
                .get(prompt.selected)
                .and_then(|(id, _)| prompt.descriptions.get(id))
                .cloned()
                .unwrap_or_default(),
        );
        lines.push(if prompt.invalid_number {
            format!(
                "No option {}. Enter a number from 1 to {end_limit}.",
                prompt.typed_option
            )
        } else if prompt.typed_option.is_empty() {
            "Type an option number or move with ↑/↓.".into()
        } else {
            format!("Option number: {}", prompt.typed_option)
        });
        lines.push("Home/End · PgUp/PgDn · Enter confirm · Esc cancel".into());
    }
    let text = lines
        .iter()
        .map(|line| escape_display(line).replace('\n', " "))
        .collect::<Vec<_>>()
        .join("\n");
    let screened = screen(&text)?;
    Ok(screened
        .split('\n')
        .map(|line| single_row(line, usize::from(body.width)))
        .collect::<Vec<_>>()
        .join("\n"))
}

fn single_row(escaped: &str, width: usize) -> String {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
    if escaped.width() <= width {
        return escaped.to_owned();
    }
    let mut remaining = width.saturating_sub(1);
    let mut shortened = escaped
        .chars()
        .take_while(|ch| {
            let columns = ch.width().unwrap_or(0);
            if let Some(rest) = remaining.checked_sub(columns) {
                remaining = rest;
                true
            } else {
                false
            }
        })
        .collect::<String>();
    if width > 0 {
        shortened.push('…');
    }
    shortened
}
