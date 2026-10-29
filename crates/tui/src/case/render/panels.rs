use crate::case::command_registry;
use crate::case::state::{CaseState, panel_findings_for};
use crate::case::{Confirmation, Engine, Result, escape_display};
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
                "{} {} {:?} {}\n{}\n[evidence: {}]",
                if index == selected { '>' } else { ' ' },
                finding.id,
                finding.kind,
                status,
                finding.value,
                finding.evidence_hash
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

pub(super) fn overlay_text(state: &CaseState, engine: &Engine<'_>) -> Result<Option<String>> {
    if let Some(picker) = &state.picker {
        let mut lines = vec![
            format!("Select evidence · {}", picker.current.display()),
            "Enter open directory · s select file/directory · Backspace parent · Esc close".into(),
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
        let detail = match confirm {
            Confirmation::Seal(_, info)
            | Confirmation::Export(_, info)
            | Confirmation::Finding(_, info)
            | Confirmation::ObjectRead(_, info) => info,
        };
        return Ok(Some(escape_display(detail)));
    }
    if let Some(search) = &state.palette {
        let listed = command_registry::matches(search)
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
