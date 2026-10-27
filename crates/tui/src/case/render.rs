use super::runtime::CaseRuntime;
use super::state;
use super::{CaseFrame, Confirmation, Engine, Result, draw_case, escape_display, summarize_usage};
use state::CaseState;

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn render(&mut self) -> Result<()> {
        let usage = summarize_usage(&self.state.entries)?;
        let tokens = usage.input_tokens.saturating_add(usage.output_tokens);
        let cost = usage.estimated_cost_microusd.map_or_else(
            || "cost n/a".to_owned(),
            |micro| {
                format!(
                    "cost ${}.{:04}",
                    micro / 1_000_000,
                    (micro % 1_000_000) / 100
                )
            },
        );
        let panel = panel_text(&self.state);
        let title = self.engine.guard.screen(&self.state.case.title)?.text;
        let shown_messages = self
            .state
            .messages
            .iter()
            .map(|message| self.engine.guard.screen(message).map(|shown| shown.text))
            .collect::<Result<Vec<_>, _>>()?
            .join("\n\n");
        let shown_input = self.engine.guard.screen(&self.state.input)?.text;
        let shown_panel = if self.state.tab == 4 {
            escape_display(&panel)
        } else {
            self.engine.guard.screen(&panel)?.text
        };
        let overlay = overlay_text(&self.state, self.engine)?;
        let status = self.active.as_ref().map_or_else(
            || "a approve, d deny, e edit".into(),
            |(_, _, label)| {
                format!(
                    "{label}: {}s elapsed",
                    self.state
                        .running_since
                        .map_or(0, |since| since.elapsed().as_secs())
                )
            },
        );
        let status = if self.overrides_active {
            format!("SESSION OVERRIDES ACTIVE | {status}")
        } else {
            status
        };
        draw_case(
            self.terminal,
            &CaseFrame {
                id: self.id,
                title: &title,
                messages: &shown_messages,
                input: &shown_input,
                panel: &shown_panel,
                overlay: overlay.as_deref(),
                tab: self.state.tab,
                tokens,
                cost: &cost,
                pending: self.state.approvals.len(),
                status: &status,
            },
        )?;
        Ok(())
    }
}

fn panel_text(state: &CaseState) -> String {
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
        4 => state
            .approvals
            .iter()
            .enumerate()
            .map(|(index, request)| {
                format!(
                    "{} {}\n{:?} {} {:?}\n",
                    if index == state.selected_approval {
                        '>'
                    } else {
                        ' '
                    },
                    request.id,
                    request.mode,
                    request.tool.as_str(),
                    request.args
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => findings_panel(state),
    }
}

fn findings_panel(state: &CaseState) -> String {
    state
        .findings
        .iter()
        .map(|finding| {
            let status = if finding.confirmed {
                "confirmed"
            } else if finding.dismissed {
                "dismissed"
            } else {
                "proposed"
            };
            format!(
                "{} {:?} {}\n{}\n[evidence: {}]",
                finding.id, finding.kind, status, finding.value, finding.evidence_hash
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

fn overlay_text(state: &CaseState, engine: &Engine<'_>) -> Result<Option<String>> {
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
            Confirmation::Seal(_, info) | Confirmation::Export(_, info) => info,
        };
        return Ok(Some(escape_display(detail)));
    }
    if let Some(search) = &state.palette {
        const ACTIONS: [&str; 7] = [
            "ingest",
            "verify",
            "rebuild graph",
            "report",
            "export",
            "seal",
            "home",
        ];
        let listed = ACTIONS
            .iter()
            .filter(|action| action.contains(search.as_str()))
            .copied()
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
