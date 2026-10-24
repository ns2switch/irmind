#![forbid(unsafe_code)]

use crate::parse_approval_args;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use irmind_app::{ContentGuard, Engine, FindingKind, LlmPort, Repository, summarize_usage};
use irmind_domain::CaseId;
use irmind_infra::LocalStore;
use irmind_security::MandatoryGuard;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Tabs, Wrap},
};
use std::io;

struct TerminalSession;

impl TerminalSession {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

pub fn run(
    engine: &Engine<'_>,
    store: &LocalStore,
    guard: &MandatoryGuard,
    model: &dyn LlmPort,
    id: &CaseId,
) -> Result<()> {
    let mut case = store.get_case(id)?;
    let _session = TerminalSession::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut input = String::new();
    let mut messages = vec![format!(
        "Case: {}\nSeverity: {}\nScope: {}",
        case.title,
        case.severity.as_str(),
        case.scope
    )];
    let mut approvals = engine.pending_approvals(id)?;
    let mut findings = engine.findings(id)?;
    let mut tab = 0usize;
    let mut selected_approval = 0usize;
    loop {
        selected_approval = selected_approval.min(approvals.len().saturating_sub(1));
        let (hashes, entries, timeline) = {
            let _case_lock = store.lock_case(id)?;
            (
                store.evidence_hashes(id)?,
                store.entries(id)?,
                store.timeline(id, 30)?,
            )
        };
        let usage = summarize_usage(&entries)?;
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
        let panel = match tab {
            0 => timeline
                .iter()
                .map(|event| {
                    format!(
                        "{} {}\n{}#{}",
                        event.at, event.event, event.evidence_hash, event.record_index
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n"),
            1 => format!("{} evidence items\n\n{}", hashes.len(), hashes.join("\n")),
            2 => entries
                .iter()
                .rev()
                .take(12)
                .map(|e| {
                    format!(
                        "#{} {} / {}: {}",
                        e.seq,
                        e.actor.as_storage(),
                        e.origin,
                        e.kind
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
            3 => format!(
                "Title: {}\nSeverity: {}\nScope: {}\nSealed: {}",
                case.title,
                case.severity.as_str(),
                case.scope,
                case.sealed
            ),
            4 => approvals
                .iter()
                .enumerate()
                .map(|(index, request)| {
                    format!(
                        "{} {}\n{:?} {} {:?}\n",
                        if index == selected_approval { '>' } else { ' ' },
                        request.id,
                        request.mode,
                        request.tool.as_str(),
                        request.args,
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
            _ => findings
                .iter()
                .map(|finding| {
                    format!(
                        "{} {:?} {}\n{}\n[evidence: {}]",
                        finding.id,
                        finding.kind,
                        if finding.confirmed {
                            "confirmed"
                        } else if finding.dismissed {
                            "dismissed"
                        } else {
                            "proposed"
                        },
                        finding.value,
                        finding.evidence_hash
                    )
                })
                .collect::<Vec<_>>()
                .join("\n\n"),
        };
        let title = guard.screen(&case.title)?.text;
        let shown_messages = messages
            .iter()
            .map(|m| guard.screen(m).map(|s| s.text))
            .collect::<Result<Vec<_>, _>>()?
            .join("\n\n");
        // Approval arguments are shown exactly. Debug formatting escapes terminal controls.
        let shown_panel = if tab == 4 {
            panel
        } else {
            guard.screen(&panel)?.text
        };
        terminal.draw(|frame| {
            let sections = Layout::vertical([
                Constraint::Min(5),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(frame.area());
            let columns =
                Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)])
                    .split(sections[0]);
            let conversation = Paragraph::new(shown_messages.as_str())
                .block(
                    Block::default()
                        .title(format!(" Conversation · {title} "))
                        .borders(Borders::ALL),
                )
                .wrap(Wrap { trim: false })
                .scroll((
                    u16::try_from(
                        shown_messages
                            .lines()
                            .count()
                            .saturating_sub(usize::from(columns[0].height.saturating_sub(2))),
                    )
                    .unwrap_or(u16::MAX),
                    0,
                ));
            frame.render_widget(conversation, columns[0]);
            let right =
                Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(columns[1]);
            let tabs = Tabs::new(vec![
                "Timeline",
                "Evidence",
                "Audit",
                "Case",
                "Approvals",
                "Findings",
            ])
            .select(tab)
            .block(Block::default().borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
            frame.render_widget(tabs, right[0]);
            frame.render_widget(
                Paragraph::new(shown_panel.as_str())
                    .block(Block::default().borders(Borders::ALL))
                    .wrap(Wrap { trim: false }),
                right[1],
            );
            frame.render_widget(
                Paragraph::new(input.as_str())
                    .block(Block::default().title(" Prompt ").borders(Borders::ALL)),
                sections[1],
            );
            frame.render_widget(
                Paragraph::new(Line::from(format!(
                    "{} | {} tokens | {} | {} pending | a approve, d deny, e edit | /quit",
                    id.as_str(),
                    tokens,
                    cost,
                    approvals.len()
                ))),
                sections[2],
            );
        })?;
        if let Event::Key(key) = event::read()? {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                break;
            }
            match key.code {
                KeyCode::Esc => break,
                KeyCode::Tab => tab = (tab + 1) % 6,
                KeyCode::Up if tab == 4 => selected_approval = selected_approval.saturating_sub(1),
                KeyCode::Down if tab == 4 && selected_approval + 1 < approvals.len() => {
                    selected_approval += 1;
                }
                KeyCode::Char('a') if tab == 4 && input.is_empty() => {
                    if let Some(request) = approvals.get(selected_approval) {
                        match engine.approve(id, &request.id) {
                            Ok(result) => messages.push(result),
                            Err(error) => messages.push(format!("Approval error: {error}")),
                        }
                        approvals = engine.pending_approvals(id)?;
                    }
                }
                KeyCode::Char('d') if tab == 4 && input.is_empty() => {
                    if let Some(request) = approvals.get(selected_approval) {
                        input = format!("/deny {} ", request.id);
                    }
                }
                KeyCode::Char('e') if tab == 4 && input.is_empty() => {
                    if let Some(request) = approvals.get(selected_approval) {
                        input = format!("/edit {} ", request.id);
                    }
                }
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char(c) if input.len() < 20_000 => input.push(c),
                KeyCode::Enter => {
                    let prompt = std::mem::take(&mut input);
                    if prompt.is_empty() {
                        continue;
                    }
                    if prompt == "/quit" {
                        break;
                    }
                    if prompt == "/scope" {
                        messages.push(format!("Scope: {}", case.scope));
                    } else if let Some(scope) = prompt.strip_prefix("/scope ") {
                        match engine.change_scope(id, scope) {
                            Ok(()) => {
                                case = store.get_case(id)?;
                                messages.push(format!("Scope updated: {}", case.scope));
                            }
                            Err(error) => messages.push(format!("Scope error: {error}")),
                        }
                    } else if prompt == "/approvals" {
                        approvals = engine.pending_approvals(id)?;
                        tab = 4;
                    } else if prompt == "/findings" {
                        findings = engine.findings(id)?;
                        tab = 5;
                    } else if prompt == "/report" {
                        match engine.report(id) {
                            Ok(report) => messages.push(report),
                            Err(error) => messages.push(format!("Report error: {error}")),
                        }
                    } else if let Some(rest) = prompt.strip_prefix("/add ") {
                        let parts = rest.splitn(3, ' ').collect::<Vec<_>>();
                        if let [kind, evidence_hash, value] = parts.as_slice() {
                            match FindingKind::parse(kind)
                                .and_then(|kind| engine.add_finding(id, kind, value, evidence_hash))
                            {
                                Ok(finding_id) => {
                                    messages.push(format!("Finding proposed: {finding_id}"));
                                }
                                Err(error) => messages.push(format!("Finding error: {error}")),
                            }
                            findings = engine.findings(id)?;
                            tab = 5;
                        } else {
                            messages.push("Usage: /add <kind> <evidence_hash> <value>".into());
                        }
                    } else if let Some(finding_id) = prompt.strip_prefix("/confirm ") {
                        match engine.confirm_finding(id, finding_id) {
                            Ok(()) => messages.push("Finding confirmed".into()),
                            Err(error) => messages.push(format!("Finding error: {error}")),
                        }
                        findings = engine.findings(id)?;
                        tab = 5;
                    } else if let Some(rest) = prompt.strip_prefix("/dismiss ") {
                        if let Some((finding_id, reason)) = rest.split_once(' ') {
                            match engine.dismiss_finding(id, finding_id, reason) {
                                Ok(()) => messages.push("Finding dismissed".into()),
                                Err(error) => messages.push(format!("Finding error: {error}")),
                            }
                            findings = engine.findings(id)?;
                            tab = 5;
                        } else {
                            messages.push("Usage: /dismiss <id> <reason>".into());
                        }
                    } else if let Some(request_id) = prompt.strip_prefix("/approve ") {
                        match engine.approve(id, request_id) {
                            Ok(result) => messages.push(result),
                            Err(error) => messages.push(format!("Approval error: {error}")),
                        }
                        approvals = engine.pending_approvals(id)?;
                    } else if let Some(rest) = prompt.strip_prefix("/deny ") {
                        if let Some((request_id, reason)) = rest.split_once(' ') {
                            match engine.deny(id, request_id, reason) {
                                Ok(result) => messages.push(result),
                                Err(error) => messages.push(format!("Approval error: {error}")),
                            }
                        } else {
                            messages.push("Usage: /deny <id> <reason>".into());
                        }
                        approvals = engine.pending_approvals(id)?;
                    } else if let Some(rest) = prompt.strip_prefix("/edit ") {
                        if let Some((request_id, args_json)) = rest.split_once(' ') {
                            match parse_approval_args(args_json).and_then(|args| {
                                engine
                                    .edit_approval(id, request_id, args)
                                    .map_err(Into::into)
                            }) {
                                Ok(result) => messages.push(result),
                                Err(error) => messages.push(format!("Approval error: {error}")),
                            }
                        } else {
                            messages.push("Usage: /edit <id> {\"ioc\":\"example.com\"}".into());
                        }
                        approvals = engine.pending_approvals(id)?;
                    } else if prompt == "/pause" {
                        messages.push("Agent paused. No background work is running.".into());
                    } else if let Some(hash) = prompt.strip_prefix("/evidence ") {
                        match store.get_evidence(id, hash) {
                            Ok(bytes) => {
                                let literal =
                                    String::from_utf8_lossy(&bytes[..bytes.len().min(4000)]);
                                let visible = literal.chars().fold(String::new(), |mut out, ch| {
                                    if (ch.is_control() && ch != '\n' && ch != '\t')
                                        || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                                    {
                                        out.extend(ch.escape_default());
                                    } else {
                                        out.push(ch);
                                    }
                                    out
                                });
                                messages.push(format!("Evidence {hash}:\n{visible}"));
                            }
                            Err(e) => messages.push(format!("Evidence error: {e}")),
                        }
                    } else {
                        messages.push(format!("Analyst: {prompt}"));
                        let answer = engine.investigate(id, &prompt, model);
                        match answer {
                            Ok(text) => messages.push(format!("IRMind: {text}")),
                            Err(e) => messages.push(format!("Error: {e}")),
                        }
                        approvals = engine.pending_approvals(id)?;
                    }
                    if messages.len() > 30 {
                        messages.drain(..messages.len() - 30);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(())
}
