use crate::{WorkspaceIo, workflow::CaseWorkflow};
use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use irmind_app::{CancellationToken, CaseId, Engine, FindingKind, LlmPort, summarize_usage};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{
    collections::BTreeMap,
    io,
    path::PathBuf,
    sync::mpsc,
    time::{Duration, Instant},
};

mod confirmation;
mod operation;
mod picker;
mod view;
pub(crate) use confirmation::escape_display;
use confirmation::{Confirmation, confirmation_summary, seal_confirmation};
use operation::cancelled_operation;
use picker::PathPicker;
pub(crate) use view::{CaseFrame, draw_case};

type ActiveTask<'scope> = (
    CancellationToken,
    std::thread::ScopedJoinHandle<'scope, Result<String, irmind_app::AppError>>,
    &'static str,
);

fn parse_approval_args(value: &str) -> Result<BTreeMap<String, String>> {
    serde_json::from_str(value).context("approval arguments must be a JSON object of strings")
}

pub(crate) fn run_case(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    model: Option<&dyn LlmPort>,
    io_ops: &dyn WorkspaceIo,
    id: &CaseId,
    shutdown: &CancellationToken,
) -> Result<()> {
    let mut case = engine.repo.get_case(id)?;
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
    let mut palette: Option<String> = None;
    let mut picker: Option<PathPicker> = None;
    let mut confirmation: Option<Confirmation> = None;
    let mut confirmed_action: Option<Confirmation> = None;
    let (progress_tx, progress_rx) = mpsc::channel::<String>();
    let workflow = CaseWorkflow {
        engine,
        model,
        io_ops,
    };
    let (mut hashes, mut entries, mut operations, mut timeline) = {
        let _case_lock = engine.repo.lock_case(id)?;
        (
            engine.evidence_store.evidence_hashes(id)?,
            engine.audit_log.entries(id)?,
            engine.audit_log.operations(id)?,
            engine.graph.timeline(id, 30)?,
        )
    };
    std::thread::scope(|scope| -> Result<()> {
        let mut active: Option<ActiveTask<'_>> = None;
        let mut needs_refresh = false;
        let mut running_since: Option<Instant> = None;
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            while let Ok(progress) = progress_rx.try_recv() {
                messages.push(progress);
            }
            if active
                .as_ref()
                .is_some_and(|(_, task, _)| task.is_finished())
                && let Some((_, task, label)) = active.take()
            {
                match task
                    .join()
                    .map_err(|_| anyhow::anyhow!("investigation thread panicked"))?
                {
                    Ok(text) => messages.push(format!("{label}: {text}")),
                    Err(irmind_app::AppError::Cancelled) => {
                        engine.record_cancellation(id, cancelled_operation(label))?;
                        messages.push(format!("{label} cancelled and audited"));
                    }
                    Err(error) => messages.push(format!("Error: {error}")),
                }
                case = engine.repo.get_case(id)?;
                approvals = engine.pending_approvals(id)?;
                findings = engine.findings(id)?;
                needs_refresh = true;
            }
            if active.is_some() && running_since.is_none() {
                running_since = Some(Instant::now());
            }
            if active.is_none() {
                running_since = None;
            }
            selected_approval = selected_approval.min(approvals.len().saturating_sub(1));
            if active.is_none() && needs_refresh {
                let _case_lock = engine.repo.lock_case(id)?;
                hashes = engine.evidence_store.evidence_hashes(id)?;
                entries = engine.audit_log.entries(id)?;
                operations = engine.audit_log.operations(id)?;
                timeline = engine.graph.timeline(id, 30)?;
                needs_refresh = false;
            }
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
                2 => {
                    let mut lines = entries
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
                        .collect::<Vec<_>>();
                    lines.extend(operations.iter().rev().take(6).map(|e| {
                        format!(
                            "operation #{} {}: cancelled {}",
                            e.seq,
                            e.actor.as_storage(),
                            e.operation
                        )
                    }));
                    lines.join("\n")
                }
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
            let title = engine.guard.screen(&case.title)?.text;
            let shown_messages = messages
                .iter()
                .map(|m| engine.guard.screen(m).map(|s| s.text))
                .collect::<Result<Vec<_>, _>>()?
                .join("\n\n");
            let shown_input = engine.guard.screen(&input)?.text;
            // Approval arguments are shown exactly. Debug formatting escapes terminal controls.
            let shown_panel = if tab == 4 {
                escape_display(&panel)
            } else {
                engine.guard.screen(&panel)?.text
            };
            let overlay = if let Some(picker) = &picker {
                let mut lines = vec![
                    format!("Select evidence · {}", picker.current.display()),
                    "Enter open directory · s select file/directory · Backspace parent · Esc close"
                        .into(),
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
                Some(engine.guard.screen(&lines.join("\n"))?.text)
            } else if let Some(confirm) = &confirmation {
                let detail = match confirm {
                    Confirmation::Seal(_, info) | Confirmation::Export(_, info) => info,
                };
                Some(escape_display(detail))
            } else if let Some(search) = &palette {
                let actions = [
                    "ingest",
                    "verify",
                    "rebuild graph",
                    "report",
                    "export",
                    "seal",
                    "home",
                ];
                let listed = actions
                    .iter()
                    .filter(|action| action.contains(search.as_str()))
                    .copied()
                    .collect::<Vec<_>>();
                Some(
                    engine
                        .guard
                        .screen(&format!(
                            "Command palette · {search}\n{}\nEnter run first match · Esc close",
                            listed.join("\n")
                        ))?
                        .text,
                )
            } else {
                None
            };
            let status = active.as_ref().map_or_else(
                || "a approve, d deny, e edit".into(),
                |(_, _, label)| {
                    format!(
                        "{label}: {}s elapsed",
                        running_since.map_or(0, |since| since.elapsed().as_secs())
                    )
                },
            );
            draw_case(
                terminal,
                &CaseFrame {
                    id,
                    title: &title,
                    messages: &shown_messages,
                    input: &shown_input,
                    panel: &shown_panel,
                    overlay: overlay.as_deref(),
                    tab,
                    tokens,
                    cost: &cost,
                    pending: approvals.len(),
                    status: &status,
                },
            )?;
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
            {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    break;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('k') {
                    palette = Some(String::new());
                    picker = None;
                    confirmation = None;
                    continue;
                }
                let mut code = key.code;
                if let Some(mut query) = palette.take() {
                    match code {
                        KeyCode::Esc => continue,
                        KeyCode::Backspace => {
                            query.pop();
                            palette = Some(query);
                            continue;
                        }
                        KeyCode::Char(ch) if query.len() < 80 => {
                            query.push(ch);
                            palette = Some(query);
                            continue;
                        }
                        KeyCode::Enter => {
                            let actions = [
                                "ingest",
                                "verify",
                                "rebuild graph",
                                "report",
                                "export",
                                "seal",
                                "home",
                            ];
                            let selected = actions
                                .iter()
                                .find(|action| action.contains(query.as_str()))
                                .copied();
                            input = match selected {
                                Some("ingest") => "/ingest".into(),
                                Some("verify") => "/verify".into(),
                                Some("rebuild graph") => "/rebuild".into(),
                                Some("report") => "/report".into(),
                                Some("export") => "/export".into(),
                                Some("seal") => "/seal".into(),
                                Some("home") => "/home".into(),
                                _ => String::new(),
                            };
                            code = KeyCode::Enter;
                        }
                        _ => {
                            palette = Some(query);
                            continue;
                        }
                    }
                }
                if let Some(mut browser) = picker.take() {
                    match code {
                        KeyCode::Esc => continue,
                        KeyCode::Up => {
                            browser.selected = browser.selected.saturating_sub(1);
                            picker = Some(browser);
                            continue;
                        }
                        KeyCode::Down => {
                            browser.selected =
                                (browser.selected + 1).min(browser.entries.len().saturating_sub(1));
                            picker = Some(browser);
                            continue;
                        }
                        KeyCode::Backspace => {
                            if let Some(parent) = browser.current.parent() {
                                browser.current = parent.to_path_buf();
                                browser.refresh()?;
                            }
                            picker = Some(browser);
                            continue;
                        }
                        KeyCode::Enter => {
                            let selected = browser.selected_path();
                            let metadata = std::fs::symlink_metadata(&selected)?;
                            if metadata.file_type().is_symlink() {
                                messages.push("Symlink selection is not allowed".into());
                                picker = Some(browser);
                                continue;
                            }
                            if metadata.is_dir() {
                                browser.current = selected;
                                browser.refresh()?;
                                picker = Some(browser);
                                continue;
                            }
                            input = format!("/ingest {}", selected.to_string_lossy());
                            code = KeyCode::Enter;
                        }
                        KeyCode::Char('s') => {
                            input =
                                format!("/ingest {}", browser.selected_path().to_string_lossy());
                            code = KeyCode::Enter;
                        }
                        _ => {
                            picker = Some(browser);
                            continue;
                        }
                    }
                }
                if let Some(pending) = confirmation.take() {
                    if code == KeyCode::Char('y') {
                        input = match &pending {
                            Confirmation::Seal(_, _) => "/seal".into(),
                            Confirmation::Export(path, _) => {
                                format!("/export {}", path.to_string_lossy())
                            }
                        };
                        confirmed_action = Some(pending);
                        code = KeyCode::Enter;
                    } else {
                        continue;
                    }
                }
                match code {
                    KeyCode::Esc => break,
                    KeyCode::Tab => tab = (tab + 1) % 6,
                    KeyCode::Up if tab == 4 => {
                        selected_approval = selected_approval.saturating_sub(1);
                    }
                    KeyCode::Down if tab == 4 && selected_approval + 1 < approvals.len() => {
                        selected_approval += 1;
                    }
                    KeyCode::Char('a') if tab == 4 && input.is_empty() && active.is_none() => {
                        if let Some(request) = approvals.get(selected_approval) {
                            let request_id = request.id.clone();
                            let cancel = shutdown.child_token();
                            let worker_cancel = cancel.clone();
                            let task = scope
                                .spawn(move || workflow.approve(id, &request_id, &worker_cancel));
                            active = Some((cancel, task, "Approval"));
                        }
                    }
                    KeyCode::Char('d') if tab == 4 && input.is_empty() && active.is_none() => {
                        if let Some(request) = approvals.get(selected_approval) {
                            input = format!("/deny {} ", request.id);
                        }
                    }
                    KeyCode::Char('e') if tab == 4 && input.is_empty() && active.is_none() => {
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
                        if prompt == "/quit" || prompt == "/home" {
                            break;
                        }
                        if prompt == "/pause" {
                            if let Some((cancel, _, _)) = &active {
                                cancel.cancel();
                                messages.push("Cancelling active investigation…".into());
                            } else {
                                messages.push("No investigation is running.".into());
                            }
                            continue;
                        }
                        if active.is_some() {
                            messages.push(
                                "Investigation running; use /pause before another command.".into(),
                            );
                            continue;
                        }
                        if prompt == "/help" {
                            messages.push("Case: /ingest, /verify, /rebuild, /verify-graph, /report, /seal, /export [path], /scope, /evidence <hash>, /evidence-save <hash> <path>, /pause, /home. Graph: /graph, /timeline, /entity, /neighbors, /entity-timeline, /path, /search, /raw. Findings: /add, /confirm, /dismiss. Approvals: /approvals, /approve, /deny, /edit.".into());
                        } else if prompt == "/ingest" {
                            picker = Some(PathPicker::open(std::env::current_dir()?)?);
                        } else if let Some(path) = prompt.strip_prefix("/ingest ") {
                            let path = PathBuf::from(path);
                            let cancel = shutdown.child_token();
                            let worker_cancel = cancel.clone();
                            let progress = progress_tx.clone();
                            let task = scope.spawn(move || {
                                workflow
                                    .ingest_path(
                                        id,
                                        &path,
                                        &worker_cancel,
                                        |done, count, source| {
                                            let _ = progress
                                                .send(format!("Ingested {done}/{count}: {source}"));
                                        },
                                    )
                                    .map(|count| format!("Ingested {count} files"))
                            });
                            active = Some((cancel, task, "Ingest"));
                        } else if prompt == "/verify" {
                            let cancel = shutdown.child_token();
                            let worker_cancel = cancel.clone();
                            let task = scope.spawn(move || {
                                workflow
                                    .verify(id, &worker_cancel)
                                    .map(|count| format!("Verified {count} audit entries"))
                            });
                            active = Some((cancel, task, "Verify"));
                        } else if prompt == "/rebuild" {
                            let cancel = shutdown.child_token();
                            let worker_cancel = cancel.clone();
                            let task = scope.spawn(move || {
                                workflow
                                    .rebuild_graph(id, &worker_cancel)
                                    .map(|count| format!("Rebuilt {count} records"))
                            });
                            active = Some((cancel, task, "Rebuild graph"));
                        } else if prompt == "/seal" {
                            if let Some(Confirmation::Seal(preview, _)) = confirmed_action.take() {
                                let cancel = shutdown.child_token();
                                let worker_cancel = cancel.clone();
                                let task = scope.spawn(move || {
                                    if worker_cancel.is_cancelled() {
                                        return Err(irmind_app::AppError::Cancelled);
                                    }
                                    workflow.seal_prepared(&preview)?;
                                    Ok("Case sealed".into())
                                });
                                active = Some((cancel, task, "Seal"));
                            } else {
                                let preview = workflow.prepare_seal(id)?;
                                let summary = seal_confirmation(&preview);
                                confirmation = Some(Confirmation::Seal(Box::new(preview), summary));
                            }
                        } else if prompt == "/export" || prompt.starts_with("/export ") {
                            let path = prompt.strip_prefix("/export ").map_or_else(
                                || PathBuf::from(format!("{}.irmind.json", id.as_str())),
                                PathBuf::from,
                            );
                            if let Some(Confirmation::Export(approved, _)) = confirmed_action.take()
                                && approved == path
                            {
                                let cancel = shutdown.child_token();
                                let worker_cancel = cancel.clone();
                                let task = scope.spawn(move || {
                                    if worker_cancel.is_cancelled() {
                                        return Err(irmind_app::AppError::Cancelled);
                                    }
                                    workflow
                                        .export(id, &path, &worker_cancel)
                                        .map(|fingerprint| {
                                            format!("Exported case; analyst key {fingerprint}")
                                        })
                                });
                                active = Some((cancel, task, "Export"));
                            } else {
                                let summary = confirmation_summary(engine, id, "Export")?;
                                confirmation = Some(Confirmation::Export(
                                    path.clone(),
                                    format!("{summary}\nDestination: {}", path.display()),
                                ));
                            }
                        } else if prompt == "/scope" {
                            messages.push(format!("Scope: {}", case.scope));
                        } else if let Some(scope) = prompt.strip_prefix("/scope ") {
                            match engine.change_scope(id, scope) {
                                Ok(()) => {
                                    case = engine.repo.get_case(id)?;
                                    messages.push(format!("Scope updated: {}", case.scope));
                                    needs_refresh = true;
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
                        } else if prompt == "/graph" {
                            match engine.graph.graph_summary(id) {
                                Ok(summary) => messages.push(summary),
                                Err(error) => messages.push(format!("Graph error: {error}")),
                            }
                        } else if prompt == "/verify-graph" {
                            let cancel = shutdown.child_token();
                            let worker_cancel = cancel.clone();
                            let task = scope.spawn(move || {
                                engine
                                    .verify_graph_cancelable(id, &worker_cancel)
                                    .map(|count| format!("Verified {count} graph records"))
                            });
                            active = Some((cancel, task, "Verify"));
                        } else if prompt == "/timeline" {
                            tab = 0;
                        } else if let Some(rest) = prompt.strip_prefix("/entity ") {
                            if let Some((kind, value)) = rest.split_once(' ') {
                                match engine.graph.entity_lookup(id, kind, value) {
                                    Ok(result) => messages.push(result),
                                    Err(error) => messages.push(format!("Graph error: {error}")),
                                }
                            }
                        } else if let Some(rest) = prompt.strip_prefix("/neighbors ") {
                            if let Some((kind, value)) = rest.split_once(' ') {
                                match engine.graph.neighbors(id, kind, value, 10) {
                                    Ok(result) => messages.push(result),
                                    Err(error) => messages.push(format!("Graph error: {error}")),
                                }
                            }
                        } else if let Some(rest) = prompt.strip_prefix("/entity-timeline ") {
                            if let Some((kind, value)) = rest.split_once(' ') {
                                match engine.graph.entity_timeline(id, kind, value, 10) {
                                    Ok(result) => messages.push(result),
                                    Err(error) => messages.push(format!("Graph error: {error}")),
                                }
                            }
                        } else if let Some(rest) = prompt.strip_prefix("/path ") {
                            let parts = rest.splitn(4, ' ').collect::<Vec<_>>();
                            if let [from_kind, from_value, to_kind, to_value] = parts.as_slice() {
                                match engine.graph.graph_path(
                                    id,
                                    (from_kind, from_value),
                                    (to_kind, to_value),
                                ) {
                                    Ok(result) => messages.push(result),
                                    Err(error) => messages.push(format!("Graph error: {error}")),
                                }
                            }
                        } else if let Some(query) = prompt.strip_prefix("/search ") {
                            match engine.graph.text_search(id, query, 10) {
                                Ok(result) => messages.push(result),
                                Err(error) => messages.push(format!("Graph error: {error}")),
                            }
                        } else if let Some(rest) = prompt.strip_prefix("/raw ") {
                            if let Some((hash, index)) = rest.split_once(' ')
                                && let Ok(index) = index.parse::<usize>()
                            {
                                match engine.graph.raw_record(id, hash, index) {
                                    Ok(result) => messages.push(result),
                                    Err(error) => messages.push(format!("Graph error: {error}")),
                                }
                            }
                        } else if let Some(rest) = prompt.strip_prefix("/add ") {
                            let parts = rest.splitn(3, ' ').collect::<Vec<_>>();
                            if let [kind, evidence_hash, value] = parts.as_slice() {
                                match FindingKind::parse(kind).and_then(|kind| {
                                    engine.add_finding(id, kind, value, evidence_hash)
                                }) {
                                    Ok(finding_id) => {
                                        messages.push(format!("Finding proposed: {finding_id}"));
                                    }
                                    Err(error) => messages.push(format!("Finding error: {error}")),
                                }
                                findings = engine.findings(id)?;
                                needs_refresh = true;
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
                            needs_refresh = true;
                            tab = 5;
                        } else if let Some(rest) = prompt.strip_prefix("/dismiss ") {
                            if let Some((finding_id, reason)) = rest.split_once(' ') {
                                match engine.dismiss_finding(id, finding_id, reason) {
                                    Ok(()) => messages.push("Finding dismissed".into()),
                                    Err(error) => messages.push(format!("Finding error: {error}")),
                                }
                                findings = engine.findings(id)?;
                                needs_refresh = true;
                                tab = 5;
                            } else {
                                messages.push("Usage: /dismiss <id> <reason>".into());
                            }
                        } else if let Some(request_id) = prompt.strip_prefix("/approve ") {
                            let request_id = request_id.to_owned();
                            let cancel = shutdown.child_token();
                            let worker_cancel = cancel.clone();
                            let task = scope
                                .spawn(move || workflow.approve(id, &request_id, &worker_cancel));
                            active = Some((cancel, task, "Approval"));
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
                            needs_refresh = true;
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
                            needs_refresh = true;
                        } else if let Some(rest) = prompt.strip_prefix("/evidence-save ") {
                            if let Some((hash, path)) = rest.split_once(' ') {
                                let hash = hash.to_owned();
                                let path = PathBuf::from(path);
                                let cancel = shutdown.child_token();
                                let worker_cancel = cancel.clone();
                                let task = scope.spawn(move || {
                                    if worker_cancel.is_cancelled() {
                                        return Err(irmind_app::AppError::Cancelled);
                                    }
                                    let bytes = engine.evidence_store.get_evidence(id, &hash)?;
                                    if worker_cancel.is_cancelled() {
                                        return Err(irmind_app::AppError::Cancelled);
                                    }
                                    io_ops.save_evidence(&path, &bytes).map_err(|_| {
                                        irmind_app::AppError::Storage("evidence save failed".into())
                                    })?;
                                    Ok(format!("Saved evidence {hash}"))
                                });
                                active = Some((cancel, task, "Save evidence"));
                            } else {
                                messages.push("Usage: /evidence-save <hash> <path>".into());
                            }
                        } else if let Some(hash) = prompt.strip_prefix("/evidence ") {
                            match engine.evidence_store.get_evidence(id, hash) {
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
                        } else if model.is_some() {
                            messages.push(format!("Analyst: {prompt}"));
                            let cancel = shutdown.child_token();
                            let worker_cancel = cancel.clone();
                            let task = scope
                                .spawn(move || workflow.investigate(id, &prompt, &worker_cancel));
                            active = Some((cancel, task, "IRMind"));
                        } else {
                            messages.push("No LLM selected. Launch with --llm-module after approval, or use case commands without a model.".into());
                        }
                        if messages.len() > 30 {
                            messages.drain(..messages.len() - 30);
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some((cancel, task, label)) = active {
            cancel.cancel();
            if let Ok(Err(irmind_app::AppError::Cancelled)) = task.join() {
                engine.record_cancellation(id, cancelled_operation(label))?;
            }
        }
        Ok(())
    })
}
