//! Analyst-only case inventory and typed, signed deletion confirmation.
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use irmind_app::{CancellationToken, CaseDeletionInventory, CaseId, Engine};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{io, time::Duration};
mod view;

pub(crate) enum Exit {
    Back(String),
    Quit,
}
#[derive(Default)]
struct Form {
    confirmation: String,
    reason: String,
    focus: usize,
    delete: bool,
    notice: String,
    option_input: String,
}
enum Action {
    Keep,
    Back,
    Sign,
}
impl Form {
    fn paste(&mut self, value: &str) {
        for ch in value.chars().filter(|ch| !ch.is_control()) {
            self.insert(ch);
        }
    }
    fn insert(&mut self, ch: char) {
        let (field, limit) = match self.focus {
            0 => (&mut self.confirmation, 200),
            1 => (&mut self.reason, 1024),
            _ => return,
        };
        if !ch.is_control() && field.len() + ch.len_utf8() <= limit {
            field.push(ch);
        }
    }
    fn key(&mut self, code: KeyCode, inventory: &CaseDeletionInventory) -> Action {
        match code {
            KeyCode::Esc => return Action::Back,
            KeyCode::Tab => self.focus = (self.focus + 1) % 3,
            KeyCode::BackTab => self.focus = (self.focus + 2) % 3,
            KeyCode::Left | KeyCode::Up if self.focus == 2 => self.delete = false,
            KeyCode::Right | KeyCode::Down if self.focus == 2 => self.delete = true,
            KeyCode::Char(ch)
                if self.focus == 2 && !ch.is_control() && self.option_input.len() < 4 =>
            {
                self.option_input.push(ch);
            }
            KeyCode::Char(ch) => self.insert(ch),
            KeyCode::Backspace => match self.focus {
                0 => {
                    self.confirmation.pop();
                }
                1 => {
                    self.reason.pop();
                }
                _ => {}
            },
            KeyCode::Enter => {
                if self.focus == 2 && !self.option_input.is_empty() {
                    match self.option_input.as_str() {
                        "1" => return Action::Back,
                        "2" => self.delete = true,
                        _ => {
                            self.notice = "Choose 1 or 2, then Enter.".into();
                            self.option_input.clear();
                            return Action::Keep;
                        }
                    }
                    self.option_input.clear();
                }
                let exact = self.confirmation == inventory.title
                    || self.confirmation == inventory.case_id.as_str();
                if self.focus == 2 && !self.delete {
                    return Action::Back;
                }
                if !exact {
                    self.notice = "Type the exact case title or identifier.".into();
                    self.focus = 0;
                } else if self.focus == 2 {
                    return Action::Sign;
                } else {
                    self.focus = 2;
                    self.delete = true;
                    self.notice = "Enter signs the deletion; Esc cancels.".into();
                }
            }
            _ => {}
        }
        Action::Keep
    }
}

type Screen = Terminal<CrosstermBackend<io::Stdout>>;
struct CancelOnDrop(Option<CancellationToken>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(token) = &self.0 {
            token.cancel();
        }
    }
}
fn wait_task<R>(
    terminal: &mut Screen,
    worker: std::thread::ScopedJoinHandle<'_, R>,
    cancel: &CancellationToken,
    shutdown: &CancellationToken,
    title: &str,
    message: &str,
) -> Result<R> {
    let mut cleanup = CancelOnDrop(Some(cancel.clone()));
    let mut confirm_exit = false;
    while !worker.is_finished() || confirm_exit {
        view::message(
            terminal,
            title,
            if confirm_exit {
                "Exit IRMind? Enter confirms; Esc cancels."
            } else {
                message
            },
        )?;
        if shutdown.is_cancelled() {
            cancel.cancel();
            confirm_exit = false;
        }
        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                confirm_exit = true;
            } else if confirm_exit {
                match key.code {
                    KeyCode::Enter => {
                        shutdown.cancel();
                        cancel.cancel();
                        confirm_exit = false;
                    }
                    KeyCode::Esc => confirm_exit = false,
                    _ => {}
                }
            } else if key.code == KeyCode::Esc {
                cancel.cancel();
            }
        }
    }
    cleanup.0 = None;
    worker.join().map_err(|_| {
        anyhow::anyhow!("Case cleanup worker stopped. Inspect /cases deleted before retrying.")
    })
}

enum Review {
    Sign(Form),
    Back,
    Quit,
}
fn review(
    terminal: &mut Screen,
    engine: &Engine<'_>,
    inventory: &CaseDeletionInventory,
    shutdown: &CancellationToken,
) -> Result<Review> {
    let mut form = Form::default();
    let mut confirm_exit = false;
    loop {
        if shutdown.is_cancelled() {
            return Ok(Review::Back);
        }
        view::form(
            terminal,
            &|text| {
                Ok(crate::case::escape_display(
                    &engine.guard.screen(text)?.text,
                ))
            },
            inventory,
            &form,
            confirm_exit,
        )?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        match event::read()? {
            Event::Paste(value) if !confirm_exit => form.paste(&value),
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    confirm_exit = true;
                    continue;
                }
                if confirm_exit {
                    match key.code {
                        KeyCode::Enter => return Ok(Review::Quit),
                        KeyCode::Esc => confirm_exit = false,
                        _ => {}
                    }
                    continue;
                }
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('u') {
                    match form.focus {
                        0 => form.confirmation.clear(),
                        1 => form.reason.clear(),
                        _ => {}
                    }
                    continue;
                }
                match form.key(key.code, inventory) {
                    Action::Keep => {}
                    Action::Back => return Ok(Review::Back),
                    Action::Sign => return Ok(Review::Sign(form)),
                }
            }
            _ => {}
        }
    }
}

pub(crate) fn run(
    terminal: &mut Screen,
    engine: &Engine<'_>,
    id: &CaseId,
    shutdown: &CancellationToken,
) -> Result<Exit> {
    std::thread::scope(|scope| -> Result<Exit> {
        let prepare_cancel = shutdown.child_token();
        let worker_cancel = prepare_cancel.clone();
        let worker = scope.spawn(move || engine.prepare_case_deletion(id, &worker_cancel));
        let prepared = match wait_task(
            terminal,
            worker,
            &prepare_cancel,
            shutdown,
            "Preparing deletion inventory…",
            "Checking the signed chain, ownership and exclusive case lock. Esc cancels.",
        )? {
            Ok(value) => value,
            Err(error) => {
                return Ok(Exit::Back(format!(
                    "Cannot delete case: {error}. Nothing was deleted."
                )));
            }
        };
        let form = match review(terminal, engine, prepared.inventory(), shutdown)? {
            Review::Back => {
                return Ok(Exit::Back(
                    "Deletion cancelled; nothing was deleted.".into(),
                ));
            }
            Review::Quit => return Ok(Exit::Quit),
            Review::Sign(value) => value,
        };
        let reason = (!form.reason.is_empty()).then_some(form.reason);
        let worker =
            scope.spawn(move || engine.delete_prepared_case(prepared, &form.confirmation, reason));
        let result = wait_task(
            terminal,
            worker,
            &prepare_cancel,
            shutdown,
            "Signing and deleting case…",
            "The signed tombstone is retained. Interrupted cleanup resumes at startup. Esc requests cancellation.",
        )?;
        Ok(Exit::Back(match result {
            Ok(p) => p.message,
            Err(error) => format!(
                "Case deletion failed: {error}. Retry from /case delete; signed cleanup is listed in /cases deleted."
            ),
        }))
    })
}

fn audit_lines(
    receipts: &[irmind_app::CaseDeletedV1],
    progress: &[irmind_app::DeletionProgress],
    offset: usize,
) -> Vec<String> {
    let mut lines = vec!["Signed tombstones only. Deletion is not secure erasure.".to_owned()];
    if receipts.is_empty() {
        lines.push("No deleted cases.".into());
    }
    for receipt in receipts.iter().skip(offset).take(8) {
        let pending = progress
            .iter()
            .find(|p| p.case_id.as_str() == receipt.case_id && !p.complete);
        lines.push(format!("{} · {} · {}\nCreated UTC epoch {} · deleted {} · {} entries · {} sources\nTail {}\n{} owned bytes · {} shared bytes · {} metadata bytes\nReason: {}", receipt.title, receipt.case_id, if pending.is_some() {"cleanup pending"} else {"deleted"}, receipt.created_at,receipt.deleted_at,receipt.entry_count, receipt.source_count,receipt.last_chain_hash,receipt.owned_file_bytes,receipt.shared_blob_bytes,receipt.logical_metadata_bytes,receipt.reason.as_deref().unwrap_or("none")));
        if let Some(p) = pending {
            lines.push(p.message.clone());
        }
    }
    lines
}

fn retry_cleanup(
    terminal: &mut Screen,
    engine: &Engine<'_>,
    shutdown: &CancellationToken,
) -> Result<Vec<irmind_app::DeletionProgress>> {
    let cancel = shutdown.child_token();
    std::thread::scope(|scope| {
        let worker_cancel = cancel.clone();
        let worker = scope.spawn(move || engine.resume_case_deletions(&worker_cancel));
        Ok(wait_task(
            terminal,
            worker,
            &cancel,
            shutdown,
            "Retrying signed cleanup…",
            "Only authenticated deletion intents are resumed. Esc cancels.",
        )??)
    })
}

pub(crate) fn deleted(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    engine: &Engine<'_>,
    shutdown: &CancellationToken,
) -> Result<Exit> {
    let receipts = engine.deleted_cases()?;
    let mut progress = retry_cleanup(terminal, engine, shutdown)?;
    let mut offset = 0usize;
    let mut confirm_exit = false;
    loop {
        if shutdown.is_cancelled() {
            return Ok(Exit::Back(String::new()));
        }
        let lines = audit_lines(&receipts, &progress, offset);
        let safe = lines
            .iter()
            .map(|line| {
                engine
                    .guard
                    .screen(line)
                    .map(|v| super::case::escape_display(&v.text))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("\n\n");
        view::message(
            terminal,
            "Deleted cases · signed global audit",
            &format!(
                "{safe}\n\n{}",
                if confirm_exit {
                    "Exit IRMind? Enter confirms; Esc cancels."
                } else {
                    "↑/↓ scroll · Enter retry cleanup · Esc back"
                }
            ),
        )?;
        if !event::poll(Duration::from_millis(100))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                confirm_exit = true;
                continue;
            }
            if confirm_exit {
                match key.code {
                    KeyCode::Enter => return Ok(Exit::Quit),
                    KeyCode::Esc => confirm_exit = false,
                    _ => {}
                }
                continue;
            }
            match key.code {
                KeyCode::Esc => return Ok(Exit::Back(String::new())),
                KeyCode::Up | KeyCode::PageUp => offset = offset.saturating_sub(1),
                KeyCode::Down | KeyCode::PageDown => {
                    offset = (offset + 1).min(receipts.len().saturating_sub(1));
                }
                KeyCode::Enter => {
                    progress = retry_cleanup(terminal, engine, shutdown)?;
                }
                _ => {}
            }
        }
    }
}
#[cfg(test)]
mod tests;
