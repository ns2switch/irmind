use super::{CaseRuntime, Confirmation, Result};
use crate::case::command_registry;
use crate::case::state::{CaseAction, CaseMessage, Focus, update};
use crate::case::{KeyCode, KeyModifiers};
use crossterm::event::{MouseEvent, MouseEventKind};

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn handle_paste(&mut self, value: &str) {
        if self.state.picker.is_some() || self.state.confirmation.is_some() {
            return;
        }
        let limit = if self.state.palette.is_some() {
            80
        } else {
            20_000
        };
        let target = self.state.palette.as_mut().unwrap_or(&mut self.state.input);
        for ch in value.replace("\r\n", "\n").replace('\r', "\n").chars() {
            if (ch == '\n' || !ch.is_control()) && target.len() + ch.len_utf8() <= limit {
                target.push(ch);
            }
        }
        if self.state.palette.is_none() {
            self.state.menu_open = self.state.input.starts_with('/');
        }
    }

    fn handle_navigation(&mut self, code: KeyCode, modifiers: KeyModifiers) -> bool {
        let page = self.state.conversation.viewport().saturating_sub(2).max(1);
        let page = isize::try_from(page).unwrap_or(isize::MAX);
        let shortcut = command_registry::shortcut_name(code, modifiers);
        if shortcut == Some("expand") && self.state.focus == Focus::Conversation {
            self.state.conversation.toggle_selected();
            return true;
        }
        let delta = match shortcut {
            Some("scroll-up") => Some(-page),
            Some("scroll-down") => Some(page),
            Some("half-up") => Some(-(page / 2).max(1)),
            Some("half-down") => Some((page / 2).max(1)),
            _ => None,
        };
        if let Some(delta) = delta {
            if self.state.confirmation.is_some()
                || self.state.picker.is_some()
                || self.state.palette.is_some()
            {
                self.state.overlay_scroll = self.state.overlay_scroll.saturating_add_signed(delta);
            } else if self.state.focus == Focus::Sidebar {
                self.state.sidebar_scroll = self.state.sidebar_scroll.saturating_add_signed(delta);
            } else {
                self.state.conversation.scroll_by(delta);
            }
            return true;
        }
        if self.state.focus == Focus::Conversation
            && self.state.palette.is_none()
            && self.state.confirmation.is_none()
        {
            return self.navigate_focused_card(code);
        }
        false
    }

    fn navigate_focused_card(&mut self, code: KeyCode) -> bool {
        if (self.state.input.is_empty()
            || self.state.input.bytes().all(|byte| byte.is_ascii_digit()))
            && let Some(id) = self
                .state
                .conversation
                .selected_approval()
                .map(str::to_owned)
            && self.approval_card_key(&id, code)
        {
            return true;
        }
        match code {
            KeyCode::Up => self.state.conversation.select_by(-1),
            KeyCode::Down => self.state.conversation.select_by(1),
            KeyCode::Enter if self.state.input.is_empty() => {
                self.state.conversation.toggle_selected();
            }
            _ => return false,
        }
        true
    }

    fn approval_card_key(&mut self, id: &str, code: KeyCode) -> bool {
        match code {
            KeyCode::Up => {
                self.state.approval_option = self.state.approval_option.saturating_sub(1);
            }
            KeyCode::Down => self.state.approval_option = (self.state.approval_option + 1).min(2),
            KeyCode::Enter => {
                if let Ok(choice) = self.state.input.parse::<usize>() {
                    self.state.approval_option = choice.saturating_sub(1).min(2);
                    self.state.input.clear();
                }
            }
            _ => return false,
        }
        if matches!(code, KeyCode::Up | KeyCode::Down) {
            return true;
        }
        match self.state.approval_option {
            0 => self.start_approval(id.to_owned()),
            1 | 2 => {
                self.state.input = format!(
                    "/{} {id} ",
                    if self.state.approval_option == 1 {
                        "deny"
                    } else {
                        "edit"
                    }
                );
                self.state.focus = Focus::Composer;
            }
            _ => {}
        }
        true
    }

    fn handle_menu(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<Option<bool>> {
        if !self.state.menu_open || self.state.palette.is_some() {
            return Ok(None);
        }
        let source = self
            .state
            .menu_query
            .as_deref()
            .unwrap_or(&self.state.input)
            .to_owned();
        let (command, prefix) = source
            .split_once(' ')
            .map_or((source.as_str(), None), |(command, prefix)| {
                (command, Some(prefix))
            });
        let options = self.menu_options(&source);
        match code {
            KeyCode::Esc => self.state.menu_open = false,
            KeyCode::Tab | KeyCode::BackTab => {
                if !options.is_empty() {
                    let started = self.state.menu_query.is_some();
                    if !started {
                        self.state.menu_query = Some(self.state.input.clone());
                    }
                    let forward = code == KeyCode::Tab && !modifiers.contains(KeyModifiers::SHIFT);
                    self.state.menu_selected = command_registry::cycle(
                        options.len(),
                        self.state.menu_selected,
                        started,
                        forward,
                    );
                    self.state.input = if prefix.is_some() {
                        format!("{command} {}", options[self.state.menu_selected])
                    } else {
                        format!("/{}", options[self.state.menu_selected])
                    };
                }
            }
            KeyCode::Up => self.state.menu_selected = self.state.menu_selected.saturating_sub(1),
            KeyCode::Down => {
                self.state.menu_selected =
                    (self.state.menu_selected + 1).min(options.len().saturating_sub(1));
            }
            KeyCode::Enter if !options.is_empty() => {
                let selected = &options[self.state.menu_selected.min(options.len() - 1)];
                let chosen = if prefix.is_some() {
                    format!("{command} {selected}")
                } else {
                    format!("/{selected}")
                };
                if prefix.is_some()
                    && !matches!(
                        command,
                        "/approve" | "/confirm" | "/evidence" | "/ingest" | "/module"
                    )
                {
                    self.state.input = chosen;
                    self.state.menu_open = false;
                    return Ok(Some(false));
                }
                self.state.menu_open = false;
                self.state.input = chosen;
                let action = update(
                    &mut self.state,
                    CaseMessage::Key(KeyCode::Enter, KeyModifiers::NONE, self.active.is_some()),
                );
                return self.apply_action(action).map(Some);
            }
            _ => return Ok(None),
        }
        Ok(Some(false))
    }

    fn menu_options(&self, source: &str) -> Vec<String> {
        if source.contains(' ') {
            let ids = self
                .modules
                .iter()
                .map(|module| module.id.clone())
                .collect::<Vec<_>>();
            let approvals = self
                .state
                .approvals
                .iter()
                .map(|item| item.id.clone())
                .collect::<Vec<_>>();
            let findings = self
                .state
                .findings
                .iter()
                .map(|item| item.id.clone())
                .collect::<Vec<_>>();
            command_registry::argument_candidates(
                source,
                &approvals,
                &findings,
                &self.state.hashes,
                &ids,
            )
        } else {
            command_registry::matches(source)
                .iter()
                .map(|item| item.name.to_owned())
                .collect()
        }
    }

    pub(super) fn handle_mouse(&mut self, mouse: MouseEvent) {
        let delta = match mouse.kind {
            MouseEventKind::ScrollUp => -3,
            MouseEventKind::ScrollDown => 3,
            _ => return,
        };
        if self.state.picker.is_some()
            || self.state.confirmation.is_some()
            || self.state.palette.is_some()
        {
            self.state.overlay_scroll = self.state.overlay_scroll.saturating_add_signed(delta);
        } else if self.state.sidebar_visible && self.state.focus == Focus::Sidebar {
            self.state.sidebar_scroll = self.state.sidebar_scroll.saturating_add_signed(delta);
        } else {
            self.state.conversation.scroll_by(delta);
        }
    }

    pub(super) fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<bool> {
        if self.state.confirm_exit == crate::ExitConfirmation::Pending {
            return match code {
                KeyCode::Enter => {
                    if let Some((cancel, _, _)) = &self.active {
                        cancel.cancel();
                    }
                    if self.io_ops.demo_mode() {
                        self.shutdown.cancel();
                    }
                    Ok(true)
                }
                KeyCode::Esc => {
                    self.state.confirm_exit = crate::ExitConfirmation::Inactive;
                    Ok(false)
                }
                _ => Ok(false),
            };
        }
        let shortcut = command_registry::shortcut_name(code, modifiers);
        if shortcut == Some("exit") {
            self.state.confirm_exit = crate::ExitConfirmation::Pending;
            self.state
                .messages
                .push("Exit IRMind? Enter confirms; Esc cancels.".into());
            return Ok(false);
        }
        if shortcut == Some("pause")
            && let Some((cancel, _, _)) = &self.active
        {
            cancel.cancel();
            self.state.menu_open = false;
            return Ok(false);
        }
        if shortcut == Some("palette") {
            self.state.palette = Some(String::new());
            self.state.picker = None;
            self.state.confirmation = None;
            return Ok(false);
        }
        if self.handle_navigation(code, modifiers) {
            return Ok(false);
        }
        if let Some(exit) = self.handle_menu(code, modifiers)? {
            return Ok(exit);
        }
        let Some(code) = self.handle_overlay_key(code)? else {
            return Ok(false);
        };
        if shortcut == Some("pause") {
            if let Some((cancel, _, _)) = &self.active {
                cancel.cancel();
                return Ok(false);
            }
            if self.state.focus != Focus::Composer {
                self.state.focus = Focus::Composer;
                return Ok(false);
            }
        }
        let action = update(
            &mut self.state,
            CaseMessage::Key(code, modifiers, self.active.is_some()),
        );
        self.apply_action(action)
    }

    fn apply_action(&mut self, action: CaseAction) -> Result<bool> {
        match action {
            CaseAction::None => {
                self.state.menu_open = self.state.input.starts_with('/');
                self.state.menu_selected = 0;
                self.state.menu_query = None;
                Ok(false)
            }
            CaseAction::Exit => Ok(true),
            CaseAction::Submit(prompt) => {
                self.state.menu_open = false;
                self.submit(prompt)
            }
        }
    }

    fn handle_overlay_key(&mut self, code: KeyCode) -> Result<Option<KeyCode>> {
        if let Some(mut query) = self.state.palette.take() {
            match code {
                KeyCode::Esc => return Ok(None),
                KeyCode::Backspace => {
                    query.pop();
                    self.state.palette = Some(query);
                    return Ok(None);
                }
                KeyCode::Char(ch) if query.len() < 80 => {
                    query.push(ch);
                    self.state.palette = Some(query);
                    return Ok(None);
                }
                KeyCode::Enter => {
                    self.state.input = command_registry::matches(&query)
                        .first()
                        .map_or_else(String::new, |command| format!("/{}", command.name));
                    return Ok(Some(KeyCode::Enter));
                }
                _ => {
                    self.state.palette = Some(query);
                    return Ok(None);
                }
            }
        }
        if self.state.picker.is_some() {
            return self.handle_picker_key(code);
        }
        if let Some(pending) = self.state.confirmation.take() {
            match code {
                KeyCode::Esc => return Ok(None),
                KeyCode::Up | KeyCode::Down => {
                    self.state.confirmation_option = 1 - self.state.confirmation_option;
                    self.state.confirmation = Some(pending);
                    return Ok(None);
                }
                KeyCode::Char(ch) if !ch.is_control() => {
                    if self.state.input.len() < 4 {
                        self.state.input.push(ch);
                    }
                    self.state.confirmation = Some(pending);
                    return Ok(None);
                }
                KeyCode::Enter => {}
                _ => {
                    self.state.confirmation = Some(pending);
                    return Ok(None);
                }
            }
            if let Ok(choice) = self.state.input.parse::<usize>()
                && (1..=2).contains(&choice)
            {
                self.state.confirmation_option = choice - 1;
            }
            self.state.input.clear();
            if self.state.confirmation_option == 1 {
                self.state.input = match &pending {
                    Confirmation::Seal(_, _) => "/seal".into(),
                    Confirmation::Export(command, _) | Confirmation::ObjectRead(command, _) => {
                        command.clone()
                    }
                };
                self.state.confirmed_action = Some(pending);
                return Ok(Some(KeyCode::Enter));
            }
            return Ok(None);
        }
        Ok(Some(code))
    }

    fn handle_picker_key(&mut self, code: KeyCode) -> Result<Option<KeyCode>> {
        let Some(mut browser) = self.state.picker.take() else {
            return Ok(Some(code));
        };
        match code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Up => browser.selected = browser.selected.saturating_sub(1),
            KeyCode::Down => {
                browser.selected =
                    (browser.selected + 1).min(browser.entries.len().saturating_sub(1));
            }
            KeyCode::Backspace => {
                if let Some(parent) = browser.current.parent() {
                    browser.current = parent.to_path_buf();
                    browser.refresh()?;
                }
            }
            KeyCode::Enter => {
                let selected = browser.selected_path();
                let metadata = std::fs::symlink_metadata(&selected)?;
                if metadata.file_type().is_symlink() {
                    self.state
                        .messages
                        .push("Symlink selection is not allowed".into());
                } else if metadata.is_dir() {
                    browser.current = selected;
                    browser.refresh()?;
                } else {
                    self.state.input = format!("/ingest {}", selected.to_string_lossy());
                    return Ok(Some(KeyCode::Enter));
                }
            }
            _ => {}
        }
        self.state.picker = Some(browser);
        Ok(None)
    }
}
