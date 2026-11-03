use super::CaseRuntime;
use crate::case::state::{CaseMessage, update};
use crate::case::{CaseExit, KeyCode, KeyModifiers, Result, demo_guide::Effect};
use std::time::Instant;

impl CaseRuntime<'_, '_, '_> {
    pub(super) fn presentation_tick(&mut self) -> Result<()> {
        if !self.io_ops.demo_mode() {
            return Ok(());
        }
        let size = self.terminal.size()?;
        let visible = size.width >= 100 && size.height >= 40;
        let busy = self.active.is_some()
            || self.state.confirmation.is_some()
            || self.state.parser_prompt.is_some()
            || self.state.time_prompt.is_some();
        let Some(guide) = self.state.demo_guide.as_mut() else {
            return Ok(());
        };
        let effect = guide.tick(Instant::now(), busy, visible);
        match effect {
            Effect::None => {}
            Effect::Error(message) => self.presentation_failed(message),
            Effect::Bind(template) => match self.bind_presentation_command(&template) {
                Ok(command) => {
                    if let Some(guide) = self.state.demo_guide.as_mut() {
                        guide.start_typing(command);
                    }
                    self.state.menu_open = false;
                    self.state.focus = crate::case::state::Focus::Composer;
                }
                Err(error) => self.presentation_failed(&error.to_string()),
            },
            Effect::Type(prefix) => self.state.input = prefix,
            Effect::Submit(command) => {
                if let Some(guide) = self.state.demo_guide.as_mut() {
                    guide.command_sent();
                }
                self.state.input = command;
                let action = update(
                    &mut self.state,
                    CaseMessage::Key(KeyCode::Enter, KeyModifiers::NONE, false),
                );
                if let Err(error) = self.apply_action(action) {
                    self.presentation_failed(&error.to_string());
                }
            }
            Effect::Finished => {
                self.state.conversation.reveal_latest();
                if let Some(guide) = self.state.demo_guide.as_mut() {
                    guide.action_finished();
                }
            }
            Effect::Next => {
                if let Some(guide) = self.state.demo_guide.as_mut() {
                    guide.next();
                }
            }
        }
        Ok(())
    }

    fn bind_presentation_command(&self, template: &str) -> Result<String> {
        match template {
            "$approve" => self
                .state
                .approvals
                .first()
                .map(|item| format!("/approve {}", item.id))
                .ok_or_else(|| anyhow::anyhow!("the expected signed approval is not available")),
            "$confirm" => self
                .state
                .findings
                .iter()
                .find(|item| !item.confirmed && !item.dismissed)
                .map(|item| format!("/confirm {}", item.id))
                .ok_or_else(|| anyhow::anyhow!("the expected proposed finding is not available")),
            _ => Ok(template.into()),
        }
    }

    pub(super) fn presentation_failed(&mut self, text: &str) {
        if let Some(guide) = self.state.demo_guide.as_mut() {
            guide.fail(text);
        }
    }

    pub(super) fn presentation_key(
        &mut self,
        code: KeyCode,
        modifiers: KeyModifiers,
    ) -> Option<bool> {
        let guide = self
            .state
            .demo_guide
            .as_mut()
            .filter(|guide| guide.active())?;
        if code == KeyCode::Esc
            || (code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL))
        {
            if let Some((cancel, _, _)) = &self.active {
                cancel.cancel();
            }
            self.shutdown.cancel();
            self.exit_to = CaseExit::Quit;
            return Some(true);
        }
        if guide.step() == 9 && matches!(code, KeyCode::Up | KeyCode::Down | KeyCode::Enter) {
            match code {
                KeyCode::Up => guide.final_option = guide.final_option.saturating_sub(1),
                KeyCode::Down => guide.final_option = (guide.final_option + 1).min(2),
                KeyCode::Enter => match guide.final_option {
                    0 => {
                        guide.hide();
                        self.state.messages.push("Demo exploration · sealed case · /help lists commands; /demo exit deletes this session.".into());
                    }
                    1 if !guide.show_real_case_help => guide.show_real_case_help = true,
                    _ => {
                        self.shutdown.cancel();
                        self.exit_to = CaseExit::Quit;
                        return Some(true);
                    }
                },
                _ => {}
            }
        } else {
            match code {
                KeyCode::Enter => guide.enter(),
                KeyCode::Backspace => guide.back(),
                KeyCode::Char(' ') => guide.pause_or_resume(),
                _ => {}
            }
        }
        Some(false)
    }
}
