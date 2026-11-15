use super::{Action, KeyCode, Screen, SourceKind, State};
impl State {
    pub(in crate::skills) fn is_form(&self) -> bool {
        matches!(
            self.screen,
            Screen::Path | Screen::Catalog | Screen::Offline
        )
    }
    pub(super) fn form_value(&mut self) -> (&mut String, usize) {
        match self.screen {
            Screen::Catalog if self.field == 0 => (&mut self.catalog_name, 64),
            Screen::Catalog => (&mut self.catalog_tag, 64),
            Screen::Offline if self.field == 1 => (&mut self.catalog_name, 64),
            Screen::Offline if self.field == 2 => (&mut self.catalog_tag, 64),
            _ => (&mut self.path, 4096),
        }
    }
    pub(super) fn form_key(&mut self, key: KeyCode) -> Action {
        let count = match self.screen {
            Screen::Catalog => 2,
            Screen::Offline => 3,
            _ => 1,
        };
        match key {
            KeyCode::Enter => return Action::Prepare,
            KeyCode::Tab => self.field = (self.field + 1) % count,
            KeyCode::BackTab => self.field = (self.field + count - 1) % count,
            KeyCode::Backspace => {
                self.form_value().0.pop();
            }
            KeyCode::Char(ch) => self.insert(ch),
            _ => {}
        }
        Action::None
    }
    pub(super) fn source_key(&mut self, key: KeyCode) -> Action {
        let index = match self.source {
            SourceKind::Local => 0,
            SourceKind::Catalog => 1,
            SourceKind::Offline => 2,
        };
        match key {
            KeyCode::Down | KeyCode::Tab => self.source = source((index + 1) % 3),
            KeyCode::Up | KeyCode::BackTab => self.source = source((index + 2) % 3),
            KeyCode::Char(ch) => self.insert(ch),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                if !self.input.is_empty() {
                    let Some(choice) = self
                        .input
                        .parse::<usize>()
                        .ok()
                        .filter(|n| (1..=3).contains(n))
                    else {
                        self.notice = "Choose 1, 2 or 3, then press Enter.".into();
                        return Action::None;
                    };
                    self.source = source(choice - 1);
                    self.input.clear();
                }
                self.screen = match self.source {
                    SourceKind::Local => Screen::Path,
                    SourceKind::Catalog => Screen::Catalog,
                    SourceKind::Offline => Screen::Offline,
                };
                self.field = 0;
            }
            _ => {}
        }
        Action::None
    }
}
fn source(index: usize) -> SourceKind {
    match index {
        1 => SourceKind::Catalog,
        2 => SourceKind::Offline,
        _ => SourceKind::Local,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{Event, KeyEvent, KeyModifiers};
    fn event(code: KeyCode) -> Event {
        Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }
    #[test]
    fn slash_and_catalog_prefix_in_a_local_path_never_choose_a_network_source() {
        let mut state = State::new(false);
        state.screen = Screen::Path;
        state.event(Event::Paste("catalog:folder/https://literal".into()));
        assert_eq!(state.path, "catalog:folder/https://literal");
        assert!(state.source == SourceKind::Local);
        assert!(state.screen == Screen::Path);
    }
    #[test]
    fn offline_fields_have_separate_literal_values_and_tab_and_shift_tab_focus() {
        let mut state = State::new(false);
        state.screen = Screen::Source;
        state.event(event(KeyCode::Char('3')));
        state.event(event(KeyCode::Enter));
        assert!(state.screen == Screen::Offline);
        state.event(Event::Paste("downloads/release".into()));
        state.event(event(KeyCode::Tab));
        state.event(Event::Paste("community-triage".into()));
        state.event(event(KeyCode::Tab));
        state.event(Event::Paste("v1.2.3".into()));
        state.event(event(KeyCode::BackTab));
        assert_eq!(state.field, 1);
        assert_eq!(state.path, "downloads/release");
        assert_eq!(state.catalog_name, "community-triage");
        assert_eq!(state.catalog_tag, "v1.2.3");
        assert!(matches!(
            state.event(event(KeyCode::Enter)),
            Action::Prepare
        ));
    }
}
