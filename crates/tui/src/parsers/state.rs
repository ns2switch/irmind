use super::{DefinitionStatus, Event, KeyCode, KeyModifiers, Result, event};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    None,
    Back,
    Palette,
    Quit,
    Preview,
    PrepareInstall,
    Install,
    Deactivate,
    Restore,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Screen {
    List,
    Install,
    Test,
    ConfirmInstall,
    ConfirmDeactivate,
    ConfirmRestore,
    Preview,
}

pub(super) struct State {
    pub(super) statuses: Vec<DefinitionStatus>,
    pub(super) selected: usize,
    pub(super) option: usize,
    pub(super) screen: Screen,
    pub(super) fields: [String; 2],
    pub(super) field: usize,
    pub(super) contents: String,
    pub(super) notice: String,
    pub(super) preview: String,
    pub(super) scroll: u16,
    pub(super) confirm_exit: bool,
    confirmation_input: String,
    pub(super) action_input: String,
}
impl State {
    pub(super) fn new(command: &str) -> Self {
        let mut state = Self {
            statuses: Vec::new(),
            selected: 0,
            option: 0,
            screen: Screen::List,
            fields: Default::default(),
            field: 0,
            contents: String::new(),
            notice: "Definitions are experimental. Only signed, validated definitions are active."
                .into(),
            preview: String::new(),
            scroll: 0,
            confirm_exit: false,
            confirmation_input: String::new(),
            action_input: String::new(),
        };
        if let Some(arguments) = command.strip_prefix("/parsers test") {
            state.screen = Screen::Test;
            if let Some((definition, file)) = arguments.trim().split_once(' ') {
                state.fields = [definition.into(), file.into()];
            }
        }
        state
    }
    pub(super) fn selected_id(&self) -> String {
        self.statuses
            .get(self.selected)
            .map_or_else(String::new, |item| item.id.clone())
    }
    pub(super) fn prepared(&mut self, result: Result<(String, String)>, action: Action) {
        match result {
            Ok((contents, preview)) => {
                self.contents = contents;
                self.preview = preview;
                self.scroll = 0;
                self.option = 0;
                self.screen = if action == Action::Preview {
                    Screen::Preview
                } else {
                    Screen::ConfirmInstall
                };
                self.notice.clear();
            }
            Err(error) => self.notice = format!("{error}. Correct the form and retry."),
        }
    }
    pub(super) fn event(&mut self, event: Event) -> Action {
        if let Event::Paste(text) = event {
            if matches!(self.screen, Screen::Install | Screen::Test) {
                for ch in text.chars().filter(|ch| !ch.is_control()) {
                    self.insert(ch);
                }
            }
            return Action::None;
        }
        let Event::Key(key) = event else {
            return Action::None;
        };
        if key.kind == event::KeyEventKind::Release {
            return Action::None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if key.code == KeyCode::Char('k') {
                return Action::Palette;
            }
            if key.code == KeyCode::Char('c') {
                self.confirm_exit = true;
                return Action::None;
            }
            if key.code == KeyCode::Char('u') {
                self.fields[self.field].clear();
                return Action::None;
            }
            return Action::None;
        }
        if self.confirm_exit {
            match key.code {
                KeyCode::Enter => return Action::Quit,
                KeyCode::Esc => self.confirm_exit = false,
                _ => {}
            }
            return Action::None;
        }
        if key.code == KeyCode::Esc {
            if self.screen == Screen::List {
                return Action::Back;
            }
            self.screen = Screen::List;
            self.notice.clear();
            self.option = 0;
            return Action::None;
        }
        match self.screen {
            Screen::List => self.list_key(key.code),
            Screen::Install | Screen::Test => self.form_key(key.code),
            Screen::ConfirmInstall | Screen::ConfirmDeactivate | Screen::ConfirmRestore => {
                self.confirm_key(key.code)
            }
            Screen::Preview => {
                match key.code {
                    KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
                    KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
                    _ => {}
                }
                Action::None
            }
        }
    }
    fn insert(&mut self, ch: char) {
        if !ch.is_control() && self.fields[self.field].len() + ch.len_utf8() <= 4096 {
            self.fields[self.field].push(ch);
        }
    }
    fn form_key(&mut self, key: KeyCode) -> Action {
        match key {
            KeyCode::Tab | KeyCode::BackTab if self.screen == Screen::Test => {
                self.field = 1 - self.field;
            }
            KeyCode::Char(ch) => self.insert(ch),
            KeyCode::Backspace => {
                self.fields[self.field].pop();
            }
            KeyCode::Enter => {
                return if self.screen == Screen::Test {
                    Action::Preview
                } else {
                    Action::PrepareInstall
                };
            }
            _ => {}
        }
        Action::None
    }
    fn list_key(&mut self, key: KeyCode) -> Action {
        match key {
            KeyCode::Char(ch) if !ch.is_control() && self.action_input.len() < 32 => {
                self.action_input.push(ch);
            }
            KeyCode::Backspace => {
                self.action_input.pop();
            }
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                self.selected = (self.selected + 1).min(self.statuses.len().saturating_sub(1));
            }
            KeyCode::Tab => self.option = (self.option + 1) % 4,
            KeyCode::BackTab => self.option = (self.option + 3) % 4,
            KeyCode::Enter => {
                if !self.action_input.is_empty() {
                    let Ok(selected) = self.action_input.parse::<usize>() else {
                        self.notice = "Choose an action from 1 to 4, then press Enter.".into();
                        return Action::None;
                    };
                    if !(1..=4).contains(&selected) {
                        self.notice = "Choose an action from 1 to 4, then press Enter.".into();
                        return Action::None;
                    }
                    self.option = selected - 1;
                    self.action_input.clear();
                }
                self.field = 0;
                self.option = self.option.min(3);
                self.screen = match self.option {
                    0 => Screen::Install,
                    1 => Screen::Test,
                    2 => Screen::ConfirmDeactivate,
                    _ => Screen::ConfirmRestore,
                };
                if matches!(
                    self.screen,
                    Screen::ConfirmDeactivate | Screen::ConfirmRestore
                ) {
                    self.preview = format!(
                        "{} {}?\nThis records a signed global operation and restarts the session. Historical definitions remain available for verified reconstruction.",
                        if self.screen == Screen::ConfirmDeactivate {
                            "Deactivate"
                        } else {
                            "Restore approved file for"
                        },
                        self.selected_id()
                    );
                }
                self.option = 0;
            }
            _ => {}
        }
        Action::None
    }
    fn confirm_key(&mut self, key: KeyCode) -> Action {
        match key {
            KeyCode::Up | KeyCode::Down => self.option = 1 - self.option,
            KeyCode::Char('1') => {
                self.confirmation_input = "1".into();
                self.option = 0;
            }
            KeyCode::Char('2') => {
                self.confirmation_input = "2".into();
                self.option = 1;
            }
            KeyCode::Enter => {
                let approved = if self.confirmation_input == "2" {
                    true
                } else if self.confirmation_input == "1" {
                    false
                } else {
                    self.option == 1
                };
                self.confirmation_input.clear();
                if approved {
                    return match self.screen {
                        Screen::ConfirmInstall => Action::Install,
                        Screen::ConfirmDeactivate => Action::Deactivate,
                        _ => Action::Restore,
                    };
                }
                self.screen = Screen::List;
            }
            _ => {}
        }
        Action::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(state: &mut State, code: KeyCode) -> Action {
        state.event(Event::Key(crossterm::event::KeyEvent::new(
            code,
            KeyModifiers::NONE,
        )))
    }
    #[test]
    fn preview_forms_preserve_slashes_and_pasted_paths_without_executing_commands() {
        let mut state = State::new("/parsers test");
        state.event(Event::Paste("/synthetic/definition.toml\n".into()));
        key(&mut state, KeyCode::Tab);
        for ch in "/synthetic/events.json".chars() {
            key(&mut state, KeyCode::Char(ch));
        }
        assert_eq!(
            state.fields,
            ["/synthetic/definition.toml", "/synthetic/events.json"]
        );
        assert_eq!(key(&mut state, KeyCode::Enter), Action::Preview);
        state.prepared(Err(anyhow::anyhow!("invalid definition")), Action::Preview);
        assert_eq!(state.fields[0], "/synthetic/definition.toml");
        assert!(state.notice.contains("retry"));
    }
    #[test]
    fn install_requires_explicit_confirmation_and_ctrl_c_requires_enter() {
        let mut state = State::new("/parsers");
        assert_eq!(key(&mut state, KeyCode::Enter), Action::None);
        assert_eq!(key(&mut state, KeyCode::Enter), Action::PrepareInstall);
        state.prepared(
            Ok(("synthetic".into(), "Install?".into())),
            Action::PrepareInstall,
        );
        assert_eq!(key(&mut state, KeyCode::Enter), Action::None);
        state.prepared(
            Ok(("synthetic".into(), "Install?".into())),
            Action::PrepareInstall,
        );
        assert_eq!(key(&mut state, KeyCode::Char('2')), Action::None);
        assert_eq!(key(&mut state, KeyCode::Enter), Action::Install);
        state.event(Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
        )));
        assert_eq!(key(&mut state, KeyCode::Esc), Action::None);
        assert!(!state.confirm_exit);
    }
}
