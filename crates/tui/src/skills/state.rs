use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
use irmind_app::{CompiledSkill, SkillStatus};
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Screen {
    List,
    Path,
    Review,
    Inspect,
    Confirm,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Action {
    None,
    Back,
    Quit,
    Palette,
    Inspect,
    Prepare,
    Apply,
}
pub(super) struct State {
    pub rows: Vec<SkillStatus>,
    pub selected: usize,
    pub action: usize,
    pub screen: Screen,
    pub path: String,
    pub input: String,
    pub notice: String,
    pub preview: String,
    pub candidate: Option<CompiledSkill>,
    pub scroll: u16,
    pub option: usize,
    pub confirm_exit: bool,
    pub readonly: bool,
}
impl State {
    pub(super) fn new(readonly: bool) -> Self {
        Self {
            rows: Vec::new(),
            selected: 0,
            action: 0,
            screen: Screen::List,
            path: String::new(),
            input: String::new(),
            notice: String::new(),
            preview: String::new(),
            candidate: None,
            scroll: 0,
            option: 0,
            confirm_exit: false,
            readonly,
        }
    }
    pub(super) fn event(&mut self, event: Event) -> Action {
        if let Event::Paste(text) = event {
            for ch in text.chars().filter(|ch| !ch.is_control()) {
                self.insert(ch);
            }
            return Action::None;
        }
        let Event::Key(key) = event else {
            return Action::None;
        };
        if key.kind == KeyEventKind::Release {
            return Action::None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('c') => self.confirm_exit = true,
                KeyCode::Char('k') => return Action::Palette,
                KeyCode::Char('u') if self.screen == Screen::Path => self.path.clear(),
                _ => {}
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
            self.input.clear();
            self.candidate = None;
            return Action::None;
        }
        match self.screen {
            Screen::List => self.list_key(key.code),
            Screen::Path => match key.code {
                KeyCode::Enter => Action::Prepare,
                KeyCode::Backspace => {
                    self.path.pop();
                    Action::None
                }
                KeyCode::Char(ch) => {
                    self.insert(ch);
                    Action::None
                }
                _ => Action::None,
            },
            Screen::Review | Screen::Confirm => self.confirm_key(key.code),
            Screen::Inspect => {
                self.scroll_key(key.code);
                Action::None
            }
        }
    }
    fn insert(&mut self, ch: char) {
        let target = if self.screen == Screen::Path {
            &mut self.path
        } else {
            &mut self.input
        };
        let limit = if self.screen == Screen::Path {
            4096
        } else {
            16
        };
        if !ch.is_control() && target.len() + ch.len_utf8() <= limit {
            target.push(ch);
        }
    }
    fn scroll_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::PageUp => self.scroll = self.scroll.saturating_sub(10),
            KeyCode::PageDown => self.scroll = self.scroll.saturating_add(10),
            _ => {}
        }
    }
    fn list_key(&mut self, code: KeyCode) -> Action {
        match code {
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => {
                self.selected = (self.selected + 1).min(self.rows.len().saturating_sub(1));
            }
            KeyCode::Tab => self.action = (self.action + 1) % 4,
            KeyCode::BackTab => self.action = (self.action + 3) % 4,
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Char(ch) => self.insert(ch),
            KeyCode::Enter => {
                if !self.input.is_empty() {
                    let Some(action) = self
                        .input
                        .parse::<usize>()
                        .ok()
                        .filter(|n| (1..=4).contains(n))
                    else {
                        self.notice = "Choose an action from 1 to 4, then press Enter.".into();
                        return Action::None;
                    };
                    self.action = action - 1;
                    self.input.clear();
                }
                if self.action == 0 {
                    return Action::Inspect;
                }
                if self.readonly {
                    self.notice =
                        "Demo methods are read-only. Start a normal session to manage skills."
                            .into();
                    return Action::None;
                }
                self.option = 0;
                self.input.clear();
                if self.action == 1 {
                    self.screen = Screen::Path;
                } else {
                    self.screen = Screen::Confirm;
                }
            }
            _ => {}
        }
        Action::None
    }
    fn confirm_key(&mut self, code: KeyCode) -> Action {
        self.scroll_key(code);
        match code {
            KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::BackTab => {
                self.option = 1 - self.option;
            }
            KeyCode::Char(ch) => self.insert(ch),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                if !self.input.is_empty() {
                    match self.input.as_str() {
                        "1" => self.option = 0,
                        "2" => self.option = 1,
                        _ => {
                            self.notice = "Choose 1 or 2, then press Enter.".into();
                            return Action::None;
                        }
                    }
                    self.input.clear();
                }
                if self.option == 1 {
                    return Action::Apply;
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
    fn key(code: KeyCode) -> Event {
        Event::Key(crossterm::event::KeyEvent::new(code, KeyModifiers::NONE))
    }
    #[test]
    fn typed_numbers_require_enter_and_folder_paste_is_literal_and_bounded() {
        let mut state = State::new(false);
        assert!(matches!(state.event(key(KeyCode::Char('2'))), Action::None));
        assert!(state.screen == Screen::List);
        state.event(key(KeyCode::Enter));
        assert!(state.screen == Screen::Path);
        state.event(Event::Paste("examples/skills\n/test\u{1b}".into()));
        assert_eq!(state.path, "examples/skills/test");
        state.event(Event::Paste("x".repeat(8192)));
        assert_eq!(state.path.len(), 4096);
        assert!(matches!(state.event(key(KeyCode::Enter)), Action::Prepare));
        state.event(key(KeyCode::Esc));
        assert!(state.screen == Screen::List);
    }
    #[test]
    fn demo_management_is_read_only_and_exit_requires_confirmation() {
        let mut state = State::new(true);
        state.event(key(KeyCode::Char('2')));
        state.event(key(KeyCode::Enter));
        assert!(state.screen == Screen::List);
        assert!(state.notice.contains("read-only"));
        state.event(Event::Key(crossterm::event::KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
        )));
        assert!(state.confirm_exit);
        state.event(key(KeyCode::Esc));
        assert!(!state.confirm_exit);
        assert!(matches!(state.event(key(KeyCode::Esc)), Action::Back));
    }
    #[test]
    fn confirmation_can_be_scrolled_and_never_applies_a_single_keystroke() {
        let mut state = State::new(false);
        state.screen = Screen::Review;
        state.event(key(KeyCode::Char('2')));
        assert_eq!(state.option, 0);
        state.event(key(KeyCode::PageDown));
        assert_eq!(state.scroll, 10);
        assert!(matches!(state.event(key(KeyCode::Enter)), Action::Apply));
    }
}
