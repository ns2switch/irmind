use super::{HomeState, KeyCode, Mode, state::HomeAction};
use secrecy::{ExposeSecret as _, SecretString};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ModelStep {
    Provider,
    OllamaModels,
    Url,
    Name,
    Key,
    Review,
    ConfirmEgress,
}

#[derive(Clone)]
pub(crate) struct ModelDraft {
    pub provider: &'static str,
    pub url: String,
    pub name: String,
    pub key: Option<SecretString>,
}

pub(super) struct ModelSetup {
    pub step: ModelStep,
    pub provider: usize,
    pub selected_model: usize,
    pub models: Vec<String>,
    pub url: String,
    pub name: String,
    pub key: SecretString,
    pub notice: String,
    pub selected_action: usize,
    pub url_edited: bool,
}

pub(super) const PROVIDERS: &[(&str, &str)] = &[
    ("Later", "No model is enabled"),
    (
        "Ollama local",
        "Runs on this device; HTTP or HTTPS loopback",
    ),
    ("OpenAI compatible", "Custom API endpoint"),
    ("Anthropic", "Remote API; case data may leave this device"),
    ("DeepSeek", "Remote API; case data may leave this device"),
    ("OpenRouter", "Remote API; case data may leave this device"),
];

impl ModelSetup {
    pub(super) fn new() -> Self {
        Self {
            step: ModelStep::Provider,
            provider: 0,
            selected_model: 0,
            models: Vec::new(),
            url: String::new(),
            name: String::new(),
            key: SecretString::from(String::new()),
            notice: String::new(),
            selected_action: 0,
            url_edited: false,
        }
    }

    fn provider_id(&self) -> &'static str {
        match self.provider {
            1 | 2 => "llm-openai-compatible",
            3 => "llm-anthropic",
            4 => "llm-deepseek",
            5 => "llm-openrouter",
            _ => "",
        }
    }

    pub(super) fn draft(&self) -> ModelDraft {
        ModelDraft {
            provider: self.provider_id(),
            url: self.url.clone(),
            name: self.name.clone(),
            key: (!self.key.expose_secret().is_empty()).then(|| self.key.clone()),
        }
    }

    fn choose_provider(&mut self) -> HomeAction {
        self.notice.clear();
        self.selected_action = 0;
        self.url_edited = false;
        self.name.clear();
        self.models.clear();
        self.key = SecretString::from(String::new());
        match self.provider {
            0 => HomeAction::None,
            1 => {
                self.url = "http://127.0.0.1:11434/v1/".into();
                HomeAction::DiscoverOllama
            }
            2 => {
                self.url = "https://api.openai.com/v1/".into();
                self.step = ModelStep::Url;
                HomeAction::None
            }
            3 => {
                self.url = "https://api.anthropic.com/".into();
                self.step = ModelStep::Url;
                HomeAction::None
            }
            4 => {
                self.url = "https://api.deepseek.com/".into();
                self.step = ModelStep::Url;
                HomeAction::None
            }
            _ => {
                self.url = "https://openrouter.ai/api/v1/".into();
                self.step = ModelStep::Url;
                HomeAction::None
            }
        }
    }
}

pub(super) fn update_model(state: &mut HomeState, key: KeyCode) -> HomeAction {
    let setup = &mut state.model_setup;
    match key {
        KeyCode::Esc => {
            setup.step = match setup.step {
                ModelStep::Provider => {
                    state.mode = Mode::List;
                    ModelStep::Provider
                }
                ModelStep::OllamaModels | ModelStep::Url => ModelStep::Provider,
                ModelStep::Name => ModelStep::Url,
                ModelStep::Key => ModelStep::Name,
                ModelStep::ConfirmEgress => ModelStep::Review,
                ModelStep::Review if setup.provider == 1 => ModelStep::OllamaModels,
                ModelStep::Review => ModelStep::Key,
            };
        }
        KeyCode::Tab if setup.step == ModelStep::OllamaModels => {
            setup.step = ModelStep::Url;
            setup.url_edited = false;
        }
        KeyCode::Up => move_selection(setup, false),
        KeyCode::Down => move_selection(setup, true),
        KeyCode::Backspace => match setup.step {
            ModelStep::Url => {
                setup.url.pop();
            }
            ModelStep::Name => {
                setup.name.pop();
            }
            ModelStep::Key => {
                let mut value = setup.key.expose_secret().to_string();
                value.pop();
                setup.key = SecretString::from(value);
            }
            _ => {
                state.input.pop();
            }
        },
        KeyCode::Char(ch) if !ch.is_control() => enter_text(state, ch),
        KeyCode::Enter => return advance(state),
        _ => {}
    }
    HomeAction::None
}

fn move_selection(setup: &mut ModelSetup, forward: bool) {
    let (selected, count) = match setup.step {
        ModelStep::Provider => (&mut setup.provider, PROVIDERS.len()),
        ModelStep::OllamaModels => (&mut setup.selected_model, setup.models.len()),
        ModelStep::Review => (&mut setup.selected_action, 3),
        ModelStep::ConfirmEgress => (&mut setup.selected_action, 2),
        _ => return,
    };
    *selected = if forward {
        (*selected + 1).min(count.saturating_sub(1))
    } else {
        selected.saturating_sub(1)
    };
}

fn enter_text(state: &mut HomeState, ch: char) {
    let setup = &mut state.model_setup;
    match setup.step {
        ModelStep::Url if setup.url.len() < 1024 => {
            if !setup.url_edited {
                setup.url.clear();
                setup.url_edited = true;
            }
            setup.url.push(ch);
        }
        ModelStep::Name if setup.name.len() < 200 => setup.name.push(ch),
        ModelStep::Key if setup.key.expose_secret().len() < 4096 => {
            let mut value = setup.key.expose_secret().to_string();
            value.push(ch);
            setup.key = SecretString::from(value);
        }
        ModelStep::Provider
        | ModelStep::OllamaModels
        | ModelStep::Review
        | ModelStep::ConfirmEgress
            if state.input.len() < 4 =>
        {
            state.input.push(ch);
        }
        _ => {}
    }
}

fn advance(state: &mut HomeState) -> HomeAction {
    if state.input.starts_with('/') {
        return super::state::execute_command(state);
    }
    let setup = &mut state.model_setup;
    apply_numeric_choice(setup, &state.input);
    state.input.clear();
    match setup.step {
        ModelStep::Provider if setup.provider == 0 => {
            state.mode = Mode::List;
            HomeAction::None
        }
        ModelStep::Provider => {
            let id = setup.provider_id();
            if state
                .modules
                .iter()
                .any(|item| item.id == id && item.compiled)
            {
                setup.choose_provider()
            } else {
                setup.notice = format!("Provider is not compiled; build with --features {id}");
                HomeAction::None
            }
        }
        ModelStep::OllamaModels if setup.models.is_empty() => HomeAction::DiscoverOllama,
        ModelStep::OllamaModels => {
            setup.name = setup.models[setup.selected_model].clone();
            setup.step = ModelStep::Review;
            HomeAction::None
        }
        ModelStep::Url
            if setup.url.starts_with("https://") || setup.url.starts_with("http://127.0.0.1:") =>
        {
            if setup.provider == 1 {
                setup.step = ModelStep::OllamaModels;
                HomeAction::DiscoverOllama
            } else {
                setup.step = ModelStep::Name;
                HomeAction::None
            }
        }
        ModelStep::Url => {
            setup.notice = "Use HTTPS, or HTTP on 127.0.0.1 only".into();
            HomeAction::None
        }
        ModelStep::Name if setup.name.trim().is_empty() => {
            setup.notice = "Enter a model name".into();
            HomeAction::None
        }
        ModelStep::Name => {
            setup.step = ModelStep::Key;
            HomeAction::None
        }
        ModelStep::Key => {
            setup.selected_action = 0;
            setup.step = ModelStep::Review;
            HomeAction::None
        }
        ModelStep::Review => review_action(setup),
        ModelStep::ConfirmEgress if setup.selected_action == 1 => {
            HomeAction::SaveModel(setup.draft())
        }
        ModelStep::ConfirmEgress => {
            setup.step = ModelStep::Review;
            HomeAction::None
        }
    }
}

fn apply_numeric_choice(setup: &mut ModelSetup, input: &str) {
    if let Ok(choice) = input.parse::<usize>() {
        match setup.step {
            ModelStep::Provider if choice < PROVIDERS.len() => setup.provider = choice,
            ModelStep::OllamaModels if choice > 0 && choice <= setup.models.len() => {
                setup.selected_model = choice - 1;
            }
            ModelStep::Review if (1..=3).contains(&choice) => setup.selected_action = choice - 1,
            ModelStep::ConfirmEgress if (1..=2).contains(&choice) => {
                setup.selected_action = choice - 1;
            }
            _ => {}
        }
    }
}

fn review_action(setup: &mut ModelSetup) -> HomeAction {
    match setup.selected_action {
        0 => HomeAction::ProbeModel(setup.draft()),
        1 if setup.provider == 1 => HomeAction::SaveModel(setup.draft()),
        1 => {
            setup.selected_action = 0;
            setup.step = ModelStep::ConfirmEgress;
            HomeAction::None
        }
        _ => {
            setup.step = ModelStep::Provider;
            HomeAction::None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend, widgets::List};

    fn screen(state: &HomeState) -> String {
        let rows = super::super::render::model_items(state, &|value| Ok(value.to_owned())).unwrap();
        let mut terminal = Terminal::new(TestBackend::new(96, 16)).unwrap();
        terminal
            .draw(|frame| frame.render_widget(List::new(rows), frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
                    .trim_end_matches(' ')
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn model_selection_starts_disabled_and_remote_key_is_masked_in_state() {
        let mut state = HomeState::new(Vec::new(), false);
        state.mode = Mode::Model;
        assert_eq!(state.model_setup.provider, 0);
        update_model(&mut state, KeyCode::Down);
        assert_eq!(state.model_setup.provider, 1);
        assert!(matches!(
            update_model(&mut state, KeyCode::Enter),
            HomeAction::None
        ));
        assert!(state.model_setup.notice.contains("not compiled"));
        assert!(matches!(
            state.model_setup.choose_provider(),
            HomeAction::DiscoverOllama
        ));
        state.model_setup.key = SecretString::from("previous-provider-key");
        state.model_setup.provider = 3;
        state.model_setup.choose_provider();
        assert!(state.model_setup.draft().key.is_none());
    }

    #[test]
    fn model_setup_has_versioned_terminal_snapshots() {
        let mut state = HomeState::new(Vec::new(), false);
        state.mode = Mode::Model;
        state.model_setup.provider = 1;
        state.model_setup.step = ModelStep::OllamaModels;
        state.model_setup.models = vec!["synthetic:latest".into()];
        insta::assert_snapshot!("ollama_available", screen(&state));
        state.model_setup.models.clear();
        state.model_setup.notice = "Ollama is not responding; start it with `ollama serve`".into();
        insta::assert_snapshot!("ollama_unavailable", screen(&state));
        state.model_setup.provider = 3;
        state.model_setup.step = ModelStep::Review;
        state.model_setup.url = "https://api.anthropic.com/".into();
        state.model_setup.name = "synthetic-model".into();
        state.model_setup.key = SecretString::from("demo-only-secret");
        state.model_setup.notice.clear();
        let remote = screen(&state);
        assert!(!remote.contains("demo-only-secret"));
        insta::assert_snapshot!("remote_model", remote);
        state.model_setup.step = ModelStep::ConfirmEgress;
        state.model_setup.selected_action = 0;
        insta::assert_snapshot!("remote_egress_confirmation", screen(&state));
    }
}
