use super::{
    ConfigChange, Engine, HomeState, KeyCode, ModuleStatus, WorkspaceIo, state::HomeAction,
};
use secrecy::{ExposeSecret as _, SecretString};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum ModelStep {
    Provider,
    AvailableModels,
    Url,
    Name,
    Key,
    ConfirmDiscovery,
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

pub(crate) fn save_configuration(
    io_ops: &dyn WorkspaceIo,
    engine: &Engine<'_>,
    modules: &[ModuleStatus],
    draft: &ModelDraft,
) -> anyhow::Result<()> {
    if !modules
        .iter()
        .any(|item| item.id == draft.provider && item.compiled)
    {
        anyhow::bail!("provider is not compiled into this binary");
    }
    let (model_field, key_field, base_field) = match draft.provider {
        "llm-openai-compatible" => ("IRMIND_MODEL", "IRMIND_LLM_API_KEY", "IRMIND_LLM_BASE_URL"),
        "llm-anthropic" => (
            "IRMIND_ANTHROPIC_MODEL",
            "ANTHROPIC_API_KEY",
            "IRMIND_ANTHROPIC_BASE_URL",
        ),
        "llm-deepseek" => (
            "IRMIND_DEEPSEEK_MODEL",
            "DEEPSEEK_API_KEY",
            "IRMIND_DEEPSEEK_BASE_URL",
        ),
        "llm-openrouter" => (
            "IRMIND_OPENROUTER_MODEL",
            "OPENROUTER_API_KEY",
            "IRMIND_OPENROUTER_BASE_URL",
        ),
        _ => anyhow::bail!("unknown model provider"),
    };
    if let Some(key) = &draft.key {
        io_ops.put_credential(key_field, key)?;
    }
    for (field, value) in [(base_field, &draft.url), (model_field, &draft.name)] {
        io_ops.change_module_configuration(
            engine,
            ConfigChange::SetValue {
                module: draft.provider.into(),
                field: field.into(),
                value: value.clone(),
            },
            true,
        )?;
    }
    io_ops.change_module_configuration(
        engine,
        ConfigChange::SelectLlm(Some(draft.provider.into())),
        true,
    )?;
    Ok(())
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
    discovery: RemoteProbe,
}

#[derive(Clone, Copy)]
enum RemoteProbe {
    List,
    Test,
}

pub(super) struct ProviderPreset {
    pub name: &'static str,
    pub detail: &'static str,
    pub module: &'static str,
    pub url: &'static str,
}

pub(super) const PROVIDERS: &[ProviderPreset] = &[
    ProviderPreset {
        name: "Ollama",
        detail: "Local · 127.0.0.1:11434",
        module: "llm-openai-compatible",
        url: "http://127.0.0.1:11434/v1/",
    },
    ProviderPreset {
        name: "LM Studio",
        detail: "Local · 127.0.0.1:1234",
        module: "llm-openai-compatible",
        url: "http://127.0.0.1:1234/v1/",
    },
    ProviderPreset {
        name: "vLLM",
        detail: "Local · 127.0.0.1:8000",
        module: "llm-openai-compatible",
        url: "http://127.0.0.1:8000/v1/",
    },
    ProviderPreset {
        name: "OpenAI",
        detail: "Remote · API key required",
        module: "llm-openai-compatible",
        url: "https://api.openai.com/v1/",
    },
    ProviderPreset {
        name: "OpenAI compatible",
        detail: "Remote custom endpoint",
        module: "llm-openai-compatible",
        url: "https://",
    },
    ProviderPreset {
        name: "Anthropic",
        detail: "Remote · API key required",
        module: "llm-anthropic",
        url: "https://api.anthropic.com/",
    },
    ProviderPreset {
        name: "DeepSeek",
        detail: "Remote · API key required",
        module: "llm-deepseek",
        url: "https://api.deepseek.com/",
    },
    ProviderPreset {
        name: "OpenRouter",
        detail: "Remote · API key required",
        module: "llm-openrouter",
        url: "https://openrouter.ai/api/v1/",
    },
    ProviderPreset {
        name: "Mistral",
        detail: "Remote · API key required",
        module: "llm-openai-compatible",
        url: "https://api.mistral.ai/v1/",
    },
    ProviderPreset {
        name: "Groq",
        detail: "Remote · API key required",
        module: "llm-openai-compatible",
        url: "https://api.groq.com/openai/v1/",
    },
    ProviderPreset {
        name: "Google Gemini",
        detail: "Remote · OpenAI-compatible API",
        module: "llm-openai-compatible",
        url: "https://generativelanguage.googleapis.com/v1beta/openai/",
    },
    ProviderPreset {
        name: "xAI",
        detail: "Remote · API key required",
        module: "llm-openai-compatible",
        url: "https://api.x.ai/v1/",
    },
    ProviderPreset {
        name: "Together",
        detail: "Remote · API key required",
        module: "llm-openai-compatible",
        url: "https://api.together.ai/v1/",
    },
    ProviderPreset {
        name: "Later",
        detail: "No model is enabled",
        module: "",
        url: "",
    },
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
            discovery: RemoteProbe::List,
        }
    }

    fn provider_id(&self) -> &'static str {
        PROVIDERS
            .get(self.provider)
            .map_or("", |preset| preset.module)
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
        let Some(preset) = PROVIDERS.get(self.provider) else {
            return HomeAction::None;
        };
        self.url = preset.url.into();
        if self.provider == 0 {
            HomeAction::DiscoverModels
        } else {
            self.step = ModelStep::Url;
            HomeAction::None
        }
    }
}

pub(super) fn update_model(state: &mut HomeState, key: KeyCode) -> HomeAction {
    let setup = &mut state.model_setup;
    match key {
        KeyCode::Esc => {
            setup.step = match setup.step {
                ModelStep::Provider => {
                    state.mode = state.settings_return;
                    ModelStep::Provider
                }
                ModelStep::AvailableModels | ModelStep::Url => ModelStep::Provider,
                ModelStep::Name | ModelStep::Review => ModelStep::AvailableModels,
                ModelStep::Key => ModelStep::Url,
                ModelStep::ConfirmDiscovery => match setup.discovery {
                    RemoteProbe::List => ModelStep::Key,
                    RemoteProbe::Test => ModelStep::Review,
                },
                ModelStep::ConfirmEgress => ModelStep::Review,
            };
        }
        KeyCode::Tab if setup.step == ModelStep::AvailableModels => {
            setup.step = ModelStep::Name;
        }
        KeyCode::BackTab if setup.step == ModelStep::AvailableModels => {
            setup.step = ModelStep::Url;
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
        ModelStep::AvailableModels => (&mut setup.selected_model, setup.models.len()),
        ModelStep::Review => (&mut setup.selected_action, 3),
        ModelStep::ConfirmEgress | ModelStep::ConfirmDiscovery => (&mut setup.selected_action, 2),
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
        | ModelStep::AvailableModels
        | ModelStep::Review
        | ModelStep::ConfirmDiscovery
        | ModelStep::ConfirmEgress
            if state.input.len() < 4 =>
        {
            state.input.push(ch);
        }
        _ => {}
    }
}

fn advance(state: &mut HomeState) -> HomeAction {
    let setup = &mut state.model_setup;
    apply_numeric_choice(setup, &state.input);
    state.input.clear();
    match setup.step {
        ModelStep::Provider if setup.provider == PROVIDERS.len() - 1 => {
            state.mode = state.settings_return;
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
        ModelStep::AvailableModels if setup.models.is_empty() => HomeAction::DiscoverModels,
        ModelStep::AvailableModels => {
            setup.name = setup.models[setup.selected_model].clone();
            setup.step = ModelStep::Review;
            HomeAction::None
        }
        ModelStep::Url => advance_url(setup),
        ModelStep::Name if setup.name.trim().is_empty() => {
            setup.notice = "Enter a model name".into();
            HomeAction::None
        }
        ModelStep::ConfirmEgress if setup.selected_action == 1 => {
            HomeAction::SaveModel(setup.draft())
        }
        ModelStep::Name | ModelStep::ConfirmEgress => {
            setup.step = ModelStep::Review;
            HomeAction::None
        }
        ModelStep::Key => advance_key(setup),
        ModelStep::ConfirmDiscovery => advance_discovery(setup),
        ModelStep::Review => review_action(setup),
    }
}

fn advance_url(setup: &mut ModelSetup) -> HomeAction {
    match normalize_base_url(&setup.url) {
        Ok(url) => {
            setup.url = url;
            if is_local_url(&setup.url) {
                setup.step = ModelStep::AvailableModels;
                HomeAction::DiscoverModels
            } else {
                setup.step = ModelStep::Key;
                HomeAction::None
            }
        }
        Err(reason) => {
            setup.notice = reason.into();
            HomeAction::None
        }
    }
}

fn advance_key(setup: &mut ModelSetup) -> HomeAction {
    if setup.key.expose_secret().is_empty() {
        setup.notice = "Enter an API key before listing models".into();
    } else {
        setup.discovery = RemoteProbe::List;
        setup.selected_action = 0;
        setup.step = ModelStep::ConfirmDiscovery;
    }
    HomeAction::None
}

fn advance_discovery(setup: &mut ModelSetup) -> HomeAction {
    if setup.selected_action == 1 {
        setup.step = match setup.discovery {
            RemoteProbe::List => ModelStep::AvailableModels,
            RemoteProbe::Test => ModelStep::Review,
        };
        return match setup.discovery {
            RemoteProbe::List => HomeAction::DiscoverModels,
            RemoteProbe::Test => HomeAction::ProbeModel(setup.draft()),
        };
    }
    setup.step = match setup.discovery {
        RemoteProbe::List => ModelStep::Name,
        RemoteProbe::Test => ModelStep::Review,
    };
    HomeAction::None
}

pub(super) fn normalize_base_url(input: &str) -> Result<String, &'static str> {
    let value = input.trim();
    let (scheme, rest) = value
        .split_once("://")
        .ok_or("Enter a complete URL, including https://")?;
    if !matches!(scheme, "https" | "http") {
        return Err("Use HTTPS, or HTTP on loopback only");
    }
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |parts| parts);
    if authority.is_empty() || authority.contains(char::is_whitespace) {
        return Err("Enter a host without spaces");
    }
    if rest.contains(char::is_whitespace) || rest.contains(['?', '#', '@']) {
        return Err("URL cannot contain spaces, credentials, query or fragment");
    }
    if scheme == "http"
        && !["127.0.0.1", "[::1]"]
            .iter()
            .any(|host| authority == *host || authority.starts_with(&format!("{host}:")))
    {
        return Err("HTTP is allowed only on loopback");
    }
    let mut normalized = format!("{scheme}://{authority}/");
    let mut slash = true;
    for ch in path.chars() {
        if ch == '/' {
            if !slash {
                normalized.push('/');
            }
            slash = true;
        } else {
            normalized.push(ch);
            slash = false;
        }
    }
    if !normalized.ends_with('/') {
        normalized.push('/');
    }
    Ok(normalized)
}

fn apply_numeric_choice(setup: &mut ModelSetup, input: &str) {
    if let Ok(choice) = input.parse::<usize>() {
        match setup.step {
            ModelStep::Provider if (1..=PROVIDERS.len()).contains(&choice) => {
                setup.provider = choice - 1;
            }
            ModelStep::AvailableModels if choice > 0 && choice <= setup.models.len() => {
                setup.selected_model = choice - 1;
            }
            ModelStep::Review if (1..=3).contains(&choice) => setup.selected_action = choice - 1,
            ModelStep::ConfirmEgress | ModelStep::ConfirmDiscovery if (1..=2).contains(&choice) => {
                setup.selected_action = choice - 1;
            }
            _ => {}
        }
    }
}

fn review_action(setup: &mut ModelSetup) -> HomeAction {
    match setup.selected_action {
        0 if is_local_url(&setup.url) => HomeAction::ProbeModel(setup.draft()),
        0 => {
            setup.discovery = RemoteProbe::Test;
            setup.selected_action = 0;
            setup.step = ModelStep::ConfirmDiscovery;
            HomeAction::None
        }
        1 if is_local_url(&setup.url) => HomeAction::SaveModel(setup.draft()),
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

fn is_local_url(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    ["127.0.0.1", "[::1]"]
        .iter()
        .any(|host| authority == *host || authority.starts_with(&format!("{host}:")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::home::Mode;
    use ratatui::{Terminal, backend::TestBackend, widgets::List};

    #[test]
    fn url_normalization_collapses_path_slashes_and_rejects_unsafe_destinations() {
        assert_eq!(
            normalize_base_url("  https://api.deepseek.com//v1/// ").unwrap(),
            "https://api.deepseek.com/v1/"
        );
        for value in [
            "http://api.deepseek.com/",
            "http://localhost:1234/v1/",
            "https://user@api.deepseek.com/",
            "https://api.deepseek.com/?token=x",
            "https://api.deepseek.com/ space",
        ] {
            assert!(normalize_base_url(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn local_preset_edited_to_remote_requires_key_and_signed_egress_step() {
        let mut state = HomeState::new(Vec::new(), false);
        state.mode = Mode::Model;
        state.model_setup.provider = 0;
        state.model_setup.url = "https://remote.example.invalid/v1/".into();
        state.model_setup.step = ModelStep::Url;
        assert!(matches!(
            update_model(&mut state, KeyCode::Enter),
            HomeAction::None
        ));
        assert!(matches!(state.model_setup.step, ModelStep::Key));
        state.model_setup.key = SecretString::from("synthetic-key");
        update_model(&mut state, KeyCode::Enter);
        assert!(matches!(
            state.model_setup.step,
            ModelStep::ConfirmDiscovery
        ));
        update_model(&mut state, KeyCode::Enter);
        assert!(matches!(state.model_setup.step, ModelStep::Name));
        state.model_setup.name = "synthetic".into();
        update_model(&mut state, KeyCode::Enter);
        state.model_setup.selected_action = 1;
        assert!(matches!(
            update_model(&mut state, KeyCode::Enter),
            HomeAction::None
        ));
        assert!(matches!(state.model_setup.step, ModelStep::ConfirmEgress));
    }

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
        state.model_setup.provider = 0;
        assert!(matches!(
            state.model_setup.choose_provider(),
            HomeAction::DiscoverModels
        ));
        state.model_setup.key = SecretString::from("previous-provider-key");
        state.model_setup.provider = 5;
        state.model_setup.choose_provider();
        assert!(state.model_setup.draft().key.is_none());
        assert_eq!(PROVIDERS[0].name, "Ollama");
        assert_eq!(PROVIDERS[PROVIDERS.len() - 1].name, "Later");
        state.model_setup.step = ModelStep::Provider;
        apply_numeric_choice(&mut state.model_setup, PROVIDERS.len().to_string().as_str());
        assert_eq!(state.model_setup.provider, PROVIDERS.len() - 1);
    }

    #[test]
    fn model_setup_has_versioned_terminal_snapshots() {
        let mut state = HomeState::new(Vec::new(), false);
        state.mode = Mode::Model;
        state.model_setup.provider = 0;
        state.model_setup.step = ModelStep::AvailableModels;
        state.model_setup.models = vec!["synthetic:latest".into()];
        insta::assert_snapshot!("ollama_available", screen(&state));
        state.model_setup.models.clear();
        state.model_setup.notice = "Ollama is not responding; start it with `ollama serve`".into();
        insta::assert_snapshot!("ollama_unavailable", screen(&state));
        state.model_setup.provider = 5;
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
        state.model_setup.provider = 6;
        state.model_setup.step = ModelStep::Url;
        state.model_setup.url = "https://api.deepseek.com/".into();
        state.model_setup.url_edited = false;
        insta::assert_snapshot!("deepseek_default_url", screen(&state));
    }
}
