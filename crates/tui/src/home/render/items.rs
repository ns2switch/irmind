use super::{
    Engine, HomeState, ListItem, LlmPort, Mode, ModuleStatus, Result, case, hex, model, sha256,
};
use crate::home::SettingsSection;
use crate::home::module_catalog::{self, DisplayStatus};
use crate::theme::Theme;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use secrecy::ExposeSecret as _;

pub(super) fn home_items(
    state: &HomeState,
    engine: &Engine<'_>,
    modules: &[ModuleStatus],
    model: Option<&dyn LlmPort>,
    new_analyst_key: bool,
) -> Result<Vec<ListItem<'static>>> {
    let fingerprint = hex(&sha256(&engine.signer.public_key()));
    let safe = |value: &str| -> Result<String> { Ok(engine.guard.screen(value)?.text) };
    let escaped = |value: &str| -> Result<String> { Ok(case::escape_display(value)) };
    let model_descriptor = model.map(LlmPort::descriptor);
    let content = match state.mode {
        Mode::List => case_items(state, engine)?,
        Mode::Settings => settings_items(state, modules, model_descriptor.as_deref(), &safe)?,
        Mode::New => Vec::new(),
        Mode::Model => model_items(state, &escaped)?,
        Mode::Modules => module_items(state, modules, &escaped)?,
        Mode::Config => vec![
            ListItem::new(format!(
                "Resume last case: {}",
                if state.resume_last_case.enabled() {
                    "on"
                } else {
                    "off"
                }
            )),
            ListItem::new(format!(
                "Mouse capture: {}",
                if state.ui_selection.mouse_capture {
                    "on"
                } else {
                    "off"
                }
            )),
            ListItem::new(format!("Theme: {}", state.theme_choice)),
        ],
        Mode::Keystore => keystore_items(state),
        Mode::VerifyExport => ["Package path", "Expected analyst key fingerprint"]
            .iter()
            .enumerate()
            .map(|(index, label)| {
                ListItem::new(format!(
                    "{} {label}: {}",
                    if index == state.verify_field {
                        ">"
                    } else {
                        " "
                    },
                    case::escape_display(&state.verify_form[index])
                ))
            })
            .collect(),
        Mode::Setup => setup_items(&fingerprint, model.is_some(), new_analyst_key),
        Mode::Help => case::command_registry::help()
            .lines()
            .map(|line| Ok(ListItem::new(safe(line)?)))
            .collect::<Result<Vec<_>>>()?,
    };
    Ok(content)
}

pub(super) fn settings_items(
    state: &HomeState,
    modules: &[ModuleStatus],
    model: Option<&str>,
    safe: &impl Fn(&str) -> Result<String>,
) -> Result<Vec<ListItem<'static>>> {
    let theme = Theme::detect();
    SettingsSection::ALL
        .iter()
        .enumerate()
        .map(|(index, section)| {
            let (summary, warning) = section_status(*section, state, modules, model);
            let label = format!(
                "{} {}",
                if index == state.settings_selected {
                    ">"
                } else {
                    " "
                },
                section.label()
            );
            let status_style = if warning {
                theme.warning()
            } else {
                theme.muted()
            };
            let suffix = if summary.is_empty() {
                String::new()
            } else {
                format!("  ·  {summary}")
            };
            Ok(ListItem::new(Line::from(vec![
                Span::styled(
                    safe(&label)?,
                    if index == state.settings_selected {
                        theme.accent()
                    } else {
                        Style::default().fg(theme.text)
                    },
                ),
                Span::styled(safe(&suffix)?, status_style),
            ])))
        })
        .collect()
}

fn section_status(
    section: SettingsSection,
    state: &HomeState,
    modules: &[ModuleStatus],
    model: Option<&str>,
) -> (String, bool) {
    match section {
        SettingsSection::Model => (model_status(modules, model), false),
        SettingsSection::Connectors => connector_status(modules),
        SettingsSection::Keystore => (
            state.keystore.as_ref().map_or_else(
                || "unavailable".into(),
                |status| {
                    format!(
                        "signing: {} · secrets: {}",
                        status.signer_backend, status.secrets_backend
                    )
                },
            ),
            state.keystore.is_none(),
        ),
        SettingsSection::Preferences => (String::new(), false),
    }
}

fn model_status(modules: &[ModuleStatus], model: Option<&str>) -> String {
    let Some(model) = model else {
        return "No model".into();
    };
    let Some(module) = modules
        .iter()
        .find(|module| module.kind == crate::ModuleKind::Llm && module.selected && module.enabled)
    else {
        return model.into();
    };
    let provider = module
        .parameters
        .iter()
        .find(|parameter| parameter.name.ends_with("BASE_URL"))
        .and_then(|parameter| {
            model::PROVIDERS
                .iter()
                .find(|preset| preset.module == module.id && preset.url == parameter.value)
        })
        .map_or_else(|| module_catalog::label(&module.id), |preset| preset.name);
    let name = module
        .parameters
        .iter()
        .find(|parameter| parameter.name.ends_with("MODEL"))
        .map_or("", |parameter| parameter.value.as_str());
    if name.is_empty() {
        provider.into()
    } else {
        format!("{provider} · {name}")
    }
}

fn connector_status(modules: &[ModuleStatus]) -> (String, bool) {
    let connectors = module_catalog::connectors(modules);
    let active = connectors
        .iter()
        .filter(|(_, module)| module.selected && module.enabled)
        .count();
    let incomplete = connectors
        .iter()
        .filter(|(_, module)| module.selected && !module.enabled)
        .count();
    let summary = if incomplete > 0 {
        format!(
            "{active} of {} active · {incomplete} needs configuration",
            connectors.len()
        )
    } else {
        format!("{active} of {} active", connectors.len())
    };
    (summary, incomplete > 0)
}

pub(super) fn module_items(
    _state: &HomeState,
    modules: &[ModuleStatus],
    safe: &impl Fn(&str) -> Result<String>,
) -> Result<Vec<ListItem<'static>>> {
    let mut items = Vec::new();
    let theme = Theme::detect();
    let mut last_group = "";
    for (_, module) in module_catalog::connectors(modules) {
        let group = module_catalog::group(&module.id);
        if group != last_group {
            items.push(ListItem::new(safe(group)?).style(theme.muted()));
            last_group = group;
        }
        let status = module_catalog::status(module);
        let name = safe(&format!("  {}", module_catalog::label(&module.id)))?;
        let status_text = if status == DisplayStatus::Missing && !module.missing.is_empty() {
            format!("    {} · {}", status.label(), module.missing.join(", "))
        } else {
            format!("    {}", status.label())
        };
        let color = match status {
            DisplayStatus::Active => theme.success,
            DisplayStatus::Disabled | DisplayStatus::NotCompiled => theme.muted,
            DisplayStatus::Missing => theme.warning,
        };
        items.push(ListItem::new(vec![
            Line::styled(name, Style::default().fg(theme.text)),
            Line::styled(safe(&status_text)?, Style::default().fg(color)),
        ]));
    }
    Ok(items)
}

pub(super) fn module_detail(
    state: &HomeState,
    modules: &[ModuleStatus],
    safe: &impl Fn(&str) -> Result<String>,
) -> Result<Vec<String>> {
    let Some(module) = modules
        .get(state.module_selected)
        .filter(|module| module.kind == crate::ModuleKind::Connector)
    else {
        return Ok(vec!["Select a connector".into()]);
    };
    let mut rows = vec![
        module_catalog::label(&module.id).to_owned(),
        format!("Status: {}", module_catalog::status(module).label()),
        format!("Technical ID: {}", module.id),
    ];
    if module.compiled {
        rows.push(format!("Configuration: {}", module.configuration));
        if !module.missing.is_empty() {
            rows.push(format!("Missing: {}", module.missing.join(", ")));
        }
        rows.push("Parameters · Tab selects, Enter edits".into());
        for (index, parameter) in module.parameters.iter().enumerate() {
            rows.push(format!(
                "{} {} = {}{}{}",
                if state.ui_selection.parameter_focused && index == state.parameter_selected {
                    ">"
                } else {
                    " "
                },
                parameter.name,
                if parameter.value.is_empty() {
                    "<unset>"
                } else {
                    &parameter.value
                },
                if parameter.required {
                    " (required)"
                } else if parameter.defaulted {
                    " (default)"
                } else {
                    ""
                },
                if parameter.overridden {
                    " (override)"
                } else {
                    ""
                },
            ));
        }
        if !module.credentials.is_empty() {
            rows.push("Credentials · /settings keystore to manage".into());
            for name in &module.credentials {
                let present = state.keystore.as_ref().is_some_and(|status| {
                    status
                        .credentials
                        .iter()
                        .any(|item| item.name == *name && item.present)
                });
                rows.push(format!(
                    "  {name}: {}",
                    if present { "stored" } else { "missing" }
                ));
            }
        }
    } else {
        rows.push(format!("Feature: --features {}", module.id));
    }
    if let Some(change) = &state.pending_module_change {
        rows.push(format!("Confirm egress change: {}", change_summary(change)));
        rows.push(format!(
            "{} 1. Cancel   {} 2. Confirm and sign",
            if state.selected_option == 0 { ">" } else { " " },
            if state.selected_option == 1 { ">" } else { " " }
        ));
    }
    rows.iter().map(|row| safe(row)).collect()
}

fn change_summary(change: &irmind_app::ConfigChange) -> String {
    match change {
        irmind_app::ConfigChange::SelectLlm(id) => {
            format!("select LLM {}", id.as_deref().unwrap_or("none"))
        }
        irmind_app::ConfigChange::SetEnabled { module, enabled } => {
            format!("set {module} enabled={enabled}")
        }
        irmind_app::ConfigChange::SetValue {
            module,
            field,
            value,
        } => {
            format!("set {module}.{field}={value}")
        }
        irmind_app::ConfigChange::SetCertificateAuthority {
            module,
            path,
            sha256,
            ..
        } => format!("set {module} CA file={path}, SHA-256={sha256}"),
        irmind_app::ConfigChange::SetResumeLastCase(enabled) => {
            format!("resume recent case={enabled}")
        }
        irmind_app::ConfigChange::SetMouseCapture(enabled) => format!("mouse capture={enabled}"),
        irmind_app::ConfigChange::SetTheme(theme) => format!("theme={theme}"),
    }
}

fn case_items(state: &HomeState, engine: &Engine<'_>) -> Result<Vec<ListItem<'static>>> {
    let rows = state.visible();
    let safe = |value: &str| -> Result<String> { Ok(engine.guard.screen(value)?.text) };
    rows.iter()
        .enumerate()
        .map(|(index, row)| -> Result<ListItem<'_>> {
            let marker = if index == state.selected { ">" } else { " " };
            let at = i64::try_from(row.last_activity)
                .ok()
                .and_then(|at| chrono::DateTime::<chrono::Utc>::from_timestamp(at, 0))
                .map_or_else(
                    || "unknown".into(),
                    |at| at.format("%Y-%m-%d %H:%M UTC").to_string(),
                );
            Ok(ListItem::new(safe(&format!(
                "{marker} {}  ·  {}  ·  {}  ·  {}",
                row.title,
                row.severity,
                row.status.label(),
                at
            ))?))
        })
        .collect::<Result<Vec<_>>>()
}

pub(in crate::home) fn keystore_items(state: &HomeState) -> Vec<ListItem<'static>> {
    state.keystore.as_ref().map_or_else(Vec::new, |keystore| {
        let mut items = vec![
            ListItem::new(format!("Signer: {}", keystore.signer_backend)),
            ListItem::new(format!("Secrets: {}", keystore.secrets_backend)),
            ListItem::new(format!("Analyst key: {}", keystore.analyst_fingerprint)),
        ];
        if state.confirm_credential_delete {
            items.push(ListItem::new(format!(
                "Delete credential? {} 1. Cancel   {} 2. Delete (Enter confirms)",
                if state.selected_option == 0 { ">" } else { " " },
                if state.selected_option == 1 { ">" } else { " " }
            )));
        }
        if state.pending_migration.is_some() {
            items.push(ListItem::new(format!(
                "Migrate backend? {} 1. Cancel   {} 2. Migrate and sign (Enter confirms)",
                if state.selected_option == 0 { ">" } else { " " },
                if state.selected_option == 1 { ">" } else { " " }
            )));
        }
        items.extend(
            keystore
                .credentials
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    ListItem::new(format!(
                        "{} {}: {}",
                        if index == state.keystore_selected {
                            ">"
                        } else {
                            " "
                        },
                        item.name,
                        if item.present { "stored" } else { "missing" }
                    ))
                }),
        );
        items.push(ListItem::new("Actions"));
        for (index, label) in [
            "Add or replace selected credential",
            "Delete selected credential",
            "Change file passphrase",
            "Migrate signing backend",
            "Migrate secrets backend",
            "Restart session",
        ]
        .iter()
        .enumerate()
        {
            items.push(ListItem::new(format!(
                "{} {label}",
                if state.ui_selection.keystore_action_focus
                    && state.keystore_action_selected == index
                {
                    ">"
                } else {
                    " "
                }
            )));
        }
        items
    })
}

fn setup_items(
    fingerprint: &str,
    has_model: bool,
    new_analyst_key: bool,
) -> Vec<ListItem<'static>> {
    vec![
        ListItem::new(if new_analyst_key {
            "Signing key: created"
        } else {
            "Signing key: available"
        }),
        ListItem::new(format!("Analyst public-key fingerprint: {fingerprint}")),
        ListItem::new("Save this fingerprint outside this computer before investigating."),
        ListItem::new(if has_model {
            "LLM: explicitly selected"
        } else {
            "LLM: none selected; investigation is disabled"
        }),
        ListItem::new("Enter to choose an optional model, or Esc to continue without one."),
        ListItem::new("Use /settings to inspect configuration."),
        ListItem::new("Use /new to create a case; no CLI setup is required."),
    ]
}

pub(in crate::home) fn model_items(
    state: &HomeState,
    safe: &impl Fn(&str) -> Result<String>,
) -> Result<Vec<ListItem<'static>>> {
    let setup = &state.model_setup;
    let mut rows = Vec::new();
    match setup.step {
        model::ModelStep::Provider | model::ModelStep::AvailableModels => {
            rows.extend(model_choice_rows(setup));
        }
        model::ModelStep::Url => {
            rows.push("API URL (HTTPS, or HTTP on loopback; type to replace default):".into());
            rows.push(format!(
                "> {}{}",
                setup.url,
                if setup.url_edited { "" } else { " (default)" }
            ));
        }
        model::ModelStep::Name => {
            rows.push("Model name:".into());
            rows.push(format!("> {}", setup.name));
        }
        model::ModelStep::Key => {
            rows.push(
                "API key (stored in the selected SecretBackend; Enter skips if optional):".into(),
            );
            rows.push(format!(
                "> {}",
                "•".repeat(setup.key.expose_secret().chars().count().min(128))
            ));
        }
        model::ModelStep::ConfirmDiscovery => {
            rows.push(format!(
                "Contact {} at {} using the entered API key?",
                model::PROVIDERS[setup.provider].name,
                setup.url
            ));
            rows.push(
                "Only a model-list request or synthetic test text is sent; no case data.".into(),
            );
            rows.push(format!(
                "{} 1. Skip",
                if setup.selected_action == 0 { ">" } else { " " }
            ));
            rows.push(format!(
                "{} 2. Continue",
                if setup.selected_action == 1 { ">" } else { " " }
            ));
        }
        model::ModelStep::Review => {
            rows.extend(model_review_rows(setup));
        }
        model::ModelStep::ConfirmEgress => {
            rows.push(format!(
                "Enable {}? Case data may be sent to {}.",
                model::PROVIDERS[setup.provider].name,
                setup.url
            ));
            rows.push("The model remains disabled until you confirm this change.".into());
            rows.push(format!(
                "{} 1. Cancel",
                if setup.selected_action == 0 { ">" } else { " " }
            ));
            rows.push(format!(
                "{} 2. Enable and sign configuration",
                if setup.selected_action == 1 { ">" } else { " " }
            ));
        }
    }
    if !setup.notice.is_empty() {
        rows.push(format!("Status: {}", setup.notice));
    }
    rows.into_iter()
        .map(|row| Ok(ListItem::new(safe(&row)?)))
        .collect()
}

fn model_choice_rows(setup: &model::ModelSetup) -> Vec<String> {
    let mut rows = Vec::new();
    if setup.step == model::ModelStep::Provider {
        rows.push("Choose an AI model now, or continue without one.".to_owned());
        for (index, preset) in model::PROVIDERS.iter().enumerate() {
            let marker = if index == setup.provider { ">" } else { " " };
            rows.push(format!(
                "{marker} {}. {} — {}",
                index + 1,
                preset.name,
                preset.detail
            ));
        }
    } else {
        rows.push("Available models (Tab enters a model ID; Shift+Tab edits the URL):".into());
        for (index, name) in setup.models.iter().enumerate() {
            let marker = if index == setup.selected_model {
                ">"
            } else {
                " "
            };
            rows.push(format!("{marker} {}. {name}", index + 1));
        }
        if setup.models.is_empty() {
            rows.push(
                "Model list unavailable. Enter retries; Tab enters a model ID manually.".into(),
            );
        }
    }
    rows
}

fn model_review_rows(setup: &model::ModelSetup) -> Vec<String> {
    let mut rows = vec![
        format!(
            "Provider: {} · Model: {}",
            model::PROVIDERS[setup.provider].name,
            setup.name
        ),
        format!("Endpoint: {}", setup.url),
        "A remote provider may receive case data after you enable it.".into(),
    ];
    for (index, label) in [
        "Test connection with synthetic text",
        "Save and enable model",
        "Back",
    ]
    .iter()
    .enumerate()
    {
        rows.push(format!(
            "{} {}. {label}",
            if index == setup.selected_action {
                ">"
            } else {
                " "
            },
            index + 1
        ));
    }
    rows
}
