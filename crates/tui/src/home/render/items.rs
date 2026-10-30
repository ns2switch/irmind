use super::{
    Engine, HomeState, ListItem, LlmPort, Mode, ModuleStatus, Result, case, hex, model, sha256,
};
use crate::theme::Theme;
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
    let content = match state.mode {
        Mode::List => case_items(state, engine)?,
        Mode::New => {
            const NAMES: [&str; 9] = [
                "Title",
                "Severity (low/medium/high/critical)",
                "Sources",
                "Accounts",
                "Projects",
                "Hosts",
                "Object prefixes (s3://, gs://, az://)",
                "From UTC",
                "To UTC",
            ];
            NAMES
                .iter()
                .enumerate()
                .map(|(index, label)| -> Result<ListItem<'_>> {
                    Ok(ListItem::new(safe(&format!(
                        "{} {label}: {}",
                        if index == state.form_field { ">" } else { " " },
                        state.form[index]
                    ))?))
                })
                .collect::<Result<Vec<_>>>()?
        }
        Mode::Model => model_items(state, &safe)?,
        Mode::Modules => module_items(state, modules, &safe)?,
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

fn module_items(
    state: &HomeState,
    modules: &[ModuleStatus],
    safe: &impl Fn(&str) -> Result<String>,
) -> Result<Vec<ListItem<'static>>> {
    let mut items = Vec::new();
    if let Some(change) = &state.pending_module_change {
        let summary = match change {
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
            } => format!("set {module}.{field}={value}"),
        };
        items.push(ListItem::new(safe(&format!(
            "Confirm egress change: {summary}"
        ))?));
        items.push(ListItem::new(format!(
            "{} 1. Cancel   {} 2. Confirm and sign (↑/↓, Enter, or number then Enter)",
            if state.selected_option == 0 { ">" } else { " " },
            if state.selected_option == 1 { ">" } else { " " }
        )));
    }
    if let Some(edit) = &state.module_edit {
        items.push(ListItem::new(safe(&format!(
            "Edit {}.{}: {}",
            edit.module, edit.field, edit.value
        ))?));
    }
    for (index, module) in modules.iter().enumerate() {
        let status = if !module.compiled {
            "not compiled"
        } else if module.selected {
            "selected"
        } else if module.enabled {
            "enabled"
        } else {
            "disabled"
        };
        let row = ListItem::new(safe(&format!(
            "{} {} · {}{} · {}",
            if index == state.module_selected {
                ">"
            } else {
                " "
            },
            module.id,
            status,
            if module.selection_overridden() {
                " (temporary override)"
            } else {
                ""
            },
            if module.compiled {
                module.configuration.clone()
            } else {
                format!("not compiled; build with --features {}", module.id)
            }
        ))?);
        items.push(if module.compiled {
            row
        } else {
            row.style(Theme::detect().muted())
        });
        if index == state.module_selected {
            items.extend(module_parameter_items(
                module,
                state.parameter_selected,
                safe,
            )?);
            if !module.credentials.is_empty() {
                items.push(ListItem::new(safe(&format!(
                    "   Credentials: {} (use /keystore to manage)",
                    module.credentials.join(", ")
                ))?));
            }
        }
    }
    Ok(items)
}

fn module_parameter_items(
    module: &ModuleStatus,
    selected: usize,
    safe: &impl Fn(&str) -> Result<String>,
) -> Result<Vec<ListItem<'static>>> {
    module
        .parameters
        .iter()
        .enumerate()
        .map(|(index, parameter)| {
            Ok(ListItem::new(safe(&format!(
                "   {} {} = {}{}{}",
                if index == selected { ">" } else { " " },
                parameter.name,
                if parameter.value.is_empty() {
                    "<unset>"
                } else {
                    &parameter.value
                },
                if parameter.required {
                    " (required)"
                } else {
                    ""
                },
                if parameter.overridden {
                    " (environment override)"
                } else {
                    ""
                },
            ))?))
        })
        .collect()
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

fn keystore_items(state: &HomeState) -> Vec<ListItem<'static>> {
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
        ListItem::new("Use /modules and /keystore to inspect configuration."),
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
        model::ModelStep::Provider => {
            rows.push("Choose an AI model now, or continue without one.".to_owned());
            for (index, (name, detail)) in model::PROVIDERS.iter().enumerate() {
                let marker = if index == setup.provider { ">" } else { " " };
                rows.push(format!("{marker} {}. {name} — {detail}", index + 1));
            }
        }
        model::ModelStep::OllamaModels => {
            rows.push("Installed Ollama models (Tab edits HTTP/HTTPS loopback URL):".into());
            for (index, name) in setup.models.iter().enumerate() {
                let marker = if index == setup.selected_model {
                    ">"
                } else {
                    " "
                };
                rows.push(format!("{marker} {}. {name}", index + 1));
            }
            if setup.models.is_empty() {
                rows.push("Ollama is unavailable. Start it with `ollama serve`, then press Enter to retry.".into());
            }
        }
        model::ModelStep::Url => {
            rows.push("API URL (HTTPS, or HTTP on loopback; type to replace default):".into());
            rows.push(format!("> {}", setup.url));
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
        model::ModelStep::Review => {
            rows.extend(model_review_rows(setup));
        }
        model::ModelStep::ConfirmEgress => {
            rows.push(format!(
                "Enable {}? Case data may be sent to {}.",
                model::PROVIDERS[setup.provider].0,
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

fn model_review_rows(setup: &model::ModelSetup) -> Vec<String> {
    let mut rows = vec![
        format!(
            "Provider: {} · Model: {}",
            model::PROVIDERS[setup.provider].0,
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
