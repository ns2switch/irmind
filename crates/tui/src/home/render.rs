use super::{
    Backend, Block, Borders, CaseStatus, Color, Constraint, Engine, HomeState, Layout, Line, List,
    ListItem, LlmPort, Mode, Modifier, ModuleStatus, Paragraph, Result, Style, Terminal, Wrap,
    case, hex, sha256,
};
use ratatui::widgets::ListState;

pub(crate) fn render_home<B: Backend>(
    terminal: &mut Terminal<B>,
    state: &HomeState,
    engine: &Engine<'_>,
    modules: &[ModuleStatus],
    model: Option<&dyn LlmPort>,
    new_analyst_key: bool,
) -> Result<()>
where
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let safe = |value: &str| -> Result<String> { Ok(engine.guard.screen(value)?.text) };
    let content = home_items(state, engine, modules, model, new_analyst_key)?;
    let header = match state.mode {
        Mode::List | Mode::Search => " Cases ",
        Mode::New => " New case ",
        Mode::Modules => " Modules ",
        Mode::Keystore => " Keystore ",
        Mode::Setup => " First-run guide ",
        Mode::VerifyExport => " Verify exported package ",
    };
    let filter = state.status_filter.map_or("all", CaseStatus::label);
    let info = safe(&format!(
        "Search: {} | Filter: {filter} | {}",
        state.search, state.notice
    ))?;
    let mut list_state = ListState::default();
    if state.mode == Mode::Modules {
        let prefix = usize::from(state.pending_module_change.is_some())
            + usize::from(state.module_edit.is_some());
        let field_offset = state
            .modules
            .get(state.module_selected)
            .map_or(0, |module| {
                usize::from(!module.parameters.is_empty()) * (state.parameter_selected + 1)
            });
        list_state.select(Some(prefix + state.module_selected + field_offset));
    }
    terminal.draw(|frame| {
        let areas = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(frame.area());
        frame.render_widget(
            Paragraph::new("IRMind · incident workspace")
                .block(Block::default().borders(Borders::ALL)),
            areas[0],
        );
        frame.render_stateful_widget(
            List::new(content)
                .block(Block::default().title(header).borders(Borders::ALL))
                .highlight_style(Style::default().fg(Color::Yellow)),
            areas[1],
            &mut list_state,
        );
        frame.render_widget(
            Paragraph::new(info)
                .block(Block::default().borders(Borders::ALL))
                .wrap(Wrap { trim: false }),
            areas[2],
        );
        let help = help_line(state);
        frame.render_widget(
            Paragraph::new(Line::from(help)).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            areas[3],
        );
    })?;
    Ok(())
}

fn home_items(
    state: &HomeState,
    engine: &Engine<'_>,
    modules: &[ModuleStatus],
    model: Option<&dyn LlmPort>,
    new_analyst_key: bool,
) -> Result<Vec<ListItem<'static>>> {
    let fingerprint = hex(&sha256(&engine.signer.public_key()));
    let safe = |value: &str| -> Result<String> { Ok(engine.guard.screen(value)?.text) };
    let content = match state.mode {
        Mode::List | Mode::Search => case_items(state, engine)?,
        Mode::New => {
            const NAMES: [&str; 7] = [
                "Title",
                "Severity (low/medium/high/critical)",
                "Sources",
                "Accounts",
                "Hosts",
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
    }
    if let Some(edit) = &state.module_edit {
        items.push(ListItem::new(safe(&format!(
            "Edit {}.{}: {}",
            edit.module, edit.field, edit.value
        ))?));
    }
    for (index, module) in modules.iter().enumerate() {
        items.push(ListItem::new(safe(&format!(
            "{} {}  compiled={} selected={} active={}{}  {}",
            if index == state.module_selected {
                ">"
            } else {
                " "
            },
            module.id,
            module.compiled,
            module.selected,
            module.enabled,
            if module.selection_overridden() {
                " (temporary override)"
            } else {
                ""
            },
            module.configuration
        ))?));
        if index == state.module_selected {
            items.extend(module_parameter_items(
                module,
                state.parameter_selected,
                safe,
            )?);
            if !module.credentials.is_empty() {
                items.push(ListItem::new(safe(&format!(
                    "   Credentials: {} (press k to open keystore)",
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
                "{marker} {}  {}  {}  {}  {}",
                row.title,
                row.severity,
                row.status.label(),
                at,
                row.id.as_str()
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
        ListItem::new("Press m to inspect compiled modules and missing configuration."),
        ListItem::new("Press k to inspect the active keystore and credentials."),
        ListItem::new("Press n to create a case; no CLI setup is required."),
    ]
}

fn help_line(state: &HomeState) -> &'static str {
    match state.mode {
        Mode::List => {
            "Enter open · n new · / search · f filter · v verify export · m modules · k keystore · ? setup · q quit"
        }
        Mode::Search => "Type to search · Enter apply · Esc cancel",
        Mode::New => {
            "Tab next field · Enter create · Esc cancel · sources, accounts, hosts: comma-separated"
        }
        Mode::Modules => {
            if state.pending_module_change.is_some() {
                "This change may send case data off this device · y confirm and sign · Esc cancel"
            } else if state.module_edit.is_some() {
                "Type parameter value · Enter save and restart session · Esc cancel"
            } else {
                "Up/Down module · Tab field · e edit · Enter select/toggle · k credentials · Esc back"
            }
        }
        Mode::Setup => "Esc back · n new case · m modules · q quit",
        Mode::Keystore => {
            if state.confirm_credential_delete {
                "Delete selected credential? y confirm · Esc cancel"
            } else if state.pending_migration.is_some() {
                "Copy to the other backend and sign the event? y confirm · Esc cancel"
            } else if state.restart_required {
                "r restart session · active connectors may still hold old credentials · Esc back"
            } else {
                "Up/Down select · a add/replace · d delete · p passphrase · s migrate signer · x migrate secrets · Esc"
            }
        }
        Mode::VerifyExport => {
            "Tab switch field · Enter verify · Esc back; expected key is mandatory"
        }
    }
}

#[cfg(test)]
mod help_tests {
    use super::{HomeState, Mode, help_line};

    #[test]
    fn keystore_offers_session_restart_after_credentials_change() {
        let mut state = HomeState::new(Vec::new(), false);
        state.mode = Mode::Keystore;
        assert!(!help_line(&state).contains("restart session"));
        state.restart_required = true;
        assert!(help_line(&state).contains("r restart session"));
        assert!(help_line(&state).contains("active connectors"));
    }
}
