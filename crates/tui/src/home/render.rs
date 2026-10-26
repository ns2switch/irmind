use super::{
    Backend, Block, Borders, CaseStatus, Color, Constraint, Engine, HomeState, Layout, Line, List,
    ListItem, LlmPort, Mode, Modifier, ModuleStatus, Paragraph, Result, Style, Terminal, Wrap,
    case, hex, sha256,
};

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
        frame.render_widget(
            List::new(content).block(Block::default().title(header).borders(Borders::ALL)),
            areas[1],
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
        Mode::Modules => modules
            .iter()
            .map(|module| -> Result<ListItem<'_>> {
                Ok(ListItem::new(safe(&format!(
                    "{}  compiled={} enabled={}  {}",
                    module.id, module.compiled, module.enabled, module.configuration
                ))?))
            })
            .collect::<Result<Vec<_>>>()?,
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
        Mode::Modules | Mode::Setup => "Esc back · n new case · m modules · q quit",
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
