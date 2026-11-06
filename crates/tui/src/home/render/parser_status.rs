use super::{HomeState, ListItem, ModuleStatus, case};

pub(super) fn items(state: &HomeState, modules: &[ModuleStatus]) -> Vec<ListItem<'static>> {
    let mut rows = state
        .parsers
        .iter()
        .map(|(name, version)| {
            ListItem::new(format!(
                "  {} · {} · experimental",
                case::escape_display(name),
                case::escape_display(version)
            ))
        })
        .collect::<Vec<_>>();
    for module in modules
        .iter()
        .filter(|module| module.id.starts_with("parser-") && !module.enabled)
    {
        rows.push(ListItem::new(format!(
            "  {} · {} · {}",
            case::escape_display(&module.id),
            if module.compiled {
                "unavailable"
            } else {
                "not compiled"
            },
            case::escape_display(&module.configuration),
        )));
    }
    if !rows.is_empty() {
        rows.insert(0, ListItem::new("Compiled parsers · experimental"));
    }
    rows
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::{ModuleKind, ModuleSelectionSource};
    use ratatui::{Terminal, backend::TestBackend, widgets::List};

    #[test]
    fn unavailable_evtx_remains_visible_in_preferences_with_escaped_reason() {
        let state = HomeState::new(Vec::new(), false);
        let module = ModuleStatus {
            id: "parser-evtx".into(),
            compiled: true,
            enabled: false,
            configuration: "Landlock unavailable\x1b[31m".into(),
            kind: ModuleKind::Local,
            selected: false,
            selection_source: ModuleSelectionSource::Persistent,
            parameters: Vec::new(),
            credentials: Vec::new(),
            missing: Vec::new(),
        };
        let mut terminal = Terminal::new(TestBackend::new(100, 4)).unwrap();
        terminal
            .draw(|frame| {
                frame.render_widget(
                    List::new(items(&state, std::slice::from_ref(&module))),
                    frame.area(),
                );
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        let text = buffer
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(text.contains("parser-evtx · unavailable · Landlock unavailable"));
        assert!(!text.contains('\x1b'));
    }
}
