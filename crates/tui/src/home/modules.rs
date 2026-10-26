use super::{ConfigChange, HomeState, KeyCode, Mode, ModuleEdit, ModuleKind, state::HomeAction};

pub(super) fn update_module_screen(state: &mut HomeState, key: KeyCode) -> HomeAction {
    if let Some(change) = state.pending_module_change.clone() {
        match key {
            KeyCode::Esc => state.pending_module_change = None,
            KeyCode::Char('y') => {
                state.pending_module_change = None;
                return HomeAction::ChangeModule(change, true);
            }
            _ => {}
        }
        return HomeAction::None;
    }
    if state.module_edit.is_some() {
        return update_edit(state, key);
    }
    match key {
        KeyCode::Esc => state.mode = Mode::List,
        KeyCode::Up => {
            state.module_selected = state.module_selected.saturating_sub(1);
            state.parameter_selected = 0;
        }
        KeyCode::Down => {
            state.module_selected =
                (state.module_selected + 1).min(state.modules.len().saturating_sub(1));
            state.parameter_selected = 0;
        }
        KeyCode::Tab => select_parameter(state, true),
        KeyCode::BackTab => select_parameter(state, false),
        KeyCode::Char('e') => begin_edit(state),
        KeyCode::Char('k') => {
            state.mode = Mode::Keystore;
            return HomeAction::LoadKeystore;
        }
        KeyCode::Char('r') if state.restart_required => return HomeAction::Restart,
        KeyCode::Enter | KeyCode::Char(' ') => return toggle_selected(state),
        _ => {}
    }
    HomeAction::None
}

fn select_parameter(state: &mut HomeState, forward: bool) {
    let count = state
        .modules
        .get(state.module_selected)
        .map_or(0, |item| item.parameters.len());
    if count > 0 {
        state.parameter_selected = if forward {
            (state.parameter_selected + 1) % count
        } else {
            (state.parameter_selected + count - 1) % count
        };
    }
}

fn begin_edit(state: &mut HomeState) {
    let Some(module) = state.modules.get(state.module_selected) else {
        return;
    };
    if !module.compiled {
        state.notice = "Module is not compiled into this binary".into();
        return;
    }
    let Some(field) = module.parameters.get(state.parameter_selected) else {
        state.notice = "This module has no public parameters; use k for credentials".into();
        return;
    };
    if field.overridden {
        state.notice = "This parameter is overridden by an environment variable".into();
        return;
    }
    state.module_edit = Some(ModuleEdit {
        module: module.id.clone(),
        field: field.name.clone(),
        value: field.value.clone(),
    });
}

fn update_edit(state: &mut HomeState, key: KeyCode) -> HomeAction {
    let Some(edit) = state.module_edit.as_mut() else {
        return HomeAction::None;
    };
    match key {
        KeyCode::Esc => state.module_edit = None,
        KeyCode::Backspace => {
            edit.value.pop();
        }
        KeyCode::Char(ch) if edit.value.len() < 1024 && !ch.is_control() => edit.value.push(ch),
        KeyCode::Enter => {
            let Some(edit) = state.module_edit.take() else {
                return HomeAction::None;
            };
            return HomeAction::ChangeModule(
                ConfigChange::SetValue {
                    module: edit.module,
                    field: edit.field,
                    value: edit.value,
                },
                false,
            );
        }
        _ => {}
    }
    HomeAction::None
}

fn toggle_selected(state: &mut HomeState) -> HomeAction {
    let Some(module) = state.modules.get(state.module_selected) else {
        return HomeAction::None;
    };
    if !module.compiled {
        state.notice = "Module is not compiled into this binary".into();
        return HomeAction::None;
    }
    if module.selection_overridden() {
        state.notice = "Module selection is overridden by a flag or environment variable".into();
        return HomeAction::None;
    }
    match module.kind {
        ModuleKind::Llm => HomeAction::ChangeModule(
            ConfigChange::SelectLlm((!module.selected).then(|| module.id.clone())),
            false,
        ),
        ModuleKind::Connector => HomeAction::ChangeModule(
            ConfigChange::SetEnabled {
                module: module.id.clone(),
                enabled: !module.selected,
            },
            false,
        ),
        ModuleKind::Keystore => {
            state.mode = Mode::Keystore;
            HomeAction::LoadKeystore
        }
        ModuleKind::Local => HomeAction::None,
    }
}
