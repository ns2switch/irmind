use super::{
    ConfigChange, HomeState, KeyCode, Mode, ModuleEdit, ModuleKind, module_catalog,
    state::HomeAction,
};

pub(super) fn update_module_screen(state: &mut HomeState, key: KeyCode) -> HomeAction {
    if let Some(change) = state.pending_module_change.clone() {
        match key {
            KeyCode::Esc => {
                state.pending_module_change = None;
                state.input.clear();
            }
            KeyCode::Up | KeyCode::Down => state.selected_option = 1 - state.selected_option,
            KeyCode::Char(ch) if !ch.is_control() && state.input.len() < 4 => state.input.push(ch),
            KeyCode::Backspace => {
                state.input.pop();
            }
            KeyCode::Enter if state.input == "2" => {
                state.input.clear();
                state.pending_module_change = None;
                return HomeAction::ChangeModule(change, true);
            }
            KeyCode::Enter if state.input == "1" => {
                state.input.clear();
                state.pending_module_change = None;
            }
            KeyCode::Enter if state.input.is_empty() && state.selected_option == 1 => {
                state.input.clear();
                state.pending_module_change = None;
                return HomeAction::ChangeModule(change, true);
            }
            KeyCode::Enter if state.input.is_empty() => state.pending_module_change = None,
            _ => {}
        }
        return HomeAction::None;
    }
    if state.module_edit.is_some() {
        return update_edit(state, key);
    }
    match key {
        KeyCode::Esc => state.mode = state.settings_return,
        KeyCode::Up => move_module(state, false),
        KeyCode::Down => move_module(state, true),
        KeyCode::Tab => select_parameter(state, true),
        KeyCode::BackTab => select_parameter(state, false),
        KeyCode::Char(ch) if state.ui_selection.parameter_focused && !ch.is_control() => {
            begin_edit(state);
            if state.module_edit.is_some() {
                return update_edit(state, KeyCode::Char(ch));
            }
        }
        KeyCode::Backspace => {
            state.input.pop();
        }
        KeyCode::Enter if !state.input.is_empty() => return super::state::execute_command(state),
        KeyCode::Enter if state.ui_selection.parameter_focused => begin_edit(state),
        KeyCode::Enter => return toggle_selected(state),
        _ => {}
    }
    HomeAction::None
}

fn move_module(state: &mut HomeState, forward: bool) {
    let order = module_catalog::connectors(&state.modules)
        .into_iter()
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if let Some(current) = order
        .iter()
        .position(|index| *index == state.module_selected)
    {
        let next = if forward {
            (current + 1).min(order.len().saturating_sub(1))
        } else {
            current.saturating_sub(1)
        };
        state.module_selected = order[next];
        state.parameter_selected = 0;
        state.ui_selection.parameter_focused = false;
    } else if let Some(first) = order.first() {
        state.module_selected = *first;
    }
}

fn select_parameter(state: &mut HomeState, forward: bool) {
    let count = state
        .modules
        .get(state.module_selected)
        .map_or(0, |item| item.parameters.len());
    if count > 0 {
        state.ui_selection.parameter_focused = true;
        state.parameter_selected = if forward {
            (state.parameter_selected + 1) % count
        } else {
            (state.parameter_selected + count - 1) % count
        };
    }
}

pub(super) fn begin_edit(state: &mut HomeState) {
    let Some(module) = state.modules.get(state.module_selected) else {
        return;
    };
    if module.kind != ModuleKind::Connector || !module.compiled {
        state.notice = "Module is not compiled into this binary".into();
        return;
    }
    let Some(field) = module.parameters.get(state.parameter_selected) else {
        state.notice =
            "This module has no public parameters; use /settings keystore for credentials".into();
        return;
    };
    if field.overridden {
        state.notice = "This parameter is overridden by an environment variable".into();
        return;
    }
    if field.name.ends_with("_CA_SHA256") {
        state.notice = "The CA fingerprint is set by approving a CA PEM file".into();
        return;
    }
    state.module_edit = Some(ModuleEdit {
        module: module.id.clone(),
        field: field.name.clone(),
        value: field.value.clone(),
        replace_on_type: true,
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
            edit.replace_on_type = false;
        }
        KeyCode::Char(ch) if edit.value.len() < 1024 && !ch.is_control() => {
            if edit.replace_on_type {
                edit.value.clear();
                edit.replace_on_type = false;
            }
            edit.value.push(ch);
        }
        KeyCode::Enter => {
            let Some(mut edit) = state.module_edit.take() else {
                return HomeAction::None;
            };
            if edit.replace_on_type {
                state.notice = "Current value accepted".into();
                return HomeAction::None;
            }
            if edit.field.ends_with("_URL") {
                match super::model::normalize_base_url(&edit.value) {
                    Ok(value) => edit.value = value,
                    Err(reason) => {
                        state.notice = reason.into();
                        state.module_edit = Some(edit);
                        return HomeAction::None;
                    }
                }
            }
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
    if module.kind != ModuleKind::Connector || !module.compiled {
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
