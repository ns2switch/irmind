use crate::case::command_registry;
use crate::case::state::CaseState;

pub(super) fn menu_text(state: &CaseState, modules: &[crate::ModuleStatus]) -> Option<String> {
    if !state.menu_open {
        return None;
    }
    let query = state.menu_query.as_deref().unwrap_or(&state.input);
    let options = if query.contains(' ') {
        let ids = modules
            .iter()
            .map(|module| module.id.clone())
            .collect::<Vec<_>>();
        let approvals = state
            .approvals
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        let findings = state
            .findings
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        command_registry::argument_candidates(query, &approvals, &findings, &state.hashes, &ids)
            .into_iter()
            .map(|value| (value, "argument".to_owned(), "Arguments"))
            .collect::<Vec<_>>()
    } else {
        command_registry::matches(query)
            .iter()
            .map(|command| {
                (
                    format!("/{}{}", command.name, command.syntax()),
                    command.description.to_owned(),
                    command.category(),
                )
            })
            .collect::<Vec<_>>()
    };
    Some(format_options(&options, state.menu_selected))
}

fn format_options(options: &[(String, String, &'static str)], selected: usize) -> String {
    let mut lines = Vec::new();
    let mut last_category = "";
    for (index, (name, description, category)) in options
        .iter()
        .enumerate()
        .skip(selected.saturating_sub(6))
        .take(7)
    {
        if *category != last_category {
            lines.push(format!("· {category}"));
            last_category = *category;
        }
        lines.push(format!(
            "{} {:<19} {}",
            if index == selected { '>' } else { ' ' },
            name,
            description
        ));
    }
    if lines.is_empty() {
        lines.push("No matching commands".into());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::format_options;

    #[test]
    fn grouped_menu_has_one_heading_per_category() {
        let options = [
            ("/ingest".into(), "Add evidence".into(), "Case"),
            ("/verify".into(), "Check custody".into(), "Case"),
            ("/evidence".into(), "View evidence".into(), "Evidence"),
            ("/raw".into(), "Read record".into(), "Evidence"),
            ("/approve".into(), "Approve call".into(), "Approvals"),
        ];
        let menu = format_options(&options, 4);
        assert_eq!(menu.matches("· Case").count(), 1);
        assert_eq!(menu.matches("· Evidence").count(), 1);
        assert_eq!(menu.matches("· Approvals").count(), 1);
        insta::assert_snapshot!("grouped_command_menu", menu);
    }
}
