use crossterm::event::{KeyCode, KeyModifiers};
use std::fmt::Write as _;
pub(super) struct Command {
    pub name: &'static str,
    pub description: &'static str,
    pub shortcut: &'static str,
    pub slash: bool,
}

mod specs;
use specs::COMMANDS;

pub(super) fn matches(query: &str) -> Vec<&'static Command> {
    let needle = query.trim_start_matches('/').to_ascii_lowercase();
    let mut found = COMMANDS
        .iter()
        .filter(|command| command.slash)
        .filter(|command| {
            let mut chars = needle.chars();
            let mut next = chars.next();
            for ch in command.name.chars() {
                if next == Some(ch) {
                    next = chars.next();
                }
            }
            next.is_none()
        })
        .collect::<Vec<_>>();
    found.sort_by_key(|command| (!command.name.starts_with(&needle), command.name));
    found
}

pub(super) fn help() -> String {
    let mut output =
        String::from("Enter send · Alt/Shift+Enter newline\nCommands and shortcuts:\n");
    for command in COMMANDS {
        let suffix = if command.slash && !command.shortcut.is_empty() {
            format!(" ({})", command.shortcut)
        } else {
            String::new()
        };
        let _ = writeln!(
            output,
            "{:<22} {}{}",
            if command.slash {
                format!("/{}", command.name)
            } else {
                command.shortcut.to_owned()
            },
            command.description,
            suffix,
        );
    }
    output
}

pub(super) fn help_bar() -> String {
    ["sidebar", "palette", "scroll-up", "help", "pause"]
        .iter()
        .filter_map(|name| COMMANDS.iter().find(|command| command.name == *name))
        .map(|command| format!("{} {}", command.shortcut, command.description))
        .collect::<Vec<_>>()
        .join(" · ")
}

pub(super) fn shortcut_name(code: KeyCode, modifiers: KeyModifiers) -> Option<&'static str> {
    if modifiers.contains(KeyModifiers::ALT) {
        return None;
    }
    let label = if modifiers.contains(KeyModifiers::CONTROL) {
        match code {
            KeyCode::Char('b') => "Ctrl+B",
            KeyCode::Char('k') => "Ctrl+K",
            KeyCode::Char('l') => "Ctrl+L",
            KeyCode::Char('i') => "Ctrl+I",
            KeyCode::Char('c') => "Ctrl+C",
            KeyCode::Char('u') => "Ctrl+U",
            KeyCode::Char('d') => "Ctrl+D",
            _ => return None,
        }
    } else {
        match code {
            KeyCode::Esc => "Esc",
            KeyCode::Char('?') => "?",
            KeyCode::Char('a') => "a",
            KeyCode::Char('c') => "c",
            KeyCode::Char('d') => "d",
            KeyCode::Char('e') => "e",
            KeyCode::PageUp => "PgUp",
            KeyCode::PageDown => "PgDn",
            KeyCode::Home => "Home",
            KeyCode::End => "End",
            KeyCode::Char('g') => "g",
            KeyCode::Char('G') => "G",
            _ => return None,
        }
    };
    COMMANDS
        .iter()
        .find(|command| command.shortcut == label)
        .map(|command| command.name)
}

pub(super) fn argument_candidates(
    input: &str,
    approvals: &[String],
    findings: &[String],
    hashes: &[String],
    modules: &[String],
) -> Vec<String> {
    let Some((command, prefix)) = input.split_once(' ') else {
        return Vec::new();
    };
    if command == "/ingest" {
        return super::picker::safe_completions(prefix);
    }
    let values: Vec<String> = match command {
        "/approve" | "/deny" | "/edit" => approvals.to_vec(),
        "/confirm" | "/dismiss" => findings.to_vec(),
        "/evidence" | "/evidence-save" | "/raw" => hashes.to_vec(),
        "/add" => ["ioc", "hypothesis", "technique"]
            .iter()
            .map(|value| (*value).into())
            .collect(),
        "/module" => modules.to_vec(),
        _ => Vec::new(),
    };
    values
        .into_iter()
        .filter(|value| value.starts_with(prefix))
        .take(20)
        .collect()
}

pub(super) fn cycle(len: usize, selected: usize, started: bool, forward: bool) -> usize {
    if len == 0 {
        return 0;
    }
    if !started {
        return if forward { 0 } else { len - 1 };
    }
    if forward {
        (selected + 1) % len
    } else {
        (selected + len - 1) % len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slash_menu_filters_prefix_and_fuzzy_and_cycles_both_ways() {
        assert_eq!(matches("/ver")[0].name, "verify");
        assert!(
            matches("/aprv")
                .iter()
                .any(|command| command.name == "approve")
        );
        assert_eq!(cycle(3, 0, false, true), 0);
        assert_eq!(cycle(3, 0, true, true), 1);
        assert_eq!(cycle(3, 0, true, false), 2);
        assert_eq!(
            shortcut_name(KeyCode::Char('a'), KeyModifiers::NONE),
            Some("approve")
        );
        assert_eq!(shortcut_name(KeyCode::Char('a'), KeyModifiers::ALT), None);
        assert_eq!(
            shortcut_name(KeyCode::Char('b'), KeyModifiers::CONTROL),
            Some("sidebar")
        );
        assert!(matches("/side").is_empty());
        assert!(help_bar().contains("Ctrl+B"));
    }

    #[test]
    fn completes_known_ids_and_safe_repository_path() {
        let approvals = vec!["approval-123".into()];
        let findings = vec!["finding-42".into()];
        let hashes = vec!["ab".repeat(32)];
        let modules = vec!["llm-openai-compatible".into()];
        assert_eq!(
            argument_candidates("/approve app", &approvals, &findings, &hashes, &modules),
            approvals
        );
        assert_eq!(
            argument_candidates("/confirm fin", &approvals, &findings, &hashes, &modules),
            findings
        );
        assert_eq!(
            argument_candidates("/evidence ab", &approvals, &findings, &hashes, &modules),
            hashes
        );
        assert_eq!(
            argument_candidates("/module llm", &approvals, &findings, &hashes, &modules),
            modules
        );
        assert!(
            argument_candidates("/ingest ../../examples/cloud", &[], &[], &[], &[])
                .iter()
                .any(|path| path.ends_with("cloudtrail-alert.json"))
        );
    }
}
