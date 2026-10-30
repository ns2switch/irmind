use crossterm::event::{KeyCode, KeyModifiers};
use std::fmt::Write as _;
pub(crate) struct Command {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    pub(crate) shortcut: &'static str,
    pub(crate) slash: bool,
}

impl Command {
    pub(crate) fn category(&self) -> &'static str {
        match self.name {
            "ingest" | "verify" | "seal" | "export" | "report" | "scope" | "home" | "rebuild" => {
                "Case"
            }
            "evidence" | "evidence-save" | "raw" | "graph" | "timeline" | "entity"
            | "neighbors" | "path" | "search" | "entity-timeline" | "siem-alert"
            | "verify-graph" | "objects" | "object-read" => "Evidence",
            "approve" | "deny" | "edit" => "Approvals",
            "findings" | "iocs" | "hypotheses" | "techniques" | "confirm" | "dismiss" | "add" => {
                "Findings"
            }
            _ => "System",
        }
    }

    pub(crate) fn syntax(&self) -> &'static str {
        match self.name {
            "approve" | "deny" | "edit" => " <id>",
            "settings" => " [model|connectors|keystore|preferences]",
            "open" => " <case title or ID>",
            "evidence" | "raw" => " <hash>",
            "ingest" => " <path>",
            "objects" => " <source> <scheme> <container> <prefix> <from> <to>",
            "object-read" => " <number> [--copy-original]",
            "search" => " <words>",
            _ => "",
        }
    }
}

pub(super) fn category_rank(category: &str) -> usize {
    match category {
        "Case" => 0,
        "Evidence" => 1,
        "Approvals" => 2,
        "Findings" => 3,
        "System" => 4,
        _ => 5,
    }
}

mod specs;
use specs::COMMANDS;

pub(crate) fn matches(query: &str) -> Vec<&'static Command> {
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
    found.sort_by_key(|command| (category_rank(command.category()), command.name));
    found
}

pub(crate) fn help() -> String {
    let mut output = String::from(
        "Enter confirm/send · Esc cancel/back · arrows select · Tab complete · PgUp/PgDn scroll · Ctrl+C confirm exit · Ctrl+K commands · Ctrl+O detail\nCommands:\n",
    );
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

pub(super) fn shortcut_name(code: KeyCode, modifiers: KeyModifiers) -> Option<&'static str> {
    if modifiers.contains(KeyModifiers::ALT) {
        return None;
    }
    let label = if modifiers.contains(KeyModifiers::CONTROL) {
        match code {
            KeyCode::Char('k') => "Ctrl+K",
            KeyCode::Char('o') => "Ctrl+O",
            KeyCode::Char('c') => "Ctrl+C",
            _ => return None,
        }
    } else {
        match code {
            KeyCode::Esc => "Esc",
            KeyCode::PageUp => "PgUp",
            KeyCode::PageDown => "PgDn",
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
    _modules: &[String],
) -> Vec<String> {
    let Some((command, prefix)) = input.split_once(' ') else {
        return Vec::new();
    };
    if matches!(command, "/ingest" | "/verify" | "/verify-graph") {
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
        "/settings" => ["model", "connectors", "keystore", "preferences"]
            .iter()
            .map(|value| (*value).into())
            .collect(),
        _ => Vec::new(),
    };
    values
        .into_iter()
        .filter(|value| value.starts_with(prefix))
        .take(20)
        .collect()
}

pub(crate) fn cycle(len: usize, selected: usize, started: bool, forward: bool) -> usize {
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
            matches("/sear")
                .iter()
                .any(|command| command.name == "search")
        );
        assert_eq!(matches("/gra")[0].name, "graph");
        assert!(
            matches("/aprv")
                .iter()
                .any(|command| command.name == "approve")
        );
        assert_eq!(cycle(3, 0, false, true), 0);
        assert_eq!(cycle(3, 0, true, true), 1);
        assert_eq!(cycle(3, 0, true, false), 2);
        assert_eq!(shortcut_name(KeyCode::Char('a'), KeyModifiers::NONE), None);
        assert_eq!(shortcut_name(KeyCode::Char('a'), KeyModifiers::ALT), None);
        assert_eq!(
            shortcut_name(KeyCode::Char('b'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(matches("/side")[0].name, "sidebar");
        assert!(help().contains("Ctrl+K"));
        let all = matches("/");
        assert!(all.windows(2).all(|pair| {
            (category_rank(pair[0].category()), pair[0].name)
                <= (category_rank(pair[1].category()), pair[1].name)
        }));
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
            argument_candidates("/settings mo", &approvals, &findings, &hashes, &modules),
            vec!["model"]
        );
        assert!(
            argument_candidates("/ingest ../../examples/cloud", &[], &[], &[], &[])
                .iter()
                .any(|path| path.ends_with("cloudtrail-alert.json"))
        );
    }
}
