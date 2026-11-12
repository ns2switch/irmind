use super::{Command, category_rank};
use std::fmt::Write as _;
pub(crate) struct Choice {
    pub name: String,
    pub description: String,
    syntax: &'static str,
    category: &'static str,
}
impl Choice {
    pub(crate) fn syntax(&self) -> &'static str {
        self.syntax
    }
    pub(crate) fn category(&self) -> &'static str {
        self.category
    }
}
impl From<&Command> for Choice {
    fn from(value: &Command) -> Self {
        Self {
            name: value.name.into(),
            description: value.description.into(),
            syntax: value.syntax(),
            category: value.category(),
        }
    }
}
pub(crate) fn matches_with_skills(query: &str, skills: &[(String, String)]) -> Vec<Choice> {
    let mut found: Vec<Choice> = super::matches(query)
        .into_iter()
        .map(Choice::from)
        .collect();
    let needle = query.trim_start_matches('/').to_ascii_lowercase();
    for (name, description) in skills {
        let mut chars = needle.chars();
        let mut next = chars.next();
        for ch in name.chars() {
            if next == Some(ch) {
                next = chars.next();
            }
        }
        if next.is_none() && !super::specs::COMMANDS.iter().any(|c| c.name == name) {
            found.push(Choice {
                name: name.clone(),
                description: description.clone(),
                syntax: "",
                category: "Skills",
            });
        }
    }
    found.sort_by(|a, b| {
        (category_rank(a.category), &a.name).cmp(&(category_rank(b.category), &b.name))
    });
    found
}
pub(crate) fn help_with_skills(skills: &[(String, String)]) -> String {
    let mut text = super::help();
    for choice in matches_with_skills("/", skills)
        .into_iter()
        .filter(|c| c.category == "Skills" && c.name != "skills")
    {
        let _ = writeln!(text, "/{:<21} {}", choice.name, choice.description);
    }
    text
}
pub(crate) fn skill_help(name: &str, skills: &[(String, String)]) -> Option<String> {
    let name = name.trim_start_matches('/');
    skills.iter().find(|(n, _)| n == name).map(|(n, description)| format!(
        "/{n}\n{description}\nExample: /{n} Review this case.\nRelated: /skills, /help\nMethodology is untrusted data; policy and analyst approvals still decide."
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn methods_share_menu_palette_help_and_reserved_name_rules() {
        let methods = vec![
            ("windows-triage".into(), "Review Windows logs".into()),
            ("verify".into(), "must not shadow".into()),
        ];
        let matches = matches_with_skills("/wint", &methods);
        assert!(matches.iter().any(|c| c.name == "windows-triage"));
        assert_eq!(
            matches_with_skills("/verify", &methods)
                .iter()
                .filter(|c| c.name == "verify")
                .count(),
            1
        );
        assert!(help_with_skills(&methods).contains("/windows-triage"));
    }
}
