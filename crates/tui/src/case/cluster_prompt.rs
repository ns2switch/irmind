use crossterm::event::{KeyCode, KeyModifiers};
use irmind_app::{AppError, ContentGuard, ParserClusterRequirement, SourceClusterContext};
use irmind_app::{ClusterContextBasis, ClusterIdentity, SourceClusterBinding};

pub(super) struct ClusterPrompt {
    pub source: String,
    value: String,
    focus: usize,
    all_files: bool,
    claims: Vec<ClusterIdentity>,
    error: Option<String>,
}
pub(super) enum ClusterPromptAction {
    Keep,
    Cancel,
    Confirm {
        context: SourceClusterContext,
        all_files: bool,
    },
}
impl ClusterPrompt {
    pub(super) fn new(source: String, requirement: &ParserClusterRequirement) -> Self {
        Self {
            source,
            value: String::new(),
            focus: 0,
            all_files: false,
            claims: requirement.source_claims().to_vec(),
            error: None,
        }
    }
    pub(super) fn paste(&mut self, value: &str) {
        if self.focus != 0 {
            return;
        }
        for ch in value.chars().filter(|ch| !ch.is_control()) {
            if self.value.len() + ch.len_utf8() > 640 {
                break;
            }
            self.value.push(ch);
        }
        self.error = None;
    }
    pub(super) fn update(&mut self, code: KeyCode, modifiers: KeyModifiers) -> ClusterPromptAction {
        match code {
            KeyCode::Esc => return ClusterPromptAction::Cancel,
            KeyCode::Tab => self.focus = (self.focus + 1) % 4,
            KeyCode::BackTab => self.focus = (self.focus + 3) % 4,
            KeyCode::Up => self.focus = self.focus.saturating_sub(1),
            KeyCode::Down => self.focus = (self.focus + 1).min(3),
            KeyCode::Backspace if self.focus == 0 => {
                self.value.pop();
            }
            KeyCode::Char('u') if self.focus == 0 && modifiers.contains(KeyModifiers::CONTROL) => {
                self.value.clear();
            }
            KeyCode::Char(ch) if !ch.is_control() && !modifiers.contains(KeyModifiers::CONTROL) => {
                self.paste(&ch.to_string());
            }
            KeyCode::Enter => return self.enter(),
            _ => {}
        }
        ClusterPromptAction::Keep
    }
    fn enter(&mut self) -> ClusterPromptAction {
        if self.focus == 0 {
            self.focus = 3;
            return ClusterPromptAction::Keep;
        }
        if self.focus == 1 {
            self.all_files = !self.all_files;
            return ClusterPromptAction::Keep;
        }
        let result = match self.focus {
            2 if !self.claims.is_empty() => self
                .claims
                .iter()
                .map(|claim| {
                    SourceClusterBinding::try_new(
                        claim.clone(),
                        ClusterContextBasis::ConfirmedSource,
                        Some(claim.id()),
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .and_then(SourceClusterContext::try_new),
            3 => ClusterIdentity::parse_qualified(&self.value)
                .and_then(|identity| {
                    SourceClusterBinding::try_new(identity, ClusterContextBasis::Analyst, None)
                })
                .and_then(|binding| SourceClusterContext::try_new(vec![binding])),
            _ => return ClusterPromptAction::Keep,
        };
        if let Ok(context) = result {
            ClusterPromptAction::Confirm {
                context,
                all_files: self.all_files,
            }
        } else {
            self.error = Some("Enter a complete provider-qualified cluster identity; names and paths alone are not identities.".into());
            ClusterPromptAction::Keep
        }
    }
    pub(super) fn screened_text(&self, guard: &dyn ContentGuard) -> Result<String, AppError> {
        let marker = |focus| if focus == self.focus { ">" } else { " " };
        let displayed = if self.value.is_empty() {
            "kubernetes:urn:k8s:team-a"
        } else {
            &self.value
        };
        let mut rows = vec![
            format!("Confirm cluster identity · {}", self.source),
            "Names alone are not unique. This choice is signed; it never grants permissions."
                .into(),
            format!(
                "{} Explicit identity\n┌────────────────────────────────────────┐\n│ {displayed}\n└────────────────────────────────────────┘",
                marker(0)
            ),
            format!(
                "{} Apply to {}",
                marker(1),
                if self.all_files {
                    "all files in this ingestion (explicit)"
                } else {
                    "this file only"
                }
            ),
        ];
        for claim in &self.claims {
            rows.push(format!("Source claim (untrusted): {}", claim.qualified()));
        }
        rows.push(format!(
            "{} Confirm {} original source claim(s)",
            marker(2),
            self.claims.len()
        ));
        rows.push(format!(
            "{} Confirm explicit identity and ingest",
            marker(3)
        ));
        if let Some(error) = &self.error {
            rows.push(error.clone());
        }
        rows.push("Tab fields/options · ↑/↓ choose · Enter confirm · Esc cancel".into());
        guard.screen(&rows.join("\n")).map(|safe| safe.text)
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;
