use super::{Card, CardKind, Conversation};
use anyhow::Result;
use irmind_app::{ContentGuard, SignedEntry, parser_extraction_warning};

pub(super) fn message(guard: &dyn ContentGuard, entries: &[SignedEntry]) -> Result<Option<String>> {
    parser_extraction_warning(entries)?
        .map(|warning| {
            warning
                .display(guard)
                .map(|text| super::escape_display(&text))
        })
        .transpose()
        .map_err(Into::into)
}

pub(super) fn append(
    conversation: &mut Conversation,
    guard: &dyn ContentGuard,
    entries: &[SignedEntry],
) -> Result<()> {
    if let Some(warning) = message(guard, entries)? {
        conversation.push(Card::new(
            CardKind::Warning,
            "Extraction warning",
            warning,
            false,
        ));
    }
    Ok(())
}

/// Verification returns a fixed summary followed by its optional warning.
/// Keep that warning visible rather than folding it into an operation detail.
pub(super) fn completion(conversation: &mut Conversation, label: &str, text: String) -> String {
    if matches!(label, "Verify" | "Verify originals")
        && let Some((summary, warning)) = text.split_once('\n')
    {
        let warning = super::escape_display(warning);
        conversation.push(Card::new(
            CardKind::Warning,
            "Extraction warning",
            warning,
            false,
        ));
        return summary.into();
    }
    text
}

#[cfg(test)]
mod tests;
