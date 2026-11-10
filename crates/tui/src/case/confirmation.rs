use anyhow::Result;
use irmind_app::{CaseId, Engine, SealPreview};

pub(super) enum Confirmation {
    Seal(Box<SealPreview>, String),
    Export(String, String),
    ObjectRead(String, String),
}

pub(super) fn seal_confirmation(preview: &SealPreview) -> String {
    format!(
        "Seal case {}\nAudit entries after seal: {}\nFinal hash: {}\nAnalyst key fingerprint: {}\n1. Cancel  2. Confirm (↑/↓, Enter, or number then Enter)",
        preview.case_id(),
        preview.entry_count(),
        irmind_app::hex(&preview.final_hash()),
        preview.analyst_key_fingerprint()
    )
}

pub(crate) fn escape_display(value: &str) -> String {
    value.chars().fold(String::new(), |mut out, ch| {
        if ch == '\n' {
            out.push(ch);
        } else if ch.is_control()
            || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}')
        {
            out.extend(ch.escape_default());
        } else {
            out.push(ch);
        }
        out
    })
}

pub(super) fn confirmation_summary(
    engine: &Engine<'_>,
    id: &CaseId,
    operation: &str,
) -> Result<String> {
    let seal = engine.repo.case_seal(id)?.ok_or({
        irmind_app::AppError::Fixed(irmind_app::FixedAppError::AdapterPolicy(
            irmind_app::AdapterPolicyError::SealTheCaseBeforeExport,
        ))
    })?;
    let entries = engine.audit_log.entries(id)?;
    let last = entries.last().map_or([0u8; 32], |entry| entry.hash);
    Ok(format!(
        "{operation} case {}\nAudit entries: {}\nFinal hash: {}\nAnalyst key fingerprint: {}\n1. Cancel  2. Confirm (↑/↓, Enter, or number then Enter)",
        id.as_str(),
        entries.len(),
        irmind_app::hex(&last),
        seal.analyst_key_fingerprint
    ))
}

#[cfg(test)]
mod tests {
    use super::escape_display;

    #[test]
    fn modal_escapes_terminal_and_bidi_controls_but_keeps_hash_lines() {
        let visible = escape_display("hash: abc123\nfile\x1b[2J\u{202e}name");
        assert!(visible.contains("hash: abc123\n"));
        assert!(!visible.contains('\x1b'));
        assert!(!visible.contains('\u{202e}'));
    }
}
