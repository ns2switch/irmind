use crate::{AppError, ContentGuard};

pub(crate) const SECURITY_NOTICE: &str =
    "[Truncated by IRMind's security limit; this response is incomplete.]";
pub(crate) const PROVIDER_NOTICE: &str = "The model reached its maximum output.";
pub(crate) const CONTINUE_INSTRUCTION: &str = "Continue the previous assistant answer exactly where it stopped. Do not repeat completed text, replay private reasoning, or use tools.";
pub(crate) const FRAME_BYTES: usize = 1024 * 1024;

pub(crate) fn utf8_prefix(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Screen one bounded input, including when a finite transport/security limit
/// interrupts a response. Unscreened suffixes are never displayed or persisted.
pub(crate) fn screen_output(guard: &dyn ContentGuard, text: &str) -> Result<String, AppError> {
    let input = utf8_prefix(
        text,
        if text.len() > 1_000_000 {
            1_000_000 - SECURITY_NOTICE.len() - 2
        } else {
            1_000_000
        },
    );
    let mut screened = guard.screen(input)?.text;
    if input.len() != text.len() || screened.len() > 1_000_000 {
        screened = utf8_prefix(&screened, 1_000_000 - SECURITY_NOTICE.len() - 2).to_owned();
        screened.push_str("\n\n");
        screened.push_str(SECURITY_NOTICE);
    }
    Ok(screened)
}

/// Find a UTF-8 prefix using the enclosing record's encoded size, not token or
/// character estimates. The notice is included in the same signed frame.
pub(crate) fn fit_frame(
    text: &str,
    mut size: impl FnMut(&str) -> Result<usize, AppError>,
) -> Result<String, AppError> {
    if size(text)? <= FRAME_BYTES {
        return Ok(text.to_owned());
    }
    let mut low = 0;
    let mut high = text.len();
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        let prefix = utf8_prefix(text, mid);
        let candidate = format!("{prefix}\n\n{SECURITY_NOTICE}");
        if size(&candidate)? <= FRAME_BYTES {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    let result = format!("{}\n\n{SECURITY_NOTICE}", utf8_prefix(text, low));
    if size(&result)? > FRAME_BYTES {
        return Err(AppError::Model(
            "Model metadata exceeds IRMind's signed-frame security limit".into(),
        ));
    }
    Ok(result)
}
