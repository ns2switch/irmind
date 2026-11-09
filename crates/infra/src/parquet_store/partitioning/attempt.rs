//! Operational failures win over source exclusions and sibling cancellation.
use irmind_app::AppError;

pub(super) fn prefer_failure(current: AppError, incoming: AppError) -> AppError {
    let operational =
        |error: &AppError| !matches!(error, AppError::Cancelled | AppError::SourceFailure(_));
    if (operational(&incoming) && !operational(&current))
        || (matches!(current, AppError::Cancelled)
            && matches!(incoming, AppError::SourceFailure(_)))
    {
        incoming
    } else {
        current
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn source() -> AppError {
        AppError::SourceFailure(
            irmind_app::RejectedSource::try_new(
                "synthetic.json".into(),
                irmind_app::SourceFailureReason::Format,
                vec![],
            )
            .unwrap(),
        )
    }
    #[test]
    fn operational_failure_is_never_downgraded_to_an_exclusion_or_cancellation() {
        assert!(matches!(
            prefer_failure(source(), AppError::Storage("synthetic failure".into())),
            AppError::Storage(_)
        ));
        assert!(matches!(
            prefer_failure(AppError::Storage("synthetic failure".into()), source()),
            AppError::Storage(_)
        ));
        assert!(matches!(
            prefer_failure(AppError::Cancelled, source()),
            AppError::SourceFailure(_)
        ));
    }
}
