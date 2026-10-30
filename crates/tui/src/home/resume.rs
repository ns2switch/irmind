use super::{CaseRow, CaseStatus};
use anyhow::Result;
use irmind_app::{AppError, CaseId};

pub(super) enum ResumeOutcome<T> {
    Home(Option<String>),
    Opened(T),
    Failed {
        id: CaseId,
        notice: String,
        inconsistent: bool,
    },
}

pub(super) fn attempt<T>(
    rows: &[CaseRow],
    remembered: Result<Option<CaseId>>,
    enabled: bool,
    first_run: bool,
    open: impl FnOnce(&CaseId) -> Result<T>,
) -> ResumeOutcome<T> {
    if !enabled || first_run || rows.is_empty() {
        return ResumeOutcome::Home(None);
    }
    let id = match remembered {
        Ok(Some(id)) => id,
        Ok(None) => return ResumeOutcome::Home(None),
        Err(error) => {
            return ResumeOutcome::Home(Some(format!(
                "Recent case reference could not be read: {error}"
            )));
        }
    };
    let Some(row) = rows.iter().find(|row| row.id == id) else {
        return ResumeOutcome::Home(Some(
            "The recent case no longer exists; choose another case.".into(),
        ));
    };
    if row.status == CaseStatus::Sealed {
        return ResumeOutcome::Home(None);
    }
    match open(&id) {
        Ok(exit) => ResumeOutcome::Opened(exit),
        Err(error) => ResumeOutcome::Failed {
            id,
            notice: format!("Cannot resume the recent case: {error}"),
            inconsistent: error.downcast_ref::<AppError>().is_some_and(|error| {
                matches!(
                    error,
                    AppError::InvalidChain(_) | AppError::EvidenceMismatch(_)
                )
            }),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{ResumeOutcome, attempt};
    use crate::home::{CaseRow, CaseStatus};
    use anyhow::Result;
    use irmind_app::{AppError, CaseId};
    use std::cell::Cell;

    fn row(status: CaseStatus) -> CaseRow {
        CaseRow {
            id: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            title: "Synthetic case".into(),
            severity: "medium".into(),
            status,
            last_activity: 1,
        }
    }

    #[test]
    fn open_recent_case_uses_the_verified_open_path() {
        let case = row(CaseStatus::Open);
        let called = Cell::new(0);
        let result = attempt(
            &[case],
            Ok(Some(row(CaseStatus::Open).id)),
            true,
            false,
            |_| {
                called.set(called.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(result, ResumeOutcome::Opened(())));
        assert_eq!(called.get(), 1);
    }

    #[test]
    fn sealed_deleted_disabled_and_first_run_stay_home() {
        let id = row(CaseStatus::Open).id;
        let opened = Cell::new(0);
        for (rows, enabled, first_run) in [
            (Vec::new(), true, false),
            (vec![row(CaseStatus::Sealed)], true, false),
            (vec![row(CaseStatus::Open)], false, false),
            (vec![row(CaseStatus::Open)], true, true),
        ] {
            let result: ResumeOutcome<()> =
                attempt(&rows, Ok(Some(id.clone())), enabled, first_run, |_| {
                    opened.set(opened.get() + 1);
                    Ok(())
                });
            assert!(matches!(result, ResumeOutcome::Home(_)));
        }
        let result = attempt(
            &[row(CaseStatus::Open)],
            Ok(Some(
                CaseId::parse("00000000-0000-0000-0000-000000000002").unwrap(),
            )),
            true,
            false,
            |_| -> Result<()> {
                opened.set(opened.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(result, ResumeOutcome::Home(Some(_))));
        assert_eq!(opened.get(), 0);
    }

    #[test]
    fn failed_verification_returns_home_with_reason() {
        let case_row = row(CaseStatus::Open);
        let result = attempt(
            &[case_row],
            Ok(Some(row(CaseStatus::Open).id)),
            true,
            false,
            |_| -> Result<()> { Err(AppError::InvalidChain(7).into()) },
        );
        assert!(
            matches!(result, ResumeOutcome::Failed { inconsistent: true, notice, .. } if notice.contains('7'))
        );
    }
}
