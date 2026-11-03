//! Local-calendar inference; the caller commits a candidate only after the row validates.
use super::AppError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct YearSequence {
    year: i32,
    previous_month: Option<u8>,
    rollover: bool,
}

impl YearSequence {
    pub(super) fn new(year: i32, rollover: bool) -> Result<Self, AppError> {
        if !(1..=9999).contains(&year) {
            return Err(super::invalid());
        }
        Ok(Self {
            year,
            previous_month: None,
            rollover,
        })
    }

    pub(super) fn year(self) -> i32 {
        self.year
    }

    /// Do not modify accepted state if a later header/date check rejects the row.
    pub(super) fn candidate(self, month: u8) -> Result<Self, AppError> {
        if !(1..=12).contains(&month) {
            return Err(super::invalid());
        }
        let mut next = self;
        if self.previous_month.is_some_and(|previous| month < previous) {
            if !self.rollover || self.previous_month != Some(12) || month != 1 {
                return Err(AppError::Policy(
                    "RFC 3164 month moved backward outside the confirmed year-rollover rule".into(),
                ));
            }
            next.year = next
                .year
                .checked_add(1)
                .filter(|year| *year <= 9999)
                .ok_or_else(super::invalid)?;
        }
        next.previous_month = Some(month);
        Ok(next)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::YearSequence;

    #[test]
    fn infers_only_confirmed_december_to_january_boundaries() {
        let start = YearSequence::new(2026, true).unwrap();
        let december = start.candidate(12).unwrap();
        let january = december.candidate(1).unwrap();
        assert_eq!(december.year(), 2026);
        assert_eq!(january.year(), 2027);
        assert_eq!(january.candidate(1).unwrap().year(), 2027);
        assert_eq!(
            january.candidate(12).unwrap().candidate(1).unwrap().year(),
            2028
        );
    }

    #[test]
    fn a_rejected_candidate_does_not_change_the_previous_accepted_state() {
        let december = YearSequence::new(2026, true)
            .unwrap()
            .candidate(12)
            .unwrap();
        assert!(december.candidate(11).is_err());
        assert_eq!(december.year(), 2026);
        assert_eq!(december.candidate(1).unwrap().year(), 2027);
        assert!(december.candidate(0).is_err());
        assert!(december.candidate(13).is_err());
    }

    #[test]
    fn disabled_rollover_and_year_overflow_fail_closed() {
        let fixed = YearSequence::new(2026, false)
            .unwrap()
            .candidate(12)
            .unwrap();
        assert!(fixed.candidate(1).is_err());
        assert!(
            YearSequence::new(9999, true)
                .unwrap()
                .candidate(12)
                .unwrap()
                .candidate(1)
                .is_err()
        );
        assert!(YearSequence::new(0, true).is_err());
        assert!(YearSequence::new(10000, true).is_err());
    }
}
