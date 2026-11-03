use crate::{AppError, ParserTimeContext};

/// Source-calendar state only. A parser commits a candidate after validating the complete row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserCalendar {
    year: u16,
    previous_month: Option<u8>,
    rollover: bool,
}
impl ParserCalendar {
    #[must_use]
    pub const fn new(context: ParserTimeContext) -> Self {
        Self {
            year: context.year(),
            previous_month: None,
            rollover: context.rollover(),
        }
    }
    #[must_use]
    pub const fn year(self) -> u16 {
        self.year
    }
    pub fn candidate(self, month: u8) -> Result<Self, AppError> {
        if !(1..=12).contains(&month) {
            return Err(invalid());
        }
        let mut next = self;
        if self.previous_month.is_some_and(|previous| month < previous) {
            if !self.rollover || self.previous_month != Some(12) || month != 1 {
                return Err(invalid());
            }
            next.year = self
                .year
                .checked_add(1)
                .filter(|year| *year <= 9999)
                .ok_or_else(invalid)?;
        }
        next.previous_month = Some(month);
        Ok(next)
    }
}
fn invalid() -> AppError {
    AppError::Policy("source month moved backward outside the confirmed year-rollover rule or exceeded the calendar bounds".into())
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn calendar(year: u16, rollover: bool) -> ParserCalendar {
        ParserCalendar::new(
            ParserTimeContext::new(year, 0, rollover, crate::ParserTimeBasis::Analyst).unwrap(),
        )
    }
    #[test]
    fn only_confirmed_december_to_january_advances_the_year() {
        let december = calendar(2026, true).candidate(12).unwrap();
        let january = december.candidate(1).unwrap();
        assert_eq!(january.year(), 2027);
        assert_eq!(january.candidate(1).unwrap().year(), 2027);
        assert_eq!(
            january.candidate(12).unwrap().candidate(1).unwrap().year(),
            2028
        );
    }
    #[test]
    fn disabled_rollover_invalid_months_and_year_overflow_are_rejected() {
        assert!(
            calendar(2026, false)
                .candidate(12)
                .unwrap()
                .candidate(1)
                .is_err()
        );
        assert!(
            calendar(9999, true)
                .candidate(12)
                .unwrap()
                .candidate(1)
                .is_err()
        );
        assert!(calendar(2026, true).candidate(0).is_err());
        assert!(calendar(2026, true).candidate(13).is_err());
    }
    #[test]
    fn a_rejected_candidate_leaves_the_accepted_state_unchanged() {
        let december = calendar(2026, true).candidate(12).unwrap();
        assert!(december.candidate(11).is_err());
        assert_eq!(december.year(), 2026);
        assert_eq!(december.candidate(1).unwrap().year(), 2027);
    }
}
