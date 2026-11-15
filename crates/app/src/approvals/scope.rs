//! Read historical request scope; execution still checks the current case.
use crate::{Actor, AppError, AuditEventKind, Case, CaseScope, SignedEntry};
use serde::Deserialize;

#[derive(Default)]
pub(super) struct ScopeReplay(Option<String>);
#[derive(Deserialize)]
struct Created {
    version: u8,
    scope: String,
}
#[derive(Deserialize)]
struct Changed {
    version: u8,
    previous_scope: String,
    new_scope: String,
}
impl ScopeReplay {
    pub(super) fn accept(&mut self, entry: &SignedEntry) -> Result<(), AppError> {
        let invalid = || AppError::InvalidChain(entry.seq);
        match entry.kind {
            AuditEventKind::CaseCreated => {
                let value: Created = serde_json::from_str(&entry.payload).map_err(|_| invalid())?;
                if self.0.is_some() || value.version != 4 || entry.actor != Actor::Analyst {
                    return Err(invalid());
                }
                CaseScope::parse(&value.scope).map_err(|_| invalid())?;
                self.0 = Some(value.scope);
            }
            AuditEventKind::CaseScopeChanged => {
                let value: Changed = serde_json::from_str(&entry.payload).map_err(|_| invalid())?;
                if value.version != 1
                    || entry.actor != Actor::Analyst
                    || self.0.as_deref() != Some(value.previous_scope.as_str())
                {
                    return Err(invalid());
                }
                CaseScope::parse(&value.new_scope).map_err(|_| invalid())?;
                self.0 = Some(value.new_scope);
            }
            _ => {}
        }
        Ok(())
    }
    pub(super) fn case(&self, case: &Case, seq: u64) -> Result<Case, AppError> {
        let mut historical = case.clone();
        historical.scope = self.0.clone().ok_or(AppError::InvalidChain(seq))?;
        Ok(historical)
    }
}
pub(super) fn case_at(case: &Case, entries: &[SignedEntry], seq: u64) -> Result<Case, AppError> {
    let mut replay = ScopeReplay::default();
    for entry in entries.iter().take_while(|entry| entry.seq <= seq) {
        replay.accept(entry)?;
    }
    replay.case(case, seq)
}
