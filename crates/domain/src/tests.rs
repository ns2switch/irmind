use crate::*;

fn case() -> Case {
    Case {
        id: CaseId::parse("00000000-0000-0000-0000-000000000001").unwrap(),
        title: "x".into(),
        severity: Severity::Medium,
        scope: "local".into(),
        sealed: false,
    }
}

mod object_scope;
mod scope;
mod scope_v2;
mod taint_and_unattended;
