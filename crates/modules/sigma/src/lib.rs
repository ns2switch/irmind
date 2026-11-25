#![forbid(unsafe_code)]

//! Bounded local Sigma rule admission. The evaluator receives typed values.
mod admission;

pub use admission::{AdmissionError, RuleDocument, RuleValue, admit_rule};

mod condition;
mod matcher;
pub use condition::ConditionError;
pub use matcher::{
    CompileError, EvaluationError, SigmaField, SigmaFieldKind, SigmaProgram, SigmaScalar,
};
