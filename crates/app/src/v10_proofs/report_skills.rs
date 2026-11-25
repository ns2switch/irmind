//! Coverage coordinates observed during the verified skill and branch replay.
use super::{V10AuditReference, V10DelegatedSkillGap};
use crate::{AppError, CompiledSkill};
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
pub enum ReportSkillLoad {
    Main(V10AuditReference),
    Delegated {
        checkpoint: V10AuditReference,
        task_id: [u8; 32],
        load_sequence: u64,
        load_sha256: [u8; 32],
    },
}

impl ReportSkillLoad {
    pub const fn main_sequence(self) -> u64 {
        match self {
            Self::Main(reference) => reference.sequence,
            Self::Delegated { checkpoint, .. } => checkpoint.sequence,
        }
    }
}

pub struct ResolvedReportSkillGap {
    pub load: ReportSkillLoad,
    pub index: u64,
    pub skill: String,
    pub text: String,
}

impl ResolvedReportSkillGap {
    pub(crate) fn key(&self) -> (u64, [u8; 32], u64, u64) {
        match self.load {
            ReportSkillLoad::Main(reference) => (reference.sequence, [0; 32], 0, self.index),
            ReportSkillLoad::Delegated {
                checkpoint,
                task_id,
                load_sequence,
                ..
            } => (checkpoint.sequence, task_id, load_sequence, self.index),
        }
    }

    pub fn delegated_reference(&self) -> Option<V10DelegatedSkillGap> {
        let ReportSkillLoad::Delegated {
            checkpoint,
            task_id,
            load_sequence,
            load_sha256,
        } = self.load
        else {
            return None;
        };
        Some(V10DelegatedSkillGap {
            checkpoint,
            task_id,
            load_sequence,
            load_sha256,
            gap_index: self.index,
        })
    }
}

pub(crate) fn report_skill_declarations(
    skill: &CompiledSkill,
    sources: &BTreeSet<String>,
) -> Result<(String, Vec<Option<String>>), AppError> {
    let mut declarations = skill
        .metadata()
        .sources()
        .iter()
        .map(|source| (!sources.contains(source)).then(|| format!("No signed source for {source}")))
        .collect::<Vec<_>>();
    if let Some(resource) = skill
        .package()
        .resources()
        .values()
        .find(|file| file.path().as_str() == "references/coverage.csv")
    {
        use crate::source_mapping::framed::csv_values;
        let mut lines = resource.untrusted_text().lines();
        let header = csv_values(lines.next().unwrap_or_default().as_bytes())?;
        let mut columns = header
            .iter()
            .enumerate()
            .filter(|(_, name)| matches!(name.as_str(), "coverage_limit" | "coverage_limits"));
        let Some((column, _)) = columns.next() else {
            return Ok((skill.metadata().name().as_str().into(), declarations));
        };
        if columns.next().is_some() {
            return Err(AppError::Policy(
                "Ambiguous skill coverage declarations".into(),
            ));
        }
        for line in lines.filter(|line| !line.trim().is_empty()) {
            let fields = csv_values(line.as_bytes())?;
            if fields.len() != header.len() {
                return Err(AppError::Policy(
                    "Invalid skill coverage declaration".into(),
                ));
            }
            declarations.push((!fields[column].trim().is_empty()).then(|| fields[column].clone()));
        }
    }
    Ok((skill.metadata().name().as_str().into(), declarations))
}
