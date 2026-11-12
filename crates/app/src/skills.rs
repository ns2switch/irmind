//! Analyst-authorized skill installation. Package text remains untrusted data.

mod compiled;
mod history;
mod operations;

use crate::{AppError, CancellationToken, Engine};
pub use compiled::CompiledSkill;
use irmind_domain::{SkillName, SkillPackage};
use std::path::Path;

pub trait SkillCompiler: Send + Sync {
    fn compile(&self, package: SkillPackage) -> Result<CompiledSkill, AppError>;
}

pub trait SkillPackageStore: Send + Sync {
    fn read_candidate(
        &self,
        directory: &Path,
        cancel: &CancellationToken,
    ) -> Result<SkillPackage, AppError>;
    fn names(&self) -> Result<Vec<SkillName>, AppError>;
    fn read_active(&self, name: &SkillName) -> Result<Option<SkillPackage>, AppError>;
    fn publish(&self, name: &SkillName, package: &SkillPackage) -> Result<(), AppError>;
    fn deactivate(&self, name: &SkillName) -> Result<(), AppError>;
    fn clean_temporary(&self) -> Result<usize, AppError>;
}

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SkillOrigin {
    Bundled,
    Organization,
    Analyst,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SkillServiceError {
    #[error("signed skill history is invalid")]
    InvalidHistory,
    #[error("skill history or installation count exceeds its limit")]
    HistoryLimit,
    #[error("at most 32 skills can be active")]
    ActiveLimit,
    #[error("skill is not installed")]
    NotInstalled,
    #[error("skill content was blocked by ContentGuard")]
    ContentBlocked,
    #[error("skill file is missing or changed; restore its approved version")]
    StorageMismatch,
    #[error("skill storage operation failed")]
    Storage,
    #[error("skill name conflicts with an existing command or installation")]
    NameConflict,
    #[error("bundled origin requires the compiled release inventory")]
    InvalidOrigin,
}

pub use history::ApprovedSkills;

#[derive(Clone, Debug)]
pub struct SkillStatus {
    pub name: SkillName,
    pub version: String,
    pub sha256: String,
    pub origin: SkillOrigin,
    pub active: bool,
    pub available: bool,
    /// Guarded text; renderers must still apply safe terminal escaping.
    pub description: String,
    pub warning: Option<String>,
}

impl Engine<'_> {
    pub(crate) fn check_skill_content(&self, compiled: &CompiledSkill) -> Result<(), AppError> {
        for resource in compiled.package().resources().values() {
            let screened = self.guard.screen(resource.untrusted_text())?;
            if !screened.detections.is_empty() {
                return Err(SkillServiceError::ContentBlocked.into());
            }
        }
        Ok(())
    }
}
