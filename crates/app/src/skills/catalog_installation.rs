//! Explicit preview/admission transaction; publisher trust never grants execution.
mod diff;
use super::history::Snapshot;
use crate::catalog::{
    BoundedPackageBytes, CatalogAsset, CatalogInstallPreview, CatalogReceipt, FrozenCatalogRelease,
    VerifiedCatalogIndex, check_release_history, older_or_unknown,
};
use crate::{AppError, CancellationToken, Engine, SkillOrigin, SkillServiceError};
use irmind_domain::SkillName;
use std::collections::BTreeSet;

impl Engine<'_> {
    pub(crate) fn build_catalog_preview(
        &self,
        index: VerifiedCatalogIndex,
        asset: &CatalogAsset,
        package: &BoundedPackageBytes,
        mode: (&str, bool),
        reserved: &BTreeSet<String>,
        cancel: &CancellationToken,
    ) -> Result<CatalogInstallPreview, AppError> {
        self.require_attended_analyst("review a catalog skill")?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let services = self
            .skill_services()
            .ok_or(SkillServiceError::NotInstalled)?;
        let skill = asset.compile(package, mode.0, services.compiler.as_ref())?;
        self.check_skill_content(&skill)?;
        self.catalog_name_available(skill.metadata().name(), reserved)?;
        let history = self.approved_skills(services.compiler.as_ref())?;
        let old = history.latest.get(skill.metadata().name());
        let downgrade = check_release_history(&index, &history.catalog_history)?
            || old.is_some_and(|old| {
                older_or_unknown(
                    skill.metadata().version().as_str(),
                    &old.snapshot.skill_version,
                )
            });
        let receipt = CatalogReceipt::new(&index, skill.metadata().name().as_str(), mode.1, false)?;
        receipt.check(&index, &skill)?;
        let differences = self.catalog_differences(old.map(|o| &o.snapshot), &skill)?;
        Ok(CatalogInstallPreview {
            skill,
            index,
            receipt,
            previous: old.map(|o| o.operation_hash.clone()),
            downgrade,
            differences,
        })
    }
    pub fn confirm_catalog_preview(
        &self,
        preview: &CatalogInstallPreview,
        downgrade_confirmed: bool,
        reserved: &BTreeSet<String>,
        cancel: &CancellationToken,
    ) -> Result<SkillName, AppError> {
        self.require_attended_analyst("admit a catalog skill")?;
        let services = self
            .skill_services()
            .ok_or(SkillServiceError::NotInstalled)?;
        let catalog = services
            .catalog
            .as_ref()
            .ok_or(crate::catalog::CatalogError::Unavailable)?;
        let _lock = self.audit_log.lock_global_operations()?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let index = catalog.verifier.verify(
            preview.index.raw(),
            &FrozenCatalogRelease::new(preview.receipt.release_tag())?,
        )?;
        let skill = services.compiler.compile(preview.skill.package().clone())?;
        preview.receipt.check(&index, &skill)?;
        self.check_skill_content(&skill)?;
        self.catalog_name_available(skill.metadata().name(), reserved)?;
        let history = self.approved_skills(services.compiler.as_ref())?;
        let old = history.latest.get(skill.metadata().name());
        if old.map(|o| &o.operation_hash) != preview.previous.as_ref() {
            return Err(AppError::Policy(
                "The installed skill changed after this preview; review it again.".into(),
            ));
        }
        let downgrade = check_release_history(&index, &history.catalog_history)?
            || old.is_some_and(|o| {
                older_or_unknown(
                    skill.metadata().version().as_str(),
                    &o.snapshot.skill_version,
                )
            });
        if downgrade && !downgrade_confirmed {
            return Err(AppError::Policy(
                "A catalog or package downgrade needs separate Analyst confirmation.".into(),
            ));
        }
        if catalog.proofs.publish(&index, cancel)? != index.proof_id() {
            return Err(super::history::invalid());
        }
        catalog.read_global(&preview.receipt, &skill, cancel)?;
        if cancel.is_cancelled() {
            return Err(AppError::Cancelled);
        }
        let mut snapshot = Snapshot::new(&skill, SkillOrigin::Catalog);
        snapshot.previous_operation.clone_from(&preview.previous);
        snapshot.active = old.is_none_or(|o| o.snapshot.active);
        snapshot.catalog = Some(CatalogReceipt::new(
            &index,
            skill.metadata().name().as_str(),
            preview.receipt.offline(),
            downgrade && downgrade_confirmed,
        )?);
        self.commit_skill_snapshot(
            services.store.as_ref(),
            services.compiler.as_ref(),
            &snapshot,
        )
    }
    fn catalog_name_available(
        &self,
        name: &SkillName,
        reserved: &BTreeSet<String>,
    ) -> Result<(), AppError> {
        if reserved.contains(name.as_str())
            || self
                .skills
                .as_ref()
                .is_some_and(|s| s.bundled.contains_key(name))
        {
            return Err(SkillServiceError::NameConflict.into());
        }
        Ok(())
    }
}
