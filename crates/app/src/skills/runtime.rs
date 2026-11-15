//! Local, explicitly composed capabilities for progressive methodology loading.
mod catalog;
mod loading;
mod proof;
use crate::{
    AppError, CompiledSkill, Engine, Signer, SkillCompiler, SkillPackageStore, SkillSnapshotId,
    SkillSnapshotV2, sha256,
};
use irmind_domain::{Actor, SkillName, SkillPackage};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub struct SkillServices {
    pub(crate) store: Arc<dyn SkillPackageStore>,
    pub(crate) compiler: Arc<dyn SkillCompiler>,
    pub(crate) agent: Arc<dyn Signer>,
    pub(crate) bundled: BTreeMap<SkillName, SkillPackage>,
    inventory: [u8; 32],
    pub(crate) catalog: Option<crate::catalog::CatalogServices>,
}
impl SkillServices {
    pub fn new(
        store: Arc<dyn SkillPackageStore>,
        compiler: Arc<dyn SkillCompiler>,
        agent: Arc<dyn Signer>,
        packages: Vec<SkillPackage>,
    ) -> Result<Self, AppError> {
        if !matches!(agent.actor(), Actor::Agent(_)) || packages.len() > 32 {
            return Err(super::receipts::invalid());
        }
        let mut bundled = BTreeMap::new();
        for package in packages {
            let skill = compiler.compile(package.clone())?;
            if bundled
                .insert(skill.metadata().name().clone(), package)
                .is_some()
            {
                return Err(super::SkillServiceError::NameConflict.into());
            }
        }
        let mut bytes = b"irmind-bundled-skill-inventory-v1\0".to_vec();
        bytes.extend_from_slice(&(bundled.len() as u64).to_be_bytes());
        for (name, package) in &bundled {
            let skill = compiler.compile(package.clone())?;
            for text in [name.as_str(), skill.metadata().version().as_str()] {
                bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
                bytes.extend_from_slice(text.as_bytes());
            }
            bytes.extend_from_slice(package.hash().as_bytes());
        }
        Ok(Self {
            store,
            compiler,
            agent,
            bundled,
            inventory: sha256(&bytes),
            catalog: None,
        })
    }
    #[must_use]
    pub fn with_catalog(mut self, catalog: crate::catalog::CatalogServices) -> Self {
        self.catalog = Some(catalog);
        self
    }
    pub fn package_store(&self) -> &dyn SkillPackageStore {
        self.store.as_ref()
    }
    pub fn compiler(&self) -> &dyn SkillCompiler {
        self.compiler.as_ref()
    }
}
#[derive(Default)]
pub(crate) struct SkillTurn {
    packages: BTreeSet<SkillSnapshotId>,
    reads: usize,
    bytes: usize,
    pub(crate) active: Option<ActiveSkill>,
    pub(crate) read_limit: usize,
}
#[derive(Clone)]
pub(crate) struct ActiveSkill {
    pub(crate) name: SkillName,
    pub(crate) package: irmind_domain::SkillDigest,
    pub(crate) tools: BTreeSet<String>,
}
pub(crate) struct ResolvedSkill {
    pub(crate) skill: CompiledSkill,
    snapshot: SkillSnapshotV2,
    catalog: Option<crate::catalog::VerifiedCatalogIndex>,
}
impl Engine<'_> {
    pub fn with_skills(mut self, services: SkillServices) -> Result<Self, AppError> {
        let trusted = self.verifier.trusted_public_key(&services.agent.actor())?;
        if trusted != services.agent.public_key() {
            return Err(super::receipts::invalid());
        }
        self.skills = Some(Arc::new(services));
        Ok(self)
    }
    pub fn skill_services(&self) -> Option<&SkillServices> {
        self.skills.as_deref()
    }
    pub(crate) fn verify_skill_receipts(
        &self,
        entries: &[crate::SignedEntry],
        cancel: &crate::CancellationToken,
    ) -> Result<(), AppError> {
        if entries
            .iter()
            .any(|entry| entry.kind == crate::AuditEventKind::RetiredSkillSnapshot)
        {
            return Err(AppError::Fixed(crate::FixedAppError::RetiredCaseFormat));
        }
        if !entries.iter().any(|e| {
            matches!(
                e.kind,
                crate::AuditEventKind::SkillSnapshotV2 | crate::AuditEventKind::SkillLoadV1
            ) || crate::subagents::is_subagent_kind(e.kind)
        }) {
            return Ok(());
        }
        let services = self
            .skills
            .as_ref()
            .ok_or(super::SkillServiceError::NotInstalled)?;
        let mut checked = super::SkillReceiptVerifier::default();
        for entry in entries {
            checked.accept(entry, services.compiler.as_ref())?;
        }
        checked.verify_bundled(
            &services.bundled.values().cloned().collect::<Vec<_>>(),
            services.compiler.as_ref(),
        )?;
        let refs = checked.admissions();
        let mut proofs: Vec<_> = self
            .audit_log
            .global_operations()?
            .into_iter()
            .filter(|p| refs.contains(&crate::hex(&p.hash)))
            .collect();
        proofs.sort_by_key(|p| p.hash);
        let analyst = self.verifier.trusted_public_key(&Actor::Analyst)?;
        let requirements =
            checked.catalog_requirements(&proofs, self.verifier.as_ref(), &analyst)?;
        let mut indices = Vec::with_capacity(requirements.len());
        for requirement in requirements {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            let catalog = services
                .catalog
                .as_ref()
                .ok_or(crate::catalog::CatalogError::Unavailable)?;
            let case = crate::CaseId::parse(
                &entries
                    .first()
                    .ok_or_else(super::receipts::invalid)?
                    .case_id,
            )
            .map_err(|_| super::receipts::invalid())?;
            indices.push(catalog.read_case(&case, &requirement, cancel)?);
        }
        checked.verify_catalog_admissions(
            &proofs,
            &indices,
            self.verifier.as_ref(),
            &analyst,
            services.compiler.as_ref(),
        )?;
        self.verify_subagent_receipts(entries, &mut checked, services, cancel)
    }
    fn verify_subagent_receipts(
        &self,
        entries: &[crate::SignedEntry],
        checked: &mut super::SkillReceiptVerifier,
        services: &SkillServices,
        cancel: &crate::CancellationToken,
    ) -> Result<(), AppError> {
        if !entries
            .iter()
            .any(|entry| crate::subagents::is_subagent_kind(entry.kind))
        {
            return Ok(());
        }
        let case = crate::CaseId::parse(
            &entries
                .first()
                .ok_or_else(super::receipts::invalid)?
                .case_id,
        )
        .map_err(|_| super::receipts::invalid())?;
        let mut journal = crate::subagents::SubagentJournal::new(case, services.agent.actor())
            .map_err(|_| super::receipts::invalid())?;
        for entry in entries {
            if cancel.is_cancelled() {
                return Err(AppError::Cancelled);
            }
            journal.accept(entry, self.verifier.as_ref())?;
        }
        let ports = self
            .subagents
            .as_ref()
            .ok_or_else(super::receipts::invalid)?;
        journal.verify_stored_branches(
            ports.branches.as_ref(),
            self.verifier.as_ref(),
            checked,
            services.compiler.as_ref(),
            cancel,
        )?;
        Ok(())
    }
}
