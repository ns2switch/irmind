//! Local, explicitly composed capabilities for progressive methodology loading.
mod catalog;
mod loading;
use crate::{
    AppError, CompiledSkill, Engine, Signer, SkillCompiler, SkillPackageStore, SkillSnapshotId,
    SkillSnapshotV1, sha256,
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
        })
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
    snapshot: SkillSnapshotV1,
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
    ) -> Result<(), AppError> {
        if !entries.iter().any(|e| {
            matches!(
                e.kind,
                crate::AuditEventKind::SkillSnapshotV1 | crate::AuditEventKind::SkillLoadV1
            )
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
        let refs = checked.admissions();
        let mut proofs: Vec<_> = self
            .audit_log
            .global_operations()?
            .into_iter()
            .filter(|p| refs.contains(&crate::hex(&p.hash)))
            .collect();
        proofs.sort_by_key(|p| p.hash);
        checked.verify_admissions(
            &proofs,
            self.verifier.as_ref(),
            &self.verifier.trusted_public_key(&Actor::Analyst)?,
        )
    }
}
