//! Bundled trust is bound to this release's exact package inventory.
use super::{SkillReceiptVerifier, invalid};
use crate::{AppError, SkillCompiler, SkillOrigin, hex, sha256};
use irmind_domain::SkillPackage;
use std::collections::BTreeMap;

impl SkillReceiptVerifier {
    pub fn verify_bundled(
        &self,
        packages: &[SkillPackage],
        compiler: &dyn SkillCompiler,
    ) -> Result<(), AppError> {
        let mut inventory_skills = BTreeMap::new();
        if packages.len() > 32 {
            return Err(invalid());
        }
        for package in packages {
            let skill = compiler.compile(package.clone())?;
            if inventory_skills
                .insert(skill.metadata().name().clone(), skill)
                .is_some()
            {
                return Err(invalid());
            }
        }
        let mut bytes = b"irmind-bundled-skill-inventory-v1\0".to_vec();
        bytes.extend_from_slice(&(inventory_skills.len() as u64).to_be_bytes());
        for (name, skill) in &inventory_skills {
            for text in [name.as_str(), skill.metadata().version().as_str()] {
                bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
                bytes.extend_from_slice(text.as_bytes());
            }
            bytes.extend_from_slice(skill.package().hash().as_bytes());
        }
        let inventory = hex(&sha256(&bytes));
        for snapshot in self.snapshots() {
            let skill = snapshot.compile(compiler)?;
            match snapshot.origin() {
                SkillOrigin::Bundled
                    if snapshot.inventory() != Some(inventory.as_str())
                        || inventory_skills
                            .get(skill.metadata().name())
                            .map(crate::CompiledSkill::package)
                            != Some(skill.package()) =>
                {
                    return Err(invalid());
                }
                SkillOrigin::Catalog if inventory_skills.contains_key(skill.metadata().name()) => {
                    return Err(invalid());
                }
                _ => {}
            }
        }
        Ok(())
    }
}
