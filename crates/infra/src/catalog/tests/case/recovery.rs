use super::*;
use irmind_app::{CompiledSkill, SkillCompiler, SkillPackageStore};
use irmind_domain::{SkillName, SkillPackage};
use std::path::Path;
struct FailPublication(crate::FileSkillPackageStore);
impl SkillPackageStore for FailPublication {
    fn read_candidate(
        &self,
        path: &Path,
        cancel: &CancellationToken,
    ) -> Result<SkillPackage, AppError> {
        self.0.read_candidate(path, cancel)
    }
    fn names(&self) -> Result<Vec<SkillName>, AppError> {
        self.0.names()
    }
    fn read_active(&self, name: &SkillName) -> Result<Option<SkillPackage>, AppError> {
        self.0.read_active(name)
    }
    fn publish(&self, _: &SkillName, _: &SkillPackage) -> Result<(), AppError> {
        Err(AppError::Storage("synthetic publication failure".into()))
    }
    fn deactivate(&self, name: &SkillName) -> Result<(), AppError> {
        self.0.deactivate(name)
    }
    fn clean_temporary(&self) -> Result<usize, AppError> {
        self.0.clean_temporary()
    }
}
#[test]
fn catalog_failed_publication_requires_explicit_recovery_against_the_current_proof() {
    let f = fixture_mode(false, false);
    let store = crate::FileSkillPackageStore::new(f.root.path());
    let agent = Arc::new(LocalSigner {
        actor: Actor::Agent(AgentId::parse("skills-agent").unwrap()),
        key: SigningKey::from_bytes(&[44; 32]),
    });
    let services = SkillServices::new(
        Arc::new(FailPublication(crate::FileSkillPackageStore::new(
            f.root.path(),
        ))),
        Arc::new(TomlSkillCompiler),
        agent,
        vec![],
    )
    .unwrap()
    .with_catalog(f.store.catalog_services());
    let engine = f.engine.with_skills(services).unwrap();
    let package = BoundedPackageBytes::new(include_bytes!(
        "../../../../../../docs/development/catalog-format-vectors/synthetic-triage-1.skill.json"
    ).to_vec()).unwrap();
    let cancel = CancellationToken::new();
    let reserved = std::collections::BTreeSet::new();
    let preview = engine
        .preview_catalog_offline(
            &bytes(INDEX),
            &FrozenCatalogRelease::new("v0.1.0").unwrap(),
            &package,
            ("synthetic-triage", "0.5.0"),
            &reserved,
            &cancel,
        )
        .unwrap();
    assert!(
        engine
            .confirm_catalog_preview(preview, false, &reserved, &cancel)
            .is_err()
    );
    assert_eq!(f.store.global_operations().unwrap().len(), 1);
    let name = SkillName::parse("synthetic-triage").unwrap();
    assert!(store.read_active(&name).unwrap().is_none());
    assert!(!engine.installed_skill_statuses().unwrap()[0].available);
    engine
        .restore_skill(&store, &TomlSkillCompiler, &name)
        .unwrap();
    assert!(engine.installed_skill_statuses().unwrap()[0].available);
    assert_eq!(f.store.global_operations().unwrap().len(), 1);
    let compiled: CompiledSkill = TomlSkillCompiler
        .compile(store.read_active(&name).unwrap().unwrap())
        .unwrap();
    assert_eq!(compiled.metadata().name(), &name);
}
