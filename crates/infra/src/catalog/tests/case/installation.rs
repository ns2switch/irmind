use super::*;
use futures_util::FutureExt as _;
use irmind_app::catalog::{
    AnalystCatalogRequest, CatalogAsset, PortFuture, SkillCatalogSource, VerifiedCatalogRelease,
};
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicUsize, Ordering},
};
fn package() -> BoundedPackageBytes {
    BoundedPackageBytes::new(include_bytes!(
        "../../../../../../docs/development/catalog-format-vectors/synthetic-triage-1.skill.json"
    ).to_vec()).unwrap()
}
#[test]
fn catalog_offline_preview_is_inert_and_admission_load_seal_export_are_complete() {
    let f = fixture_mode(false, false);
    let cancel = CancellationToken::new();
    let reserved = BTreeSet::new();
    let preview = f
        .engine
        .preview_catalog_offline(
            &bytes(INDEX),
            &FrozenCatalogRelease::new("v0.1.0").unwrap(),
            &package(),
            ("synthetic-triage", "0.5.0"),
            &reserved,
            &cancel,
        )
        .unwrap();
    assert!(preview.receipt().offline());
    assert!(!preview.downgrade_confirmation_required());
    assert_eq!(preview.differences(), "New installation.");
    assert!(f.engine.installed_skill_statuses().unwrap().is_empty());
    assert!(f.store.global_operations().unwrap().is_empty());
    let name = f
        .engine
        .confirm_catalog_preview(&preview, false, &reserved, &cancel)
        .unwrap();
    assert_eq!(name.as_str(), "synthetic-triage");
    let status = f.engine.installed_skill_statuses().unwrap();
    assert!(status[0].active && status[0].available);
    assert_eq!(status[0].origin, irmind_app::SkillOrigin::Catalog);
    let operation = &f.store.global_operations().unwrap()[0];
    assert!(operation.operation.starts_with("skill-installation-v2:"));
    let model = Model::default();
    f.engine
        .investigate(&f.case.id, "/synthetic-triage", &model)
        .unwrap();
    f.engine.verify(&f.case.id).unwrap();
    f.engine.seal(&f.case.id).unwrap();
    let path = f.root.path().join("offline.irmind");
    f.store.export_case(&f.case.id, &path, &cancel).unwrap();
    crate::seal::verify_export_with_catalog(&path, None, &f.store.catalog_verifier).unwrap();
}
#[test]
fn catalog_preview_rejects_cancellation_reserved_names_and_stale_admissions() {
    let f = fixture_mode(false, false);
    let cancel = CancellationToken::new();
    let release = FrozenCatalogRelease::new("v0.1.0").unwrap();
    let reserved = BTreeSet::from(["synthetic-triage".into()]);
    assert!(
        f.engine
            .preview_catalog_offline(
                &bytes(INDEX),
                &release,
                &package(),
                ("synthetic-triage", "0.5.0"),
                &reserved,
                &cancel
            )
            .is_err()
    );
    let reserved = BTreeSet::new();
    let preview = || {
        f.engine
            .preview_catalog_offline(
                &bytes(INDEX),
                &release,
                &package(),
                ("synthetic-triage", "0.5.0"),
                &reserved,
                &cancel,
            )
            .unwrap()
    };
    let first = preview();
    let stale = preview();
    f.engine
        .confirm_catalog_preview(&first, false, &reserved, &cancel)
        .unwrap();
    let count = f.store.global_operations().unwrap().len();
    assert!(
        f.engine
            .confirm_catalog_preview(&stale, false, &reserved, &cancel)
            .is_err()
    );
    assert_eq!(f.store.global_operations().unwrap().len(), count);
    let pending = preview();
    cancel.cancel();
    assert!(
        f.engine
            .confirm_catalog_preview(&pending, false, &reserved, &cancel)
            .is_err()
    );
    assert_eq!(f.store.global_operations().unwrap().len(), count);
}
struct Source {
    calls: AtomicUsize,
    tag: &'static str,
}
impl SkillCatalogSource for Source {
    fn index<'a>(
        &'a self,
        request: &'a AnalystCatalogRequest,
        _: &'a CancellationToken,
    ) -> PortFuture<'a, CatalogIndexBytes> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.name().as_str(), "synthetic-triage");
            assert!(request.tag().is_none());
            Ok(bytes(INDEX).with_resolved_tag(self.tag).unwrap())
        })
    }
    fn package<'a>(
        &'a self,
        release: &'a VerifiedCatalogRelease,
        asset: &'a CatalogAsset,
        _: &'a CancellationToken,
    ) -> PortFuture<'a, BoundedPackageBytes> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(release.tag(), "v0.1.0");
            assert_eq!(release.index_hash(), asset.index_hash());
            Ok(package())
        })
    }
}
#[test]
fn catalog_download_requires_explicit_analyst_request_and_freezes_latest_before_package() {
    let f = fixture_mode(false, false);
    let source = Source {
        calls: AtomicUsize::new(0),
        tag: "v0.1.0",
    };
    let request = f.engine.catalog_request("synthetic-triage", None).unwrap();
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    let preview = f
        .engine
        .download_catalog_preview(
            &source,
            &request,
            "0.5.0",
            &BTreeSet::new(),
            &CancellationToken::new(),
        )
        .now_or_never()
        .unwrap()
        .unwrap();
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    assert!(!preview.receipt().offline());
    assert!(f.store.global_operations().unwrap().is_empty());
}

fn extended_keys() -> &'static [[u8; 32]] {
    static EXTENDED: std::sync::OnceLock<[[u8; 32]; 2]> = std::sync::OnceLock::new();
    EXTENDED.get_or_init(|| {
        [
            keys()[0],
            SigningKey::from_bytes(&[88; 32]).verifying_key().to_bytes(),
        ]
    })
}
fn release(tag: &str, sequence: u64, commit: char) -> CatalogIndexBytes {
    use ed25519_dalek::Signer as _;
    let key = SigningKey::from_bytes(&[88; 32]);
    let mut value: serde_json::Value = serde_json::from_slice(INDEX).unwrap();
    value["release_tag"] = tag.into();
    value["release_sequence"] = sequence.into();
    value["release_commit"] = commit.to_string().repeat(40).into();
    value["key_id"] = irmind_app::hex(&irmind_app::sha256(&key.verifying_key().to_bytes())).into();
    let index: irmind_app::catalog::CatalogIndex = serde_json::from_value(value).unwrap();
    let raw = CatalogIndexBytes::new(serde_json::to_vec(&index).unwrap(), &[0; 64]).unwrap();
    let signature = key.sign(&raw.signature_preimage());
    CatalogIndexBytes::new(raw.index().to_vec(), &signature.to_bytes()).unwrap()
}
#[test]
fn catalog_history_rejects_equivocation_and_retains_downgrade_high_water_across_disable() {
    let f = fixture_keys(false, false, extended_keys());
    let cancel = CancellationToken::new();
    let reserved = BTreeSet::new();
    let preview = |raw: &CatalogIndexBytes, tag| {
        f.engine.preview_catalog_offline(
            raw,
            &FrozenCatalogRelease::new(tag).unwrap(),
            &package(),
            ("synthetic-triage", "0.5.0"),
            &reserved,
            &cancel,
        )
    };
    let newer = release("v0.2.0", 2, 'b');
    let prepared = preview(&newer, "v0.2.0").unwrap();
    f.engine
        .confirm_catalog_preview(&prepared, false, &reserved, &cancel)
        .unwrap();
    for (raw, tag) in [
        (release("v0.2.0", 2, 'c'), "v0.2.0"),
        (release("v0.3.0", 2, 'b'), "v0.3.0"),
        (release("v0.2.0", 3, 'b'), "v0.2.0"),
    ] {
        assert!(preview(&raw, tag).is_err());
    }
    let older = bytes(INDEX);
    let prepared = preview(&older, "v0.1.0").unwrap();
    assert!(prepared.downgrade_confirmation_required());
    assert!(
        f.engine
            .confirm_catalog_preview(&prepared, false, &reserved, &cancel)
            .is_err()
    );
    let prepared = preview(&older, "v0.1.0").unwrap();
    let name = f
        .engine
        .confirm_catalog_preview(&prepared, true, &reserved, &cancel)
        .unwrap();
    let services = f.engine.skill_services().unwrap();
    f.engine
        .set_skill_active(services.package_store(), services.compiler(), &name, false)
        .unwrap();
    assert!(
        preview(&older, "v0.1.0")
            .unwrap()
            .downgrade_confirmation_required()
    );
    let operations = f.store.global_operations().unwrap();
    let last = operations
        .last()
        .unwrap()
        .operation
        .strip_prefix("skill-installation-v2:")
        .unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(&hex::decode(last).unwrap()).unwrap();
    assert_eq!(snapshot["catalog"]["downgrade_confirmed"], true);
}

struct RefusingSigner;
impl Signer for RefusingSigner {
    fn actor(&self) -> Actor {
        Actor::Analyst
    }
    fn public_key(&self) -> Vec<u8> {
        SigningKey::from_bytes(&[42; 32])
            .verifying_key()
            .to_bytes()
            .to_vec()
    }
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, AppError> {
        Err(AppError::Storage("synthetic signing failure".into()))
    }
}
#[test]
fn catalog_signature_failure_and_unattended_requests_never_admit_or_publish_a_package() {
    let f = fixture_mode(false, false);
    let engine = new_engine(
        f.root.path(),
        f.store.clone(),
        Arc::new(RefusingSigner),
        ExecutionMode::Attended,
    );
    let cancel = CancellationToken::new();
    let reserved = BTreeSet::new();
    let preview = engine
        .preview_catalog_offline(
            &bytes(INDEX),
            &FrozenCatalogRelease::new("v0.1.0").unwrap(),
            &package(),
            ("synthetic-triage", "0.5.0"),
            &reserved,
            &cancel,
        )
        .unwrap();
    assert!(
        engine
            .confirm_catalog_preview(&preview, false, &reserved, &cancel)
            .is_err()
    );
    assert!(f.store.global_operations().unwrap().is_empty());
    let services = engine.skill_services().unwrap();
    assert!(
        services
            .package_store()
            .read_active(&irmind_domain::SkillName::parse("synthetic-triage").unwrap())
            .unwrap()
            .is_none()
    );
    let unattended = new_engine(
        f.root.path(),
        f.store.clone(),
        Arc::new(LocalSigner {
            actor: Actor::Analyst,
            key: SigningKey::from_bytes(&[42; 32]),
        }),
        ExecutionMode::Unattended,
    );
    assert!(
        unattended
            .catalog_request("synthetic-triage", None)
            .is_err()
    );
    assert!(
        unattended
            .preview_catalog_offline(
                &bytes(INDEX),
                &FrozenCatalogRelease::new("v0.1.0").unwrap(),
                &package(),
                ("synthetic-triage", "0.5.0"),
                &reserved,
                &cancel
            )
            .is_err()
    );
}

#[test]
fn catalog_misleading_latest_metadata_never_fetches_a_package_or_signs() {
    let f = fixture_mode(false, false);
    let source = Source {
        calls: AtomicUsize::new(0),
        tag: "v0.2.0",
    };
    let request = f.engine.catalog_request("synthetic-triage", None).unwrap();
    let result = f
        .engine
        .download_catalog_preview(
            &source,
            &request,
            "0.5.0",
            &BTreeSet::new(),
            &CancellationToken::new(),
        )
        .now_or_never()
        .unwrap();
    assert!(result.is_err());
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    assert!(f.store.global_operations().unwrap().is_empty());
}

#[test]
fn configured_catalog_source_uses_the_composed_runtime_and_remains_inert_until_confirmation() {
    let f = fixture_mode(false, false);
    let source = Arc::new(Source {
        calls: AtomicUsize::new(0),
        tag: "v0.1.0",
    });
    let agent = Arc::new(LocalSigner {
        actor: Actor::Agent(AgentId::parse("skills-agent").unwrap()),
        key: SigningKey::from_bytes(&[44; 32]),
    });
    let services = SkillServices::new(
        Arc::new(crate::FileSkillPackageStore::new(f.root.path())),
        Arc::new(TomlSkillCompiler),
        agent,
        vec![],
    )
    .unwrap()
    .with_catalog(
        f.store
            .catalog_services()
            .with_source(source.clone(), "0.5.0")
            .unwrap(),
    );
    let engine = f.engine.with_skills(services).unwrap();
    let cancel = CancellationToken::new();
    let preview = engine
        .configured_catalog_preview("synthetic-triage", None, &BTreeSet::new(), &cancel)
        .unwrap();
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    assert!(f.store.global_operations().unwrap().is_empty());
    assert!(!preview.receipt().offline());
    engine
        .confirm_catalog_preview(&preview, false, &BTreeSet::new(), &cancel)
        .unwrap();
    assert!(engine.installed_skill_statuses().unwrap()[0].available);
}
