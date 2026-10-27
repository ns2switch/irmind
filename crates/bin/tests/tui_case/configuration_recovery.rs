use super::*;
use irmind_app::{ConfigChange, ConfigurationInspection, PersistentConfig};
use irmind_infra::TomlConfigurationStore;

fn setup() -> (
    tempfile::TempDir,
    Arc<LocalStore>,
    Engine<'static>,
    TomlConfigurationStore,
) {
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(LocalStore::open(root.path()).unwrap());
    let signer = Arc::new(support::TestSigner(SigningKey::from_bytes(&[121u8; 32])));
    let engine = Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(
                signer.clone(),
                Arc::new(LocalVerifier::from_signer(signer.as_ref())),
            ),
            Arc::new(MandatoryGuard::new().unwrap()),
            Arc::new(JsonParser),
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )
    .unwrap();
    let config = TomlConfigurationStore::new(root.path());
    (root, store, engine, config)
}

fn model(value: &str) -> ConfigChange {
    ConfigChange::SetValue {
        module: "llm-openai-compatible".into(),
        field: "IRMIND_MODEL".into(),
        value: value.into(),
    }
}

struct FailSave<'a> {
    store: &'a TomlConfigurationStore,
}

impl ConfigurationStore for FailSave<'_> {
    fn load(&self) -> Result<PersistentConfig, AppError> {
        self.store.load()
    }
    fn save(&self, _: &PersistentConfig) -> Result<(), AppError> {
        Err(AppError::Fixed(
            irmind_app::FixedAppError::PolicyInvalidPublicConfiguration,
        ))
    }
}

#[test]
fn signed_snapshot_restores_after_crash_before_file_write() {
    let (_root, audit, engine, file) = setup();
    let manifests = [&irmind_mod_llm_openai_compatible::MANIFEST];
    assert!(
        engine
            .apply_configuration_change(
                &FailSave { store: &file },
                &manifests,
                model("synthetic"),
                false
            )
            .is_err()
    );
    let review = match engine
        .inspect_configuration(&file, &manifests, false)
        .unwrap()
    {
        ConfigurationInspection::Review(review) => Some(review),
        ConfigurationInspection::Current => None,
    }
    .unwrap();
    assert!(review.file_missing);
    assert!(review.approved.is_some());
    assert_eq!(audit.global_operations().unwrap().len(), 1);
    engine
        .restore_approved_configuration(&file, &manifests, false)
        .unwrap();
    assert_eq!(
        file.load().unwrap().modules["llm-openai-compatible"].values["IRMIND_MODEL"],
        "synthetic"
    );
    engine.verify_configuration(&file, &manifests).unwrap();
}

#[test]
fn manual_configuration_edit_requires_review_then_can_be_signed() {
    let (_root, audit, engine, file) = setup();
    let manifests = [&irmind_mod_llm_openai_compatible::MANIFEST];
    engine
        .apply_configuration_change(&file, &manifests, model("original"), false)
        .unwrap();
    let mut manual = file.load().unwrap();
    manual
        .modules
        .get_mut("llm-openai-compatible")
        .unwrap()
        .values
        .insert("IRMIND_MODEL".into(), "revised".into());
    file.save(&manual).unwrap();
    let review = match engine
        .inspect_configuration(&file, &manifests, true)
        .unwrap()
    {
        ConfigurationInspection::Review(review) => Some(review),
        ConfigurationInspection::Current => None,
    }
    .unwrap();
    assert!(
        review
            .differences
            .iter()
            .any(|item| item.field.ends_with("IRMIND_MODEL")
                && item.current.as_deref() == Some("revised"))
    );
    engine
        .accept_current_configuration(&file, &manifests, true, false)
        .unwrap();
    engine.verify_configuration(&file, &manifests).unwrap();
    assert_eq!(audit.global_operations().unwrap().len(), 2);
}

#[test]
fn rejected_manual_edit_restores_approved_fields() {
    let (_root, audit, engine, file) = setup();
    let manifests = [&irmind_mod_llm_openai_compatible::MANIFEST];
    engine
        .apply_configuration_change(&file, &manifests, model("original"), false)
        .unwrap();
    let mut manual = file.load().unwrap();
    manual
        .modules
        .get_mut("llm-openai-compatible")
        .unwrap()
        .values
        .insert("IRMIND_MODEL".into(), "rejected".into());
    file.save(&manual).unwrap();
    engine
        .restore_approved_configuration(&file, &manifests, true)
        .unwrap();
    assert_eq!(
        file.load().unwrap().modules["llm-openai-compatible"].values["IRMIND_MODEL"],
        "original"
    );
    assert!(
        audit
            .global_operations()
            .unwrap()
            .iter()
            .any(|entry| entry.operation.starts_with("configuration-restored:"))
    );
}

#[test]
fn secret_field_in_manual_file_cannot_be_accepted() {
    let (_root, _audit, engine, file) = setup();
    let manifests = [&irmind_mod_llm_openai_compatible::MANIFEST];
    engine
        .apply_configuration_change(&file, &manifests, model("original"), false)
        .unwrap();
    let mut manual = file.load().unwrap();
    manual
        .modules
        .get_mut("llm-openai-compatible")
        .unwrap()
        .values
        .insert("IRMIND_LLM_API_KEY".into(), "synthetic-secret".into());
    file.save(&manual).unwrap();
    let review = match engine
        .inspect_configuration(&file, &manifests, true)
        .unwrap()
    {
        ConfigurationInspection::Review(review) => Some(review),
        ConfigurationInspection::Current => None,
    }
    .unwrap();
    assert!(review.current_invalid);
    assert!(review.current.is_none());
    assert!(
        engine
            .accept_current_configuration(&file, &manifests, true, true)
            .is_err()
    );
    engine
        .restore_approved_configuration(&file, &manifests, true)
        .unwrap();
    assert!(
        !file.load().unwrap().modules["llm-openai-compatible"]
            .values
            .contains_key("IRMIND_LLM_API_KEY")
    );
}

#[test]
fn active_manual_endpoint_change_still_needs_egress_confirmation() {
    let (_root, _audit, engine, file) = setup();
    let manifests = [&irmind_mod_llm_openai_compatible::MANIFEST];
    engine
        .apply_configuration_change(&file, &manifests, model("synthetic"), false)
        .unwrap();
    engine
        .apply_configuration_change(
            &file,
            &manifests,
            ConfigChange::SelectLlm(Some("llm-openai-compatible".into())),
            true,
        )
        .unwrap();
    let mut manual = file.load().unwrap();
    manual
        .modules
        .get_mut("llm-openai-compatible")
        .unwrap()
        .values
        .insert(
            "IRMIND_LLM_BASE_URL".into(),
            "https://approved.example.invalid/v1/".into(),
        );
    file.save(&manual).unwrap();
    assert!(matches!(
        engine.accept_current_configuration(&file, &manifests, true, false),
        Err(AppError::Fixed(
            irmind_app::FixedAppError::PolicyConfigurationConfirmationRequired
        ))
    ));
    engine
        .accept_current_configuration(&file, &manifests, true, true)
        .unwrap();
    engine.verify_configuration(&file, &manifests).unwrap();
}

#[test]
fn existing_hash_only_configuration_event_keeps_verifying() {
    let (_root, audit, engine, file) = setup();
    let manifests = [&irmind_mod_llm_openai_compatible::MANIFEST];
    let fingerprint = irmind_app::hex(&irmind_app::sha256(
        &serde_json::to_vec(&PersistentConfig::default()).unwrap(),
    ));
    let signing = SigningKey::from_bytes(&[121u8; 32]);
    let mut entry = irmind_app::SignedOperation {
        case_id: irmind_app::GLOBAL_OPERATION_SCOPE.into(),
        seq: 1,
        at: 1,
        actor: Actor::Analyst,
        operation: format!("configuration-approved:{fingerprint}:{fingerprint}:false"),
        prev: [0; 32],
        hash: [0; 32],
        sig: Vec::new(),
        public_key: signing.verifying_key().to_bytes().to_vec(),
    };
    entry.hash = irmind_app::sha256(&entry.canonical());
    entry.sig = signing.sign(&entry.hash).to_bytes().to_vec();
    audit.append_global_operation(&entry).unwrap();
    engine.verify_configuration(&file, &manifests).unwrap();
    assert!(matches!(
        engine
            .inspect_configuration(&file, &manifests, false)
            .unwrap(),
        ConfigurationInspection::Review(_)
    ));
}
