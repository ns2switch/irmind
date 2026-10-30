#![allow(clippy::unwrap_used)]

use super::*;
use crate::modules::ConfigField;

static LLM: ModuleManifest = ModuleManifest {
    id: "llm-openai-compatible",
    version: "test",
    ports: &[ModulePort::Llm],
    tools: &[],
    config: &[
        ConfigField {
            name: "IRMIND_MODEL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_LLM_BASE_URL",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_LLM_API_KEY",
            required: false,
            secret: true,
        },
    ],
};
static SIEM: ModuleManifest = ModuleManifest {
    id: "siem-splunk",
    version: "test",
    ports: &[ModulePort::Siem],
    tools: &[],
    config: &[ConfigField {
        name: "IRMIND_SPLUNK_URL",
        required: true,
        secret: false,
    }],
};

#[test]
fn unset_mouse_capture_preserves_signed_v1_configuration_bytes() {
    let mut config = PersistentConfig::default();
    assert_eq!(
        serde_json::to_string(&config).unwrap(),
        r#"{"version":1,"llm_module":null,"policy_path":null,"input_microusd_per_million":null,"output_microusd_per_million":null,"modules":{}}"#
    );
    config.mouse_capture = Some(false);
    assert!(
        serde_json::to_string(&config)
            .unwrap()
            .contains("\"mouse_capture\":false")
    );
    assert!(config.validate(&[]).is_ok());
    let resumed = PersistentConfig::default()
        .changed(ConfigChange::SetResumeLastCase(false), &[])
        .unwrap();
    assert_eq!(resumed.resume_last_case, Some(false));
    assert!(
        serde_json::to_string(&resumed)
            .unwrap()
            .contains("\"resume_last_case\":false")
    );
    let themed = PersistentConfig::default()
        .changed(ConfigChange::SetTheme("dark".into()), &[])
        .unwrap();
    assert_eq!(themed.theme.as_deref(), Some("dark"));
    assert!(
        serde_json::to_string(&themed)
            .unwrap()
            .contains("\"theme\":\"dark\"")
    );
    assert!(
        PersistentConfig::default()
            .changed(ConfigChange::SetTheme("invalid".into()), &[])
            .is_err()
    );
}

#[test]
fn persistent_configuration_rejects_secrets_and_unknown_fields() {
    let manifests = [&LLM];
    let base = PersistentConfig::default();
    assert!(base.validate(&manifests).is_ok());
    assert!(
        base.changed(
            ConfigChange::SetValue {
                module: LLM.id.into(),
                field: "IRMIND_LLM_API_KEY".into(),
                value: "secret".into(),
            },
            &manifests
        )
        .is_err()
    );
    assert!(
        base.changed(
            ConfigChange::SetValue {
                module: LLM.id.into(),
                field: "UNLISTED".into(),
                value: "x".into(),
            },
            &manifests
        )
        .is_err()
    );
    assert!(
        base.changed(
            ConfigChange::SetValue {
                module: LLM.id.into(),
                field: "IRMIND_MODEL".into(),
                value: "safe\u{202e}spoof".into(),
            },
            &manifests
        )
        .is_err()
    );
    let mut manual = base.clone();
    manual
        .modules
        .entry(LLM.id.into())
        .or_default()
        .values
        .insert("IRMIND_LLM_API_KEY".into(), "secret".into());
    assert!(manual.validate(&manifests).is_err());
}

#[test]
fn model_endpoint_must_be_https_or_loopback_http_without_embedded_credentials() {
    let base = PersistentConfig::default();
    let change = |value: &str| ConfigChange::SetValue {
        module: LLM.id.into(),
        field: "IRMIND_LLM_BASE_URL".into(),
        value: value.into(),
    };
    assert!(
        base.changed(change("http://127.0.0.1:11434/v1/"), &[&LLM])
            .is_ok()
    );
    assert!(
        base.changed(change("https://example.invalid/v1/"), &[&LLM])
            .is_ok()
    );
    assert!(
        base.changed(change("http://example.invalid/v1/"), &[&LLM])
            .is_err()
    );
    assert!(
        base.changed(change("https://user:pass@example.invalid/"), &[&LLM])
            .is_err()
    );
    assert!(
        base.changed(change("https://example.invalid/?token=x"), &[&LLM])
            .is_err()
    );
}

#[test]
fn egress_confirmation_covers_selection_and_active_parameter_changes() {
    let base = PersistentConfig::default();
    let staged = base
        .changed(
            ConfigChange::SetValue {
                module: LLM.id.into(),
                field: "IRMIND_MODEL".into(),
                value: "synthetic".into(),
            },
            &[&LLM],
        )
        .unwrap();
    assert!(!base.active_egress_changed(&staged));
    let active = staged
        .changed(ConfigChange::SelectLlm(Some(LLM.id.into())), &[&LLM])
        .unwrap();
    assert!(staged.active_egress_changed(&active));
    let new_model = active
        .changed(
            ConfigChange::SetValue {
                module: LLM.id.into(),
                field: "IRMIND_MODEL".into(),
                value: "synthetic-2".into(),
            },
            &[&LLM],
        )
        .unwrap();
    assert!(active.active_egress_changed(&new_model));

    let inactive = base
        .changed(
            ConfigChange::SetValue {
                module: SIEM.id.into(),
                field: "IRMIND_SPLUNK_URL".into(),
                value: "https://splunk.example.invalid/".into(),
            },
            &[&SIEM],
        )
        .unwrap();
    assert!(!base.active_egress_changed(&inactive));
    let enabled = inactive
        .changed(
            ConfigChange::SetEnabled {
                module: SIEM.id.into(),
                enabled: true,
            },
            &[&SIEM],
        )
        .unwrap();
    assert!(inactive.active_egress_changed(&enabled));
    let changed = enabled
        .changed(
            ConfigChange::SetValue {
                module: SIEM.id.into(),
                field: "IRMIND_SPLUNK_URL".into(),
                value: "https://other.example.invalid/".into(),
            },
            &[&SIEM],
        )
        .unwrap();
    assert!(enabled.active_egress_changed(&changed));
}
