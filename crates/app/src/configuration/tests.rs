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
            name: "IRMIND_MODEL_MAX_OUTPUT_TOKENS",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_MODEL_OUTPUT_REQUIRED",
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
    config: &[
        ConfigField {
            name: "IRMIND_SPLUNK_URL",
            required: true,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_CA_PEM",
            required: false,
            secret: false,
        },
        ConfigField {
            name: "IRMIND_SPLUNK_CA_SHA256",
            required: false,
            secret: false,
        },
    ],
};

#[test]
fn connector_ca_path_and_fingerprint_change_atomically() {
    let base = PersistentConfig::default();
    let path = "test-ca.pem";
    let digest = "a".repeat(64);
    let change = ConfigChange::SetCertificateAuthority {
        module: SIEM.id.into(),
        path_field: "IRMIND_SPLUNK_CA_PEM".into(),
        path: path.into(),
        sha256: digest.clone(),
    };
    let configured = base.changed(change, &[&SIEM]).unwrap();
    let values = &configured.modules.get(SIEM.id).unwrap().values;
    assert_eq!(values.get("IRMIND_SPLUNK_CA_PEM"), Some(&path.into()));
    assert_eq!(values.get("IRMIND_SPLUNK_CA_SHA256"), Some(&digest));
    let enabled = configured
        .changed(
            ConfigChange::SetEnabled {
                module: SIEM.id.into(),
                enabled: true,
            },
            &[&SIEM],
        )
        .unwrap();
    let changed_ca = enabled
        .changed(
            ConfigChange::SetCertificateAuthority {
                module: SIEM.id.into(),
                path_field: "IRMIND_SPLUNK_CA_PEM".into(),
                path: "replacement-ca.pem".into(),
                sha256: "b".repeat(64),
            },
            &[&SIEM],
        )
        .unwrap();
    assert!(enabled.active_egress_changed(&changed_ca));
    assert!(
        base.changed(
            ConfigChange::SetValue {
                module: SIEM.id.into(),
                field: "IRMIND_SPLUNK_CA_PEM".into(),
                value: path.into(),
            },
            &[&SIEM]
        )
        .is_err()
    );
    assert!(
        base.changed(
            ConfigChange::SetValue {
                module: SIEM.id.into(),
                field: "IRMIND_SPLUNK_CA_SHA256".into(),
                value: digest,
            },
            &[&SIEM]
        )
        .is_err()
    );
    let mut incomplete = configured.clone();
    incomplete
        .modules
        .get_mut(SIEM.id)
        .unwrap()
        .values
        .remove("IRMIND_SPLUNK_CA_SHA256");
    assert!(incomplete.validate(&[&SIEM]).is_err());
    let cleared = configured
        .changed(
            ConfigChange::SetCertificateAuthority {
                module: SIEM.id.into(),
                path_field: "IRMIND_SPLUNK_CA_PEM".into(),
                path: String::new(),
                sha256: String::new(),
            },
            &[&SIEM],
        )
        .unwrap();
    assert!(cleared.modules.get(SIEM.id).unwrap().values.is_empty());
}

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
    let no_hints = PersistentConfig::default()
        .changed(ConfigChange::SetShowHints(false), &[])
        .unwrap();
    assert_eq!(no_hints.show_hints, Some(false));
    assert!(
        serde_json::to_string(&no_hints)
            .unwrap()
            .contains("\"show_hints\":false")
    );
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

#[test]
fn worker_preference_is_optional_signed_and_bounded() {
    let defaults = PersistentConfig::default();
    for limit in [0, 257] {
        assert!(
            defaults
                .changed(ConfigChange::SetMaxParallelWorkers(Some(limit)), &[])
                .is_err()
        );
    }
    let limited = defaults
        .changed(ConfigChange::SetMaxParallelWorkers(Some(2)), &[])
        .unwrap();
    assert_eq!(limited.max_parallel_workers, Some(2));
    assert_ne!(
        limited.fingerprint().unwrap(),
        defaults.fingerprint().unwrap()
    );
    let auto = limited
        .changed(ConfigChange::SetMaxParallelWorkers(None), &[])
        .unwrap();
    assert_eq!(auto.fingerprint().unwrap(), defaults.fingerprint().unwrap());
}

#[test]
fn chronicle_scope_change_always_requires_egress_confirmation_even_when_disabled() {
    let mut current = PersistentConfig::default();
    current
        .modules
        .insert("siem-chronicle".into(), ProductSettings::default());
    let mut next = current.clone();
    next.modules
        .get_mut("siem-chronicle")
        .unwrap()
        .values
        .insert("IRMIND_CHRONICLE_SCOPE_MODE".into(), "instance".into());
    assert!(current.active_egress_changed(&next));
    assert!(next.active_egress_changed(&current));
    next.modules
        .get_mut("siem-chronicle")
        .unwrap()
        .values
        .insert("IRMIND_CHRONICLE_SCOPE_MODE".into(), "event-account".into());
    assert!(!current.active_egress_changed(&next));
}

#[test]
fn joint_model_update_replaces_all_parameters_and_clears_a_previous_capability() {
    let draft = ModelConfiguration {
        module: LLM.id.into(),
        base_url: "http://127.0.0.1:11434/v1/".into(),
        model: "synthetic-local".into(),
        maximum_output_tokens: Some(128_000),
        output_required: true,
    };
    let base = PersistentConfig::default();
    let configured = base
        .changed(ConfigChange::ConfigureModel(draft.clone()), &[&LLM])
        .unwrap();
    assert!(base.modules.is_empty());
    assert_eq!(configured.llm_module.as_deref(), Some(LLM.id));
    let values = &configured.modules[LLM.id].values;
    assert_eq!(values["IRMIND_MODEL"], draft.model);
    assert_eq!(values["IRMIND_LLM_BASE_URL"], draft.base_url);
    assert_eq!(values["IRMIND_MODEL_MAX_OUTPUT_TOKENS"], "128000");
    assert_eq!(values["IRMIND_MODEL_OUTPUT_REQUIRED"], "true");
    let replacement = ModelConfiguration {
        model: "another-local-model".into(),
        maximum_output_tokens: None,
        output_required: false,
        ..draft
    };
    let next = configured
        .changed(ConfigChange::ConfigureModel(replacement), &[&LLM])
        .unwrap();
    assert!(
        !next.modules[LLM.id]
            .values
            .contains_key("IRMIND_MODEL_MAX_OUTPUT_TOKENS")
    );
    assert_eq!(
        next.modules[LLM.id].values["IRMIND_MODEL_OUTPUT_REQUIRED"],
        "false"
    );
    assert!(configured.active_egress_changed(&next));
}

#[test]
fn joint_model_validation_accepts_matching_providers_gateways_and_custom_endpoints() {
    for (module, base_url, model) in [
        (
            "llm-openai-compatible",
            "https://api.openai.com/v1/",
            "gpt-4.1",
        ),
        (
            "llm-anthropic",
            "https://api.anthropic.com/",
            "claude-sonnet-4-6",
        ),
        (
            "llm-deepseek",
            "https://api.deepseek.com/v1/",
            "deepseek-v4-flash",
        ),
        (
            "llm-openrouter",
            "https://openrouter.ai/api/v1/",
            "anthropic/claude-sonnet-4-6",
        ),
        (
            "llm-openai-compatible",
            "http://127.0.0.1:11434/v1/",
            "local-model:latest",
        ),
        (
            "llm-anthropic",
            "https://proxy.example.invalid/",
            "custom-model",
        ),
    ] {
        ModelConfiguration {
            module: module.into(),
            base_url: base_url.into(),
            model: model.into(),
            maximum_output_tokens: None,
            output_required: module == "llm-anthropic",
        }
        .validate()
        .unwrap();
    }
}

#[test]
fn joint_model_validation_rejects_cross_provider_drafts_without_changing_configuration() {
    for (module, base_url, model) in [
        (
            "llm-deepseek",
            "https://api.anthropic.com/",
            "deepseek-v4-flash",
        ),
        (
            "llm-anthropic",
            "https://api.deepseek.com/",
            "claude-sonnet-4-6",
        ),
        (
            "llm-openai-compatible",
            "https://api.deepseek.com/",
            "deepseek-v4-flash",
        ),
        (
            "llm-openai-compatible",
            "https://api.openai.com/",
            "claude-sonnet-4-6",
        ),
        ("llm-deepseek", "https://api.deepseek.com/", "gpt-4.1"),
        (
            "llm-anthropic",
            "https://api.anthropic.com/",
            "deepseek-v4-flash",
        ),
        ("siem-splunk", "https://example.invalid/", "synthetic"),
        (
            "llm-openai-compatible",
            "http://remote.example.invalid/",
            "synthetic",
        ),
        (
            "llm-openai-compatible",
            "https://secret@example.invalid/",
            "synthetic",
        ),
        (
            "llm-openai-compatible",
            "https://example.invalid/?key=synthetic",
            "synthetic",
        ),
    ] {
        let base = PersistentConfig::default();
        let draft = ModelConfiguration {
            module: module.into(),
            base_url: base_url.into(),
            model: model.into(),
            maximum_output_tokens: Some(128_000),
            output_required: module == "llm-anthropic",
        };
        assert!(
            base.changed(ConfigChange::ConfigureModel(draft), &[&LLM, &SIEM])
                .is_err()
        );
        assert!(base.modules.is_empty() && base.llm_module.is_none());
    }
    let mut draft = ModelConfiguration {
        module: LLM.id.into(),
        base_url: "https://model.example.invalid/".into(),
        model: "synthetic".into(),
        maximum_output_tokens: Some(0),
        output_required: false,
    };
    assert!(draft.validate().is_err());
    draft.maximum_output_tokens = Some(128_000);
    assert!(
        PersistentConfig::default()
            .changed(ConfigChange::ConfigureModel(draft), &[&SIEM])
            .is_err()
    );
}
