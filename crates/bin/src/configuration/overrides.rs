use super::{Cli, PersistentConfig, compiled_manifests, effective_value, enabled};
use irmind_app::ConfigChange;

#[derive(Clone)]
pub(crate) struct EgressOverride {
    pub field: String,
    pub saved: Option<String>,
    pub effective: Option<String>,
    pub change: Option<ConfigChange>,
}

pub(crate) fn collect_egress_overrides(cli: &Cli, saved: &PersistentConfig) -> Vec<EgressOverride> {
    let mut rows = Vec::new();
    if cli.llm_module != saved.llm_module && cli.llm_module.is_some() {
        rows.push(EgressOverride {
            field: "llm_module".into(),
            saved: saved.llm_module.clone(),
            effective: cli.llm_module.clone(),
            change: Some(ConfigChange::SelectLlm(cli.llm_module.clone())),
        });
    }
    connector_overrides(cli, saved, &mut rows);
    for manifest in compiled_manifests() {
        for field in manifest.config.iter().filter(|field| !field.secret) {
            if std::env::var_os(field.name).is_none() {
                continue;
            }
            let effective = effective_value(manifest.id, field.name, saved, true);
            let previous = saved
                .modules
                .get(manifest.id)
                .and_then(|settings| settings.values.get(field.name))
                .cloned();
            if effective.as_ref().ok() != Some(&previous) {
                let value = effective.ok().flatten();
                rows.push(EgressOverride {
                    field: format!("modules.{}.{}", manifest.id, field.name),
                    saved: previous,
                    effective: value.clone(),
                    change: value.map(|value| ConfigChange::SetValue {
                        module: manifest.id.into(),
                        field: field.name.into(),
                        value,
                    }),
                });
            }
        }
    }
    let manifests = compiled_manifests();
    for row in &mut rows {
        if row.change.as_ref().is_none_or(|change| {
            matches!(change, ConfigChange::SetValue { value, .. } if value.is_empty())
                || saved.changed(change.clone(), &manifests).is_err()
        }) {
            row.change = None;
            row.effective = Some("<invalid public setting>".into());
        }
    }
    rows
}

fn connector_overrides(cli: &Cli, saved: &PersistentConfig, rows: &mut Vec<EgressOverride>) {
    for (module, env_name, flag) in [
        ("siem-splunk", "IRMIND_ENABLE_SPLUNK", cli.enable_splunk),
        ("cloud-aws", "IRMIND_ENABLE_AWS", cli.enable_aws),
        (
            "storage-s3",
            "IRMIND_ENABLE_STORAGE_S3",
            cli.enable_storage_s3,
        ),
        (
            "storage-gcs",
            "IRMIND_ENABLE_STORAGE_GCS",
            cli.enable_storage_gcs,
        ),
        (
            "storage-azure",
            "IRMIND_ENABLE_STORAGE_AZURE",
            cli.enable_storage_azure,
        ),
        (
            "edr-crowdstrike",
            "IRMIND_ENABLE_CROWDSTRIKE",
            cli.enable_crowdstrike,
        ),
        (
            "edr-sentinelone",
            "IRMIND_ENABLE_SENTINELONE",
            cli.enable_sentinelone,
        ),
        ("ti-misp", "IRMIND_ENABLE_MISP", cli.enable_misp),
        (
            "ti-virustotal",
            "IRMIND_ENABLE_VIRUSTOTAL",
            cli.enable_virustotal,
        ),
    ] {
        if !flag && std::env::var_os(env_name).is_none() {
            continue;
        }
        let previous = saved
            .modules
            .get(module)
            .is_some_and(|settings| settings.enabled);
        let effective = enabled(flag, env_name, previous);
        if effective.as_ref().map_or(true, |value| *value != previous) {
            let value = effective.ok();
            rows.push(EgressOverride {
                field: format!("modules.{module}.enabled"),
                saved: Some(previous.to_string()),
                effective: value.map(|enabled| enabled.to_string()),
                change: value.map(|enabled| ConfigChange::SetEnabled {
                    module: module.into(),
                    enabled,
                }),
            });
        }
    }
}
