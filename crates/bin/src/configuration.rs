use crate::{Cli, HashSet, ModuleManifest, PersistentConfig, Result, anyhow};
use anyhow::Context as _;
use irmind_app::{AppError, ModelPricing, SecretBackend, modules::ModuleConfig};

mod overrides;
pub(super) use overrides::{EgressOverride, collect_egress_overrides};

pub(super) fn compiled_manifests() -> Vec<&'static ModuleManifest> {
    vec![
        &irmind_mod_llm_openai_compatible::MANIFEST,
        #[cfg(feature = "llm-anthropic")]
        &irmind_mod_llm_anthropic::MANIFEST,
        #[cfg(feature = "llm-deepseek")]
        &irmind_mod_llm_deepseek::MANIFEST,
        #[cfg(feature = "llm-openrouter")]
        &irmind_mod_llm_openrouter::MANIFEST,
        #[cfg(feature = "siem-splunk")]
        &irmind_mod_siem_splunk::MANIFEST,
        #[cfg(feature = "cloud-aws")]
        &irmind_mod_cloud_aws::MANIFEST,
        #[cfg(feature = "storage-s3")]
        &irmind_mod_storage_object::S3_MANIFEST,
        #[cfg(feature = "storage-gcs")]
        &irmind_mod_storage_object::GCS_MANIFEST,
        #[cfg(feature = "storage-azure")]
        &irmind_mod_storage_object::AZURE_MANIFEST,
        #[cfg(feature = "edr-crowdstrike")]
        &irmind_mod_edr_crowdstrike::MANIFEST,
        #[cfg(feature = "edr-sentinelone")]
        &irmind_mod_edr_sentinelone::MANIFEST,
        #[cfg(feature = "ti-misp")]
        &irmind_mod_ti_misp::MANIFEST,
        #[cfg(feature = "ti-virustotal")]
        &irmind_mod_ti_virustotal::MANIFEST,
    ]
}

pub(super) fn selection_overrides(cli: &Cli) -> HashSet<String> {
    let mut overrides = HashSet::new();
    if cli.llm_module.is_some() {
        overrides.insert("llm".into());
    }
    for (id, env_name, flagged) in [
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
        if flagged || std::env::var_os(env_name).is_some() {
            overrides.insert(id.into());
        }
    }
    overrides
}

pub(super) fn effective_value(
    module: &str,
    field: &str,
    saved: &PersistentConfig,
    allow_environment: bool,
) -> Result<Option<String>> {
    if !allow_environment {
        return Ok(saved
            .modules
            .get(module)
            .and_then(|settings| settings.values.get(field))
            .cloned());
    }
    match std::env::var(field) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(saved
            .modules
            .get(module)
            .and_then(|settings| settings.values.get(field))
            .cloned()),
        Err(_) => Err(anyhow!("module setting is not valid Unicode")),
    }
}

fn enabled(flag: bool, env_name: &str, saved: bool) -> Result<bool> {
    let environment = match std::env::var(env_name) {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => return Err(anyhow!("connector enable override is not valid Unicode")),
    };
    enabled_from_values(flag, environment.as_deref(), saved)
}

fn enabled_from_values(flag: bool, environment: Option<&str>, saved: bool) -> Result<bool> {
    if flag {
        return Ok(true);
    }
    match environment {
        Some(value) => match value {
            "1" | "true" | "yes" => Ok(true),
            "0" | "false" | "no" => Ok(false),
            _ => Err(anyhow!("invalid connector enable override")),
        },
        None => Ok(saved),
    }
}

pub(super) fn resolve_cli(
    cli: &mut Cli,
    saved: &PersistentConfig,
    allow_overrides: bool,
) -> Result<()> {
    if !allow_overrides {
        restore_saved_cli(cli, saved);
        return Ok(());
    }
    if cli.llm_module.is_none() {
        cli.llm_module.clone_from(&saved.llm_module);
    }
    cli.policy = cli
        .policy
        .take()
        .or_else(|| saved.policy_path.as_ref().map(Into::into));
    macro_rules! resolve {
        ($field:ident, $env:literal, $id:literal) => {
            cli.$field = enabled(
                cli.$field,
                $env,
                saved.modules.get($id).is_some_and(|item| item.enabled),
            )?;
        };
    }
    resolve!(enable_splunk, "IRMIND_ENABLE_SPLUNK", "siem-splunk");
    resolve!(enable_aws, "IRMIND_ENABLE_AWS", "cloud-aws");
    resolve!(enable_storage_s3, "IRMIND_ENABLE_STORAGE_S3", "storage-s3");
    resolve!(
        enable_storage_gcs,
        "IRMIND_ENABLE_STORAGE_GCS",
        "storage-gcs"
    );
    resolve!(
        enable_storage_azure,
        "IRMIND_ENABLE_STORAGE_AZURE",
        "storage-azure"
    );
    resolve!(
        enable_crowdstrike,
        "IRMIND_ENABLE_CROWDSTRIKE",
        "edr-crowdstrike"
    );
    resolve!(
        enable_sentinelone,
        "IRMIND_ENABLE_SENTINELONE",
        "edr-sentinelone"
    );
    resolve!(enable_misp, "IRMIND_ENABLE_MISP", "ti-misp");
    resolve!(
        enable_virustotal,
        "IRMIND_ENABLE_VIRUSTOTAL",
        "ti-virustotal"
    );
    Ok(())
}

fn restore_saved_cli(cli: &mut Cli, saved: &PersistentConfig) {
    let enabled = |id: &str| saved.modules.get(id).is_some_and(|item| item.enabled);
    cli.llm_module.clone_from(&saved.llm_module);
    cli.policy = saved.policy_path.as_ref().map(Into::into);
    cli.enable_splunk = enabled("siem-splunk");
    cli.enable_aws = enabled("cloud-aws");
    cli.enable_storage_s3 = enabled("storage-s3");
    cli.enable_storage_gcs = enabled("storage-gcs");
    cli.enable_storage_azure = enabled("storage-azure");
    cli.enable_crowdstrike = enabled("edr-crowdstrike");
    cli.enable_sentinelone = enabled("edr-sentinelone");
    cli.enable_misp = enabled("ti-misp");
    cli.enable_virustotal = enabled("ti-virustotal");
}

pub(super) fn load_module_config(
    manifest: &ModuleManifest,
    secrets: &dyn SecretBackend,
    saved: &PersistentConfig,
    allow_environment: bool,
) -> Result<ModuleConfig> {
    let mut config = ModuleConfig::new();
    for field in manifest.config {
        if field.secret {
            match secrets.get(field.name) {
                Ok(value) => config.insert_secret(field.name, value),
                Err(AppError::SecretMissing) if !field.required => {}
                Err(_) => {
                    return Err(anyhow!(
                        "required module secret {} is unavailable",
                        field.name
                    ));
                }
            }
        } else {
            match effective_value(manifest.id, field.name, saved, allow_environment)? {
                Some(value) => config.insert_value(field.name, value),
                None if !field.required => {}
                None => return Err(anyhow!("required module setting {} is missing", field.name)),
            }
        }
    }
    Ok(config)
}

pub(super) fn configuration_issue(
    manifest: &ModuleManifest,
    secrets: &dyn SecretBackend,
    saved: &PersistentConfig,
    allow_environment: bool,
) -> String {
    let missing = manifest
        .config
        .iter()
        .filter(|field| field.required)
        .filter(|field| {
            if field.secret {
                secrets.get(field.name).is_err()
            } else {
                effective_value(manifest.id, field.name, saved, allow_environment)
                    .ok()
                    .flatten()
                    .is_none()
            }
        })
        .map(|field| field.name)
        .collect::<Vec<_>>();
    if missing.is_empty() {
        "invalid values in module configuration".into()
    } else {
        format!("missing required settings: {}", missing.join(", "))
    }
}

pub(super) fn load_pricing(saved: &PersistentConfig) -> Result<Option<ModelPricing>> {
    let price_override = |name| match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(anyhow!("model price override is not valid Unicode")),
    };
    let input = price_override("IRMIND_INPUT_MICROUSD_PER_MILLION")?;
    let output = price_override("IRMIND_OUTPUT_MICROUSD_PER_MILLION")?;
    let input = input.or_else(|| {
        saved
            .input_microusd_per_million
            .map(|value| value.to_string())
    });
    let output = output.or_else(|| {
        saved
            .output_microusd_per_million
            .map(|value| value.to_string())
    });
    match (input, output) {
        (None, None) => Ok(None),
        (Some(input), Some(output)) => {
            let input_microusd_per_million = input.parse::<u64>().context("invalid input price")?;
            let output_microusd_per_million =
                output.parse::<u64>().context("invalid output price")?;
            if input_microusd_per_million > 1_000_000_000_000
                || output_microusd_per_million > 1_000_000_000_000
            {
                return Err(anyhow!("model price exceeds configured maximum"));
            }
            Ok(Some(ModelPricing {
                input_microusd_per_million,
                output_microusd_per_million,
            }))
        }
        _ => Err(anyhow!("both input and output model prices must be set")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn connector_precedence_is_flag_then_environment_then_saved() {
        assert!(enabled_from_values(true, Some("false"), false).is_ok_and(|value| value));
        assert!(!enabled_from_values(false, Some("false"), true).is_ok_and(|value| value));
        assert!(enabled_from_values(false, Some("true"), false).is_ok_and(|value| value));
        assert!(enabled_from_values(false, None, true).is_ok_and(|value| value));
        assert!(enabled_from_values(false, Some("maybe"), false).is_err());
    }

    #[test]
    fn rejecting_tui_overrides_uses_only_saved_selection() {
        use clap::Parser as _;
        let mut cli = Cli::parse_from([
            "irmind",
            "--llm-module",
            "llm-openai-compatible",
            "--enable-splunk",
        ]);
        let saved = PersistentConfig::default();
        resolve_cli(&mut cli, &saved, false).unwrap();
        assert!(cli.llm_module.is_none());
        assert!(!cli.enable_splunk);
        assert!(
            effective_value("llm-openai-compatible", "IRMIND_MODEL", &saved, false)
                .unwrap()
                .is_none()
        );
    }
}
