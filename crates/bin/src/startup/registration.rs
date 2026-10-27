#[cfg(feature = "llm-anthropic")]
use super::Anthropic;
#[cfg(feature = "cloud-aws")]
use super::AwsCloudTrail;
#[cfg(feature = "edr-crowdstrike")]
use super::CrowdStrike;
#[cfg(feature = "llm-deepseek")]
use super::DeepSeek;
#[cfg(feature = "ti-misp")]
use super::Misp;
#[cfg(feature = "llm-openrouter")]
use super::OpenRouter;
#[cfg(feature = "edr-sentinelone")]
use super::SentinelOne;
#[cfg(feature = "siem-splunk")]
use super::Splunk;
#[cfg(feature = "ti-virustotal")]
use super::VirusTotal;
use super::{
    BTreeMap, Cli, DEFAULT_LLM_MODULE, JsonParser, ModuleConfig, ModuleRegistry, OpenAiCompatible,
    PersistentConfig, Result, SecretBackend, anyhow, configuration_issue, load_module_config,
};

pub(super) fn configured_registry(
    cli: &Cli,
    saved: &PersistentConfig,
    secrets: &dyn SecretBackend,
    allow_environment: bool,
    interactive: bool,
) -> Result<(ModuleRegistry, BTreeMap<&'static str, String>)> {
    let mut registry = ModuleRegistry::new();
    let mut config_issues = BTreeMap::<&'static str, String>::new();
    registry.register(Box::new(JsonParser), &ModuleConfig::new())?;
    register_llm(
        cli,
        saved,
        secrets,
        allow_environment,
        interactive,
        &mut registry,
        &mut config_issues,
    )?;
    register_security_products(
        cli,
        saved,
        secrets,
        allow_environment,
        interactive,
        &mut registry,
        &mut config_issues,
    )?;
    register_edr_and_intel(
        cli,
        saved,
        secrets,
        allow_environment,
        interactive,
        &mut registry,
        &mut config_issues,
    )?;
    Ok((registry, config_issues))
}

fn register_llm(
    cli: &Cli,
    saved: &PersistentConfig,
    secrets: &dyn SecretBackend,
    allow_environment: bool,
    interactive: bool,
    registry: &mut ModuleRegistry,
    config_issues: &mut BTreeMap<&'static str, String>,
) -> Result<()> {
    if cli.llm_module.is_some() {
        match cli
            .llm_module
            .as_deref()
            .ok_or_else(|| anyhow!("select an approved LLM explicitly with --llm-module"))?
        {
            DEFAULT_LLM_MODULE => register_configured!(
                registry,
                OpenAiCompatible,
                irmind_mod_llm_openai_compatible::MANIFEST,
                secrets,
                saved,
                allow_environment,
                interactive,
                config_issues
            ),
            #[cfg(feature = "llm-anthropic")]
            irmind_mod_llm_anthropic::MODULE_ID => {
                register_configured!(
                    registry,
                    Anthropic,
                    irmind_mod_llm_anthropic::MANIFEST,
                    secrets,
                    saved,
                    allow_environment,
                    interactive,
                    config_issues
                );
            }
            #[cfg(feature = "llm-deepseek")]
            irmind_mod_llm_deepseek::MODULE_ID => {
                register_configured!(
                    registry,
                    DeepSeek,
                    irmind_mod_llm_deepseek::MANIFEST,
                    secrets,
                    saved,
                    allow_environment,
                    interactive,
                    config_issues
                );
            }
            #[cfg(feature = "llm-openrouter")]
            irmind_mod_llm_openrouter::MODULE_ID => {
                register_configured!(
                    registry,
                    OpenRouter,
                    irmind_mod_llm_openrouter::MANIFEST,
                    secrets,
                    saved,
                    allow_environment,
                    interactive,
                    config_issues
                );
            }
            _ if interactive => {}
            _ => return Err(anyhow!("LLM module is not compiled into this binary")),
        }
    }
    Ok(())
}

fn register_security_products(
    cli: &Cli,
    saved: &PersistentConfig,
    secrets: &dyn SecretBackend,
    allow_environment: bool,
    interactive: bool,
    registry: &mut ModuleRegistry,
    config_issues: &mut BTreeMap<&'static str, String>,
) -> Result<()> {
    let _ = (
        &secrets,
        &registry,
        &config_issues,
        saved,
        allow_environment,
    );
    #[cfg(feature = "siem-splunk")]
    if cli.enable_splunk {
        register_configured!(
            registry,
            Splunk,
            irmind_mod_siem_splunk::MANIFEST,
            secrets,
            saved,
            allow_environment,
            interactive,
            config_issues
        );
    }
    #[cfg(not(feature = "siem-splunk"))]
    if cli.enable_splunk && !interactive {
        return Err(anyhow!(
            "this binary was built without the siem-splunk feature"
        ));
    }
    #[cfg(feature = "ti-misp")]
    if cli.enable_misp {
        register_configured!(
            registry,
            Misp,
            irmind_mod_ti_misp::MANIFEST,
            secrets,
            saved,
            allow_environment,
            interactive,
            config_issues
        );
    }
    #[cfg(not(feature = "ti-misp"))]
    if cli.enable_misp && !interactive {
        return Err(anyhow!("this binary was built without the ti-misp feature"));
    }
    #[cfg(feature = "cloud-aws")]
    if cli.enable_aws {
        register_configured!(
            registry,
            AwsCloudTrail,
            irmind_mod_cloud_aws::MANIFEST,
            secrets,
            saved,
            allow_environment,
            interactive,
            config_issues
        );
    }
    #[cfg(not(feature = "cloud-aws"))]
    if cli.enable_aws && !interactive {
        return Err(anyhow!(
            "this binary was built without the cloud-aws feature"
        ));
    }
    Ok(())
}

fn register_edr_and_intel(
    cli: &Cli,
    saved: &PersistentConfig,
    secrets: &dyn SecretBackend,
    allow_environment: bool,
    interactive: bool,
    registry: &mut ModuleRegistry,
    config_issues: &mut BTreeMap<&'static str, String>,
) -> Result<()> {
    let _ = (
        &secrets,
        &registry,
        &config_issues,
        saved,
        allow_environment,
    );
    #[cfg(feature = "edr-crowdstrike")]
    if cli.enable_crowdstrike {
        register_configured!(
            registry,
            CrowdStrike,
            irmind_mod_edr_crowdstrike::MANIFEST,
            secrets,
            saved,
            allow_environment,
            interactive,
            config_issues
        );
    }
    #[cfg(not(feature = "edr-crowdstrike"))]
    if cli.enable_crowdstrike && !interactive {
        return Err(anyhow!(
            "this binary was built without the edr-crowdstrike feature"
        ));
    }
    #[cfg(feature = "edr-sentinelone")]
    if cli.enable_sentinelone {
        register_configured!(
            registry,
            SentinelOne,
            irmind_mod_edr_sentinelone::MANIFEST,
            secrets,
            saved,
            allow_environment,
            interactive,
            config_issues
        );
    }
    #[cfg(not(feature = "edr-sentinelone"))]
    if cli.enable_sentinelone && !interactive {
        return Err(anyhow!(
            "this binary was built without the edr-sentinelone feature"
        ));
    }
    #[cfg(feature = "ti-virustotal")]
    if cli.enable_virustotal {
        register_configured!(
            registry,
            VirusTotal,
            irmind_mod_ti_virustotal::MANIFEST,
            secrets,
            saved,
            allow_environment,
            interactive,
            config_issues
        );
    }
    #[cfg(not(feature = "ti-virustotal"))]
    if cli.enable_virustotal && !interactive {
        return Err(anyhow!(
            "this binary was built without the ti-virustotal feature"
        ));
    }
    Ok(())
}
