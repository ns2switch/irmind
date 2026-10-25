#![forbid(unsafe_code)]

mod cli;
use cli::{
    Cli, Command, audit_source_name, input_files, read_evidence, terminal_safe_path,
    write_private_output,
};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use irmind_app::{
    AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph, EvidenceStore,
    FindingKind, ModelPricing, Repository, Signer,
    modules::{ModuleConfig, ModuleManifest, ModuleRegistry},
};
use irmind_domain::{Actor, CaseId, ExecutionMode, PolicyRules, Severity, Tool};
use irmind_infra::{LocalExportVerifier, LocalSigner, LocalStore, LocalVerifier, SystemClock};
#[cfg(feature = "cloud-aws")]
use irmind_mod_cloud_aws::AwsCloudTrail;
#[cfg(feature = "edr-crowdstrike")]
use irmind_mod_edr_crowdstrike::CrowdStrike;
#[cfg(feature = "edr-sentinelone")]
use irmind_mod_edr_sentinelone::SentinelOne;
#[cfg(feature = "llm-anthropic")]
use irmind_mod_llm_anthropic::Anthropic;
#[cfg(feature = "llm-deepseek")]
use irmind_mod_llm_deepseek::DeepSeek;
use irmind_mod_llm_openai_compatible::{MODULE_ID as DEFAULT_LLM_MODULE, OpenAiCompatible};
#[cfg(feature = "llm-openrouter")]
use irmind_mod_llm_openrouter::OpenRouter;
use irmind_mod_parser_json::JsonParser;
#[cfg(feature = "siem-splunk")]
use irmind_mod_siem_splunk::Splunk;
#[cfg(feature = "ti-misp")]
use irmind_mod_ti_misp::Misp;
#[cfg(feature = "ti-virustotal")]
use irmind_mod_ti_virustotal::VirusTotal;
use irmind_security::MandatoryGuard;
use irmind_tui::{ModuleStatus, WorkspaceIo};
use secrecy::SecretString;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn load_module_config(manifest: &ModuleManifest) -> Result<ModuleConfig> {
    let mut config = ModuleConfig::new();
    for field in manifest.config {
        if field.secret {
            let entry = keyring::Entry::new("irmind-module", field.name)
                .with_context(|| format!("open keyring entry {}", field.name))?;
            match entry.get_password() {
                Ok(value) => config.insert_secret(field.name, SecretString::from(value)),
                Err(keyring::Error::NoEntry) if !field.required => {}
                Err(error) => return Err(anyhow!("keyring entry {}: {error}", field.name)),
            }
        } else {
            match std::env::var(field.name) {
                Ok(value) => config.insert_value(field.name, value),
                Err(std::env::VarError::NotPresent) if !field.required => {}
                Err(error) => return Err(anyhow!("module setting {}: {error}", field.name)),
            }
        }
    }
    Ok(config)
}

fn configuration_issue(manifest: &ModuleManifest) -> String {
    let missing = manifest
        .config
        .iter()
        .filter(|field| field.required)
        .filter(|field| {
            if field.secret {
                keyring::Entry::new("irmind-module", field.name)
                    .and_then(|entry| entry.get_password())
                    .is_err()
            } else {
                std::env::var(field.name).is_err()
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

macro_rules! register_configured {
    ($registry:expr, $module:ty, $manifest:expr, $interactive:expr, $issues:expr) => {{
        let outcome = (|| -> Result<()> {
            let config = load_module_config(&$manifest)?;
            $registry.register(Box::new(<$module>::from_config(&config)?), &config)?;
            Ok(())
        })();
        if let Err(error) = outcome {
            if $interactive {
                $issues.insert($manifest.id, configuration_issue(&$manifest));
            } else {
                return Err(error);
            }
        }
    }};
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u8,
    max_tool_calls_per_case: usize,
    max_model_result_bytes: usize,
    max_model_tokens_per_case: u64,
    denied_tools: Vec<String>,
}

fn load_policy(path: &std::path::Path) -> Result<(PolicyRules, String)> {
    let raw =
        std::fs::read(path).with_context(|| format!("read policy {}", terminal_safe_path(path)))?;
    let source = std::str::from_utf8(&raw).context("policy must be UTF-8")?;
    let file: PolicyFile = toml::from_str(source).context("parse policy TOML")?;
    if file.version != 1 {
        return Err(anyhow!("unsupported policy version"));
    }
    let denied_tools = file
        .denied_tools
        .iter()
        .map(|name| Tool::parse(name).map_err(|_| anyhow!("unknown policy tool: {name}")))
        .collect::<Result<Vec<_>>>()?;
    let policy = PolicyRules {
        denied_tools,
        max_tool_calls_per_case: file.max_tool_calls_per_case,
        max_model_result_bytes: file.max_model_result_bytes,
        max_model_tokens_per_case: file.max_model_tokens_per_case,
    };
    policy
        .validate()
        .map_err(|_| anyhow!("invalid policy limits"))?;
    let fingerprint = irmind_app::hex(&irmind_app::sha256(&raw));
    Ok((policy, fingerprint))
}

fn load_pricing() -> Result<Option<ModelPricing>> {
    let input = std::env::var("IRMIND_INPUT_MICROUSD_PER_MILLION").ok();
    let output = std::env::var("IRMIND_OUTPUT_MICROUSD_PER_MILLION").ok();
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

struct RootWorkspaceIo {
    store: Arc<LocalStore>,
}

impl WorkspaceIo for RootWorkspaceIo {
    fn input_files(&self, root: &Path) -> Result<Vec<PathBuf>> {
        input_files(root)
    }
    fn read_evidence(&self, path: &Path) -> Result<Vec<u8>> {
        read_evidence(path)
    }
    fn audit_source_name(&self, root: &Path, file: &Path) -> Result<String> {
        audit_source_name(root, file)
    }
    fn save_evidence(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        write_private_output(path, bytes)
    }
    fn verify_export(&self, path: &Path, expected_key: &str) -> Result<String> {
        let (fingerprint, entries) =
            irmind_app::verify_export(&LocalExportVerifier, path, Some(expected_key))?;
        Ok(format!(
            "Verified {entries} entries; analyst key {fingerprint}"
        ))
    }
    fn case_exporter(&self) -> &dyn irmind_app::CaseExporter {
        self.store.as_ref()
    }
}

fn module_statuses(
    cli: &Cli,
    registry: &ModuleRegistry,
    issues: &BTreeMap<&'static str, String>,
) -> Vec<ModuleStatus> {
    let mut out = vec![ModuleStatus {
        id: "parser-json".into(),
        compiled: true,
        enabled: true,
        configuration: "valid; built-in parser".into(),
    }];
    macro_rules! status {
        ($id:expr, $compiled:expr, $requested:expr) => {{
            let enabled = registry.manifest($id).is_some();
            out.push(ModuleStatus {
                id: $id.into(),
                compiled: $compiled,
                enabled,
                configuration: if let Some(issue) = issues.get($id) {
                    issue.clone()
                } else if enabled {
                    "valid".into()
                } else if !$compiled {
                    "not compiled".into()
                } else if $requested {
                    "invalid configuration; check required settings and keyring".into()
                } else {
                    "disabled".into()
                },
            });
        }};
    }
    status!(
        "llm-openai-compatible",
        true,
        cli.llm_module.as_deref() == Some("llm-openai-compatible")
    );
    status!(
        "llm-anthropic",
        cfg!(feature = "llm-anthropic"),
        cli.llm_module.as_deref() == Some("llm-anthropic")
    );
    status!(
        "llm-deepseek",
        cfg!(feature = "llm-deepseek"),
        cli.llm_module.as_deref() == Some("llm-deepseek")
    );
    status!(
        "llm-openrouter",
        cfg!(feature = "llm-openrouter"),
        cli.llm_module.as_deref() == Some("llm-openrouter")
    );
    status!(
        "siem-splunk",
        cfg!(feature = "siem-splunk"),
        cli.enable_splunk
    );
    status!("cloud-aws", cfg!(feature = "cloud-aws"), cli.enable_aws);
    status!(
        "edr-crowdstrike",
        cfg!(feature = "edr-crowdstrike"),
        cli.enable_crowdstrike
    );
    status!(
        "edr-sentinelone",
        cfg!(feature = "edr-sentinelone"),
        cli.enable_sentinelone
    );
    status!("ti-misp", cfg!(feature = "ti-misp"), cli.enable_misp);
    status!(
        "ti-virustotal",
        cfg!(feature = "ti-virustotal"),
        cli.enable_virustotal
    );
    out
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let interactive = matches!(&cli.command, None | Some(Command::Tui { .. }));
    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    std::thread::spawn(move || {
        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            let _ = runtime.block_on(tokio::signal::ctrl_c());
            signal_cancel.cancel();
        } else {
            signal_cancel.cancel();
        }
    });
    if let Some(Command::VerifyExport { path, expected_key }) = &cli.command {
        let (fingerprint, entries) =
            irmind_app::verify_export(&LocalExportVerifier, path, expected_key.as_deref())?;
        println!("verified {entries} audit entries; analyst key fingerprint {fingerprint}");
        return Ok(());
    }
    let home = match &cli.home {
        Some(path) => path.clone(),
        None => ProjectDirs::from("", "IRMind", "IRMind")
            .ok_or_else(|| anyhow!("cannot determine the user's standard data directory"))?
            .data_local_dir()
            .to_path_buf(),
    };
    let store = Arc::new(match LocalStore::open(&home) {
        Ok(store) => store,
        Err(error) => {
            if interactive {
                let _ = irmind_tui::show_startup_error(
                    "Local case storage is unavailable. Check the data directory permissions.",
                );
            }
            return Err(error.into());
        }
    });
    let new_analyst_key =
        interactive && LocalSigner::public_key_for_actor(&Actor::Analyst).is_err();
    let signer = Arc::new(match LocalSigner::load_or_create(Actor::Analyst) {
        Ok(signer) => signer,
        Err(error) => {
            if interactive {
                let _ = irmind_tui::show_startup_error(
                    "The system keyring is unavailable. Configure the native keyring and restart IRMind.",
                );
            }
            return Err(error).context("load analyst signing key from system keyring");
        }
    });
    let mut verifier = LocalVerifier::from_signer(signer.as_ref());
    for case in store.list_cases()? {
        let actors = store
            .entries(&case.id)?
            .into_iter()
            .map(|entry| entry.actor)
            .chain(
                store
                    .operations(&case.id)?
                    .into_iter()
                    .map(|entry| entry.actor),
            );
        for actor in actors {
            if actor == signer.actor() {
                continue;
            }
            let key = LocalSigner::public_key_for_actor(&actor)
                .with_context(|| format!("load trusted public key for {}", actor.as_storage()))?;
            verifier = verifier.with_trusted_key(&actor, &key)?;
        }
    }
    let guard = Arc::new(MandatoryGuard::new()?);
    let mut registry = ModuleRegistry::new();
    let mut config_issues = BTreeMap::<&'static str, String>::new();
    registry.register(Box::new(JsonParser), &ModuleConfig::new())?;
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
                interactive,
                config_issues
            ),
            #[cfg(feature = "llm-anthropic")]
            irmind_mod_llm_anthropic::MODULE_ID => {
                register_configured!(
                    registry,
                    Anthropic,
                    irmind_mod_llm_anthropic::MANIFEST,
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
                    interactive,
                    config_issues
                );
            }
            _ if interactive => {}
            _ => return Err(anyhow!("LLM module is not compiled into this binary")),
        }
    }
    #[cfg(feature = "siem-splunk")]
    if cli.enable_splunk {
        register_configured!(
            registry,
            Splunk,
            irmind_mod_siem_splunk::MANIFEST,
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
    #[cfg(feature = "edr-crowdstrike")]
    if cli.enable_crowdstrike {
        register_configured!(
            registry,
            CrowdStrike,
            irmind_mod_edr_crowdstrike::MANIFEST,
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
    let mut engine = registry.bind(Engine::new(
        EnginePorts::new(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            CryptoPorts::new(signer.clone(), Arc::new(verifier)),
            guard.clone(),
            registry.parser()?,
        ),
        ExecutionMode::Attended,
        Arc::new(SystemClock),
    )?)?;
    if let Some(path) = &cli.policy {
        let (policy, fingerprint) = load_policy(path)?;
        engine = engine.with_policy(policy, fingerprint)?;
    }
    if let Some(pricing) = load_pricing()? {
        engine = engine.with_pricing(pricing);
    }
    let workspace_io = RootWorkspaceIo {
        store: store.clone(),
    };
    let module_statuses = module_statuses(&cli, &registry, &config_issues);
    let selected_model = match cli.llm_module.as_deref() {
        Some(id) if interactive => registry.llm(id).ok(),
        Some(id) => Some(registry.llm(id)?),
        None => None,
    };
    match cli.command {
        None => irmind_tui::run_workspace(
            &engine,
            selected_model,
            &workspace_io,
            &module_statuses,
            &cancel,
            None,
            new_analyst_key,
        )?,
        Some(command) => cli::AutomationContext {
            engine: &engine,
            store: &store,
            guard: &guard,
            registry: &registry,
            llm_module: cli.llm_module.as_deref(),
            selected_model,
            workspace_io: &workspace_io,
            module_statuses: &module_statuses,
            cancel: &cancel,
            new_analyst_key,
        }
        .run(command)?,
    }
    Ok(())
}
