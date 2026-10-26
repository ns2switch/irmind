#![forbid(unsafe_code)]

#[cfg(not(any(feature = "keystore-os", feature = "keystore-file")))]
compile_error!("IRMind requires at least one signer and secret backend");

mod cli;
mod keystore;
use cli::{
    Cli, Command, audit_source_name, input_files, read_evidence, terminal_safe_path,
    write_private_output,
};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use irmind_app::{
    AppError, AuditLog, CancellationToken, CryptoPorts, Engine, EnginePorts, EvidenceGraph,
    EvidenceStore, FindingKind, ModelPricing, Repository, SecretBackend, SignerBackend,
    modules::{ModuleConfig, ModuleManifest, ModuleRegistry},
};
use irmind_domain::{CaseId, ExecutionMode, PolicyRules, Severity, Tool};
use irmind_infra::{LocalExportVerifier, LocalStore, LocalVerifier, SystemClock};
#[cfg(feature = "cloud-aws")]
use irmind_mod_cloud_aws::AwsCloudTrail;
#[cfg(feature = "edr-crowdstrike")]
use irmind_mod_edr_crowdstrike::CrowdStrike;
#[cfg(feature = "edr-sentinelone")]
use irmind_mod_edr_sentinelone::SentinelOne;
#[cfg(feature = "keystore-os")]
use irmind_mod_keystore_os::OsKeystore;
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
use irmind_tui::{CredentialStatus, KeystoreStatus, ModuleStatus, WorkspaceIo};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn load_module_config(
    manifest: &ModuleManifest,
    secrets: &dyn SecretBackend,
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
            match std::env::var(field.name) {
                Ok(value) => config.insert_value(field.name, value),
                Err(std::env::VarError::NotPresent) if !field.required => {}
                Err(error) => return Err(anyhow!("module setting {}: {error}", field.name)),
            }
        }
    }
    Ok(config)
}

fn configuration_issue(manifest: &ModuleManifest, secrets: &dyn SecretBackend) -> String {
    let missing = manifest
        .config
        .iter()
        .filter(|field| field.required)
        .filter(|field| {
            if field.secret {
                secrets.get(field.name).is_err()
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
    ($registry:expr, $module:ty, $manifest:expr, $secrets:expr, $interactive:expr, $issues:expr) => {{
        let outcome = (|| -> Result<()> {
            let config = load_module_config(&$manifest, $secrets)?;
            $registry.register(Box::new(<$module>::from_config(&config)?), &config)?;
            Ok(())
        })();
        if let Err(error) = outcome {
            if $interactive {
                $issues.insert($manifest.id, configuration_issue(&$manifest, $secrets));
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
    home: PathBuf,
    credential_fields: Vec<&'static str>,
    store: Arc<LocalStore>,
    signer_backend: Arc<dyn SignerBackend>,
    secret_backend: Arc<dyn SecretBackend>,
    signer_id: String,
    secrets_id: String,
    #[cfg(feature = "keystore-file")]
    file_backend: Option<Arc<irmind_mod_keystore_file::FileKeystore>>,
}

fn compiled_credential_fields() -> Vec<&'static str> {
    let mut fields = Vec::new();
    macro_rules! collect {
        ($manifest:expr) => {
            fields.extend(
                $manifest
                    .config
                    .iter()
                    .filter(|field| field.secret)
                    .map(|field| field.name),
            );
        };
    }
    collect!(irmind_mod_llm_openai_compatible::MANIFEST);
    #[cfg(feature = "llm-anthropic")]
    collect!(irmind_mod_llm_anthropic::MANIFEST);
    #[cfg(feature = "llm-deepseek")]
    collect!(irmind_mod_llm_deepseek::MANIFEST);
    #[cfg(feature = "llm-openrouter")]
    collect!(irmind_mod_llm_openrouter::MANIFEST);
    #[cfg(feature = "siem-splunk")]
    collect!(irmind_mod_siem_splunk::MANIFEST);
    #[cfg(feature = "cloud-aws")]
    collect!(irmind_mod_cloud_aws::MANIFEST);
    #[cfg(feature = "edr-crowdstrike")]
    collect!(irmind_mod_edr_crowdstrike::MANIFEST);
    #[cfg(feature = "edr-sentinelone")]
    collect!(irmind_mod_edr_sentinelone::MANIFEST);
    #[cfg(feature = "ti-misp")]
    collect!(irmind_mod_ti_misp::MANIFEST);
    #[cfg(feature = "ti-virustotal")]
    collect!(irmind_mod_ti_virustotal::MANIFEST);
    fields.sort_unstable();
    fields.dedup();
    fields
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
    fn keystore_status(&self) -> Result<KeystoreStatus> {
        let credentials = self
            .credential_fields
            .iter()
            .map(|name| {
                let present = match self.secret_backend.get(name) {
                    Ok(_) => true,
                    Err(AppError::SecretMissing) => false,
                    Err(error) => return Err(error.into()),
                };
                Ok(CredentialStatus {
                    name: (*name).into(),
                    present,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let key = self
            .signer_backend
            .public_key_for_actor(&irmind_domain::Actor::Analyst)?;
        Ok(KeystoreStatus {
            signer_backend: self.signer_id.clone(),
            secrets_backend: self.secrets_id.clone(),
            analyst_fingerprint: irmind_app::hex(&irmind_app::sha256(&key)),
            credentials,
            file_backend_active: self.signer_id == "file" || self.secrets_id == "file",
        })
    }
    fn put_credential(&self, name: &str, value: &SecretString) -> Result<()> {
        if !self.credential_fields.contains(&name) {
            return Err(anyhow!("unknown module credential field"));
        }
        self.secret_backend.put(name, value)?;
        if self.secret_backend.get(name)?.expose_secret() != value.expose_secret() {
            return Err(anyhow!("credential write verification failed"));
        }
        Ok(())
    }
    fn delete_credential(&self, name: &str) -> Result<()> {
        if !self.credential_fields.contains(&name) {
            return Err(anyhow!("unknown module credential field"));
        }
        self.secret_backend.delete(name)?;
        match self.secret_backend.get(name) {
            Err(AppError::SecretMissing) => Ok(()),
            _ => Err(anyhow!("credential deletion verification failed")),
        }
    }
    fn change_keystore_passphrase(&self, value: &SecretString) -> Result<()> {
        #[cfg(feature = "keystore-file")]
        if let Some(file) = &self.file_backend {
            return file.change_passphrase(value).map_err(Into::into);
        }
        let _ = value;
        Err(anyhow!("the encrypted file backend is not active"))
    }
    fn migrate_keystore(
        &self,
        engine: &Engine<'_>,
        capability: &str,
        target: &str,
        passphrase: Option<&SecretString>,
    ) -> Result<()> {
        #[cfg(not(feature = "keystore-file"))]
        let _ = passphrase;
        let current = match capability {
            "signer" => self.signer_id.as_str(),
            "secrets" => self.secrets_id.as_str(),
            _ => return Err(anyhow!("invalid keystore capability")),
        };
        if current == target {
            return Err(anyhow!("target backend is already active"));
        }
        let (target_signer, target_secrets): (Arc<dyn SignerBackend>, Arc<dyn SecretBackend>) =
            match target {
                #[cfg(feature = "keystore-os")]
                "os" => {
                    let backend = Arc::new(OsKeystore::probe()?);
                    (backend.clone(), backend)
                }
                #[cfg(feature = "keystore-file")]
                "file" => {
                    let backend = match &self.file_backend {
                        Some(backend) => backend.clone(),
                        None => Arc::new(irmind_mod_keystore_file::FileKeystore::open(
                            &self.home,
                            passphrase
                                .ok_or_else(|| anyhow!("file keystore passphrase required"))?,
                            true,
                        )?),
                    };
                    (backend.clone(), backend)
                }
                _ => return Err(anyhow!("target keystore backend was not compiled")),
            };
        match capability {
            "signer" => engine
                .migrate_signer_backend(self.signer_backend.as_ref(), target_signer.as_ref())?,
            "secrets" => engine.migrate_secret_backend(
                self.secret_backend.as_ref(),
                target_secrets.as_ref(),
                &self.credential_fields,
            )?,
            _ => return Err(anyhow!("invalid keystore capability")),
        }
        let fingerprint = irmind_app::hex(&irmind_app::sha256(
            &self
                .signer_backend
                .public_key_for_actor(&irmind_domain::Actor::Analyst)?,
        ));
        keystore::select_migrated_backend(&self.home, capability, target, &fingerprint)?;
        Ok(())
    }
}

mod startup;

fn main() -> Result<()> {
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
    while !cancel.is_cancelled() && startup::run_once(&cancel)? {}
    Ok(())
}
