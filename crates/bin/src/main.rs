#![forbid(unsafe_code)]

#[cfg(not(any(feature = "keystore-os", feature = "keystore-file")))]
compile_error!("IRMind requires at least one signer and secret backend");

mod cli;
mod configuration;
mod diagnostics;
mod keystore;
mod model_probe;
mod policy_config;
mod recent_case;
use cli::{
    Cli, Command, audit_source_name, input_files_large, read_evidence, write_private_output,
};
use configuration::{configuration_issue, load_module_config, load_pricing};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use irmind_app::{
    AppError, AuditLog, CancellationToken, ConfigChange, ConfigurationStore, CryptoPorts, Engine,
    EnginePorts, EvidenceGraph, EvidenceStore, FindingKind, LargeCaseUseCases, PersistentConfig,
    Repository, SecretBackend, SignerBackend,
    modules::{ModuleConfig, ModuleManifest, ModuleRegistry},
};
use irmind_domain::{CaseId, ExecutionMode, Severity};
use irmind_infra::{
    LocalExportVerifier, LocalStore, LocalVerifier, SystemClock, TomlConfigurationStore,
};
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
use policy_config::load_policy;
use secrecy::{ExposeSecret as _, SecretString};
use std::collections::{BTreeMap, HashSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

static STREAMING_JSON_PARSER: JsonParser = JsonParser;

macro_rules! register_configured {
    ($registry:expr, $module:ty, $manifest:expr, $secrets:expr, $saved:expr, $allow_env:expr, $interactive:expr, $issues:expr) => {{
        let outcome = (|| -> Result<()> {
            let config = load_module_config(&$manifest, $secrets, $saved, $allow_env)?;
            $registry.register(Box::new(<$module>::from_config(&config)?), &config)?;
            Ok(())
        })();
        if let Err(error) = outcome {
            if $interactive {
                $issues.insert(
                    $manifest.id,
                    configuration_issue(&$manifest, $secrets, $saved, $allow_env),
                );
            } else {
                return Err(error);
            }
        }
    }};
}

struct RootWorkspaceIo {
    home: PathBuf,
    credential_fields: Vec<&'static str>,
    store: Arc<LocalStore>,
    signer_backend: Arc<dyn SignerBackend>,
    secret_backend: Arc<dyn SecretBackend>,
    config_store: Arc<TomlConfigurationStore>,
    manifests: Vec<&'static ModuleManifest>,
    module_overrides: HashSet<String>,
    allow_environment: bool,
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
    #[cfg(feature = "storage-s3")]
    collect!(irmind_mod_storage_object::S3_MANIFEST);
    #[cfg(feature = "storage-gcs")]
    collect!(irmind_mod_storage_object::GCS_MANIFEST);
    #[cfg(feature = "storage-azure")]
    collect!(irmind_mod_storage_object::AZURE_MANIFEST);
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
    fn load_last_case(&self) -> Result<Option<CaseId>> {
        recent_case::load(&self.home)
    }
    fn remember_last_case(&self, id: &CaseId) -> Result<()> {
        recent_case::save(&self.home, id)
    }
    fn input_files(&self, root: &Path) -> Result<Vec<PathBuf>> {
        input_files_large(root)
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
        let result =
            irmind_app::verify_export_details(&LocalExportVerifier, path, Some(expected_key))?;
        Ok(format!(
            "Verified {} entries; analyst key {}; original bytes verified {}; unavailable {}",
            result.entries,
            result.analyst_key_fingerprint,
            result.source_bytes_verified,
            result.source_bytes_unavailable
        ))
    }
    fn case_exporter(&self) -> &dyn irmind_app::CaseExporter {
        self.store.as_ref()
    }
    fn large_case_exporter(&self) -> Option<&dyn irmind_app::LargeCaseExporter> {
        Some(self.store.as_ref())
    }
    fn large_case_store(&self) -> Option<&dyn irmind_app::LargeCaseStore> {
        Some(self.store.as_ref())
    }
    fn streaming_parser(&self) -> Option<&dyn irmind_app::StreamingEventParser> {
        Some(&STREAMING_JSON_PARSER)
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
    fn change_module_configuration(
        &self,
        engine: &Engine<'_>,
        change: ConfigChange,
        confirmed: bool,
    ) -> Result<bool> {
        let overridden = match &change {
            ConfigChange::SetResumeLastCase(_)
            | ConfigChange::SetMouseCapture(_)
            | ConfigChange::SetTheme(_) => false,
            ConfigChange::SelectLlm(_) => self.module_overrides.contains("llm"),
            ConfigChange::SetEnabled { module, .. } => self.module_overrides.contains(module),
            ConfigChange::SetValue { module, field, .. } => {
                std::env::var_os(field).is_some()
                    || self.module_overrides.contains(module)
                    || (self.module_overrides.contains("llm")
                        && self.manifests.iter().any(|manifest| {
                            manifest.id == module
                                && manifest
                                    .ports
                                    .contains(&irmind_app::modules::ModulePort::Llm)
                        }))
            }
        };
        if overridden {
            return Err(anyhow!(
                "this setting is overridden by a flag or environment variable"
            ));
        }
        let current = self.config_store.load()?;
        let next = current.changed(change.clone(), &self.manifests)?;
        let active_module = match &change {
            ConfigChange::SelectLlm(Some(id)) => Some(id.as_str()),
            ConfigChange::SetEnabled {
                module,
                enabled: true,
            } => Some(module.as_str()),
            ConfigChange::SetValue { module, .. }
                if next.llm_module.as_deref() == Some(module.as_str())
                    || next
                        .modules
                        .get(module)
                        .is_some_and(|settings| settings.enabled) =>
            {
                Some(module.as_str())
            }
            _ => None,
        };
        if let Some(id) = active_module {
            let manifest = self
                .manifests
                .iter()
                .copied()
                .find(|manifest| manifest.id == id)
                .ok_or_else(|| anyhow!("module is not compiled into this binary"))?;
            load_module_config(
                manifest,
                self.secret_backend.as_ref(),
                &next,
                self.allow_environment,
            )?;
        }
        Ok(engine.apply_configuration_change(
            self.config_store.as_ref(),
            &self.manifests,
            change,
            confirmed,
        )?)
    }
    fn list_ollama_models(&self, base_url: &str) -> Result<Vec<String>> {
        model_probe::list_ollama_models(base_url)
    }
    fn list_provider_models(
        &self,
        provider: &str,
        base_url: &str,
        key: Option<&secrecy::SecretString>,
    ) -> Result<Vec<String>> {
        model_probe::list_provider_models(provider, base_url, key)
    }
    fn test_model_connection(
        &self,
        provider: &str,
        base_url: &str,
        model: &str,
        key: Option<&SecretString>,
    ) -> Result<String> {
        model_probe::test_model_connection(
            provider,
            base_url,
            model,
            key,
            self.secret_backend.as_ref(),
        )
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
