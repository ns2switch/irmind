#![forbid(unsafe_code)]

#[cfg(not(any(feature = "keystore-os", feature = "keystore-file")))]
compile_error!("IRMind requires at least one signer and secret backend");

mod catalog_source;
mod cli;
mod configuration;
#[cfg(all(feature = "keystore-file", feature = "parser-json"))]
mod demo;
#[cfg(not(all(feature = "keystore-file", feature = "parser-json")))]
mod demo {
    pub(super) fn run(
        _shutdown: &irmind_app::CancellationToken,
        _scripted: bool,
        _presentation_speed: u8,
    ) -> anyhow::Result<()> {
        anyhow::bail!("demo requires a binary built with keystore-file and parser-json")
    }
}
mod diagnostics;
mod keystore;
mod model_probe;
mod parser_definitions;
mod policy_config;
mod recent_case;
mod source_query_settings;
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
    modules::{ModuleManifest, ModuleRegistry},
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
#[cfg(feature = "parser-json")]
use irmind_mod_parser_json::JsonParser;
#[cfg(not(feature = "parser-json"))]
mod disabled_parser;
#[cfg(not(feature = "parser-json"))]
use disabled_parser::JsonParser;
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
    subagent_review: Arc<irmind_app::subagents::AnalystPlanMailbox>,
    parser_catalog: irmind_app::modules::ParserCatalog,
    definition_store: irmind_infra::FileDefinitionStore,
    home: PathBuf,
    credential_fields: Vec<String>,
    source_query_settings: Option<source_query_settings::SourceQuerySettings>,
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
    let mut fields = configuration::compiled_manifests()
        .into_iter()
        .flat_map(|manifest| manifest.config.iter())
        .filter(|field| field.secret)
        .map(|field| field.name)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    fields.dedup();
    fields
}

impl RootWorkspaceIo {
    fn configuration_is_overridden(&self, change: &ConfigChange) -> bool {
        match change {
            ConfigChange::SetResumeLastCase(_)
            | ConfigChange::SetShowHints(_)
            | ConfigChange::SetMouseCapture(_)
            | ConfigChange::SetTheme(_)
            | ConfigChange::SetMaxParallelWorkers(_)
            | ConfigChange::SetCaseBudgetDefaults(_)
            | ConfigChange::SetConfirmAllSubagentPlans(_)
            | ConfigChange::SetStatusBar(_) => false,
            ConfigChange::SelectLlm(_) => self.module_overrides.contains("llm"),
            ConfigChange::ConfigureModel(model) => {
                self.module_overrides.contains("llm")
                    || self.module_overrides.contains(&model.module)
                    || model.parameter_fields().map_or(true, |fields| {
                        fields.iter().any(|field| std::env::var_os(field).is_some())
                    })
            }
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
            ConfigChange::SetCertificateAuthority {
                module, path_field, ..
            } => std::env::var_os(path_field).is_some() || self.module_overrides.contains(module),
        }
    }
}

impl WorkspaceIo for RootWorkspaceIo {
    #[cfg(feature = "sigma")]
    fn inspect_sigma_pack(
        &self,
        directory: &Path,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<String, AppError> {
        let pack = irmind_infra::sigma_pack::inspect_local_sigma_pack(directory, cancel)?;
        let manifest = pack.manifest.encode().map_err(|_| {
            AppError::Policy("Sigma pack manifest exceeds the supported limits".into())
        })?;
        Ok(format!(
            "Sigma pack preview · {} validated rules\nManifest SHA-256 {}",
            pack.rules.len(),
            irmind_app::hex(&irmind_app::sha256(&manifest))
        ))
    }

    fn preview_cited_report(
        &self,
        engine: &Engine<'_>,
        id: &irmind_app::CaseId,
        language: irmind_app::ReportDocumentLanguage,
        cancel: &irmind_app::CancellationToken,
    ) -> Result<String, AppError> {
        use std::fmt::Write as _;
        let preview = self
            .store
            .preview_cited_report(engine, id, language, cancel)?;
        let mut heading = "Unsigned cited preview".to_owned();
        if preview.omitted_findings > 0 {
            let _ = write!(
                heading,
                "\nConfirmed findings without a verified row citation: {}",
                preview.omitted_findings
            );
        }
        Ok(format!("{heading}\n\n{}", preview.markdown))
    }

    fn definition_store(&self) -> Option<&dyn irmind_app::ParserDefinitionStore> {
        Some(&self.definition_store)
    }
    fn definition_compiler(&self) -> Option<&dyn irmind_app::DefinitionCompiler> {
        #[cfg(feature = "parser-declarative")]
        {
            Some(&irmind_mod_parser_declarative::DeclarativeCompiler)
        }
        #[cfg(not(feature = "parser-declarative"))]
        {
            None
        }
    }
    fn read_parser_input(&self, path: &Path, limit: usize) -> Result<Vec<u8>> {
        parser_definitions::read(path, limit)
    }

    fn show_hints(&self) -> bool {
        self.config_store
            .load()
            .map_or(true, |config| config.show_hints.unwrap_or(true))
    }
    fn parser_catalog(&self) -> Option<&irmind_app::modules::ParserCatalog> {
        Some(&self.parser_catalog)
    }

    fn read_format_sample(&self, path: &Path) -> Result<Vec<u8>> {
        use std::io::Read as _;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("selected source has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| anyhow!("selected source has no file name"))?;
        let file = irmind_fs::open_regular_no_follow(parent, Path::new(name))?;
        let mut sample = Vec::new();
        file.take(64 * 1024).read_to_end(&mut sample)?;
        Ok(sample)
    }
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
        use std::fmt::Write as _;
        let result =
            irmind_app::verify_export_details(&LocalExportVerifier, path, Some(expected_key))?;
        let mut message = format!(
            "Verified {} entries; analyst key {}; original bytes verified {}; unavailable {}",
            result.entries,
            result.analyst_key_fingerprint,
            result.source_bytes_verified,
            result.source_bytes_unavailable
        );
        for notice in result.source_query_limits {
            let _ = write!(
                message,
                "\n{} — {}",
                notice.capture_sha256(),
                notice.message()
            );
        }
        Ok(message)
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
                let key = source_query_settings::storage_credential_name(name);
                let present = match self.secret_backend.get(&key) {
                    Ok(_) => true,
                    Err(AppError::SecretMissing) => false,
                    Err(error) => return Err(error.into()),
                };
                Ok(CredentialStatus {
                    name: name.clone(),
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
        if !self.credential_fields.iter().any(|field| field == name) {
            return Err(anyhow!("unknown module credential field"));
        }
        let key = source_query_settings::storage_credential_name(name);
        self.secret_backend.put(&key, value)?;
        if self.secret_backend.get(&key)?.expose_secret() != value.expose_secret() {
            return Err(anyhow!("credential write verification failed"));
        }
        Ok(())
    }
    fn delete_credential(&self, name: &str) -> Result<()> {
        if !self.credential_fields.iter().any(|field| field == name) {
            return Err(anyhow!("unknown module credential field"));
        }
        let key = source_query_settings::storage_credential_name(name);
        self.secret_backend.delete(&key)?;
        match self.secret_backend.get(&key) {
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
            "secrets" => {
                let names = self
                    .credential_fields
                    .iter()
                    .map(|name| source_query_settings::storage_credential_name(name))
                    .collect::<Vec<_>>();
                let names = names.iter().map(String::as_str).collect::<Vec<_>>();
                engine.migrate_secret_backend(
                    self.secret_backend.as_ref(),
                    target_secrets.as_ref(),
                    &names,
                )?;
            }
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
        if let ConfigChange::SetCertificateAuthority { path, sha256, .. } = &change
            && !path.is_empty()
            && irmind_http::load_ca_file(Path::new(path))?.fingerprint() != sha256
        {
            return Err(anyhow!(
                "the CA file changed after its fingerprint was shown"
            ));
        }
        let overridden = self.configuration_is_overridden(&change);
        if overridden {
            return Err(anyhow!(
                "this setting is overridden by a flag or environment variable"
            ));
        }
        let current = self.config_store.load()?;
        let next = current.changed(change.clone(), &self.manifests)?;
        if let ConfigChange::ConfigureModel(model) = &change {
            model_probe::validate_configuration(model, self.secret_backend.as_ref())?;
        }
        let active_module = match &change {
            ConfigChange::SelectLlm(Some(id)) => Some(id.as_str()),
            ConfigChange::ConfigureModel(model) => Some(model.module.as_str()),
            ConfigChange::SetEnabled {
                module,
                enabled: true,
            } => Some(module.as_str()),
            ConfigChange::SetValue { module, .. }
            | ConfigChange::SetCertificateAuthority { module, .. }
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
    fn ca_fingerprint(&self, path: &Path) -> Result<String> {
        Ok(irmind_http::load_ca_file(path)?.fingerprint().to_owned())
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
        output: irmind_app::ModelOutputProfile,
    ) -> Result<String> {
        model_probe::test_model_connection(
            provider,
            base_url,
            model,
            key,
            self.secret_backend.as_ref(),
            output,
        )
    }
}

mod skills;
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

#[cfg(test)]
mod credential_fields_tests {
    #[test]
    fn every_compiled_secret_field_is_exposed_by_the_keystore_form() {
        let expected = super::configuration::compiled_manifests()
            .iter()
            .flat_map(|manifest| manifest.config.iter())
            .filter(|field| field.secret)
            .map(|field| field.name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            super::compiled_credential_fields()
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
    }
    #[cfg(feature = "siem-elastic")]
    #[test]
    fn elastic_key_is_available_without_ambient_credentials() {
        assert!(super::compiled_credential_fields().contains(&"IRMIND_ELASTIC_API_KEY"));
    }
    #[cfg(feature = "siem-chronicle")]
    #[test]
    fn chronicle_credentials_are_available_without_ambient_credentials() {
        for field in irmind_mod_siem_chronicle::MANIFEST
            .config
            .iter()
            .filter(|field| field.secret)
        {
            assert!(super::compiled_credential_fields().contains(&field.name));
        }
    }
}
