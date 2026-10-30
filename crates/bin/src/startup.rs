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
    Arc, AuditLog, BTreeMap, CancellationToken, Cli, Command, ConfigurationStore, Context,
    CryptoPorts, DEFAULT_LLM_MODULE, Engine, EnginePorts, ExecutionMode, JsonParser,
    LocalExportVerifier, LocalStore, LocalVerifier, MandatoryGuard, ModuleConfig, ModuleRegistry,
    ModuleStatus, OpenAiCompatible, Parser, PathBuf, PersistentConfig, ProjectDirs, Repository,
    Result, RootWorkspaceIo, SecretBackend, SignerBackend, SystemClock, TomlConfigurationStore,
    anyhow, cli, compiled_credential_fields, configuration, configuration_issue, keystore,
    load_module_config, load_policy, load_pricing,
};
use irmind_app::ContentGuard as _;

mod status;
use status::module_statuses;
mod preflight;
use preflight::{decide_overrides, reconcile_configuration};

struct PreparedStartup {
    cli: Cli,
    interactive: bool,
    home: PathBuf,
    store: Arc<LocalStore>,
    active: keystore::ActiveKeystore,
    config_store: Arc<TomlConfigurationStore>,
    manifests: Vec<&'static irmind_app::modules::ModuleManifest>,
    saved: PersistentConfig,
    allow_environment: bool,
    module_overrides: std::collections::HashSet<String>,
    overrides_active: bool,
    verifier: Arc<LocalVerifier>,
    guard: Arc<MandatoryGuard>,
}

pub(super) fn run_once(cancel: &CancellationToken) -> Result<bool> {
    let cli = Cli::parse();
    let interactive = matches!(&cli.command, None | Some(Command::Tui { .. }));
    if let Some(Command::VerifyExport { path, expected_key }) = &cli.command {
        return run_verify_export(path, expected_key.as_deref());
    }
    let prepared = match PreparedStartup::new(cli, interactive) {
        Err(error) if error.downcast_ref::<keystore::SetupCancelled>().is_some() => {
            return Ok(false);
        }
        other => other?,
    };
    let Some(prepared) = prepared else {
        return Ok(false);
    };
    prepared.run(cancel)
}

impl PreparedStartup {
    fn new(mut cli: Cli, interactive: bool) -> Result<Option<Self>> {
        let (home, store, active) = open_local(&cli, interactive)?;
        let config_store = Arc::new(TomlConfigurationStore::new(&home));
        let manifests = configuration::compiled_manifests();
        let verifier = Arc::new(trusted_verifier(
            store.as_ref(),
            active.signer.as_ref(),
            active.signer_backend.as_ref(),
        )?);
        let guard = Arc::new(MandatoryGuard::new()?);
        let preflight = Engine::new(
            EnginePorts::new(
                store.clone(),
                store.clone(),
                store.clone(),
                store.clone(),
                CryptoPorts::new(active.signer.clone(), verifier.clone()),
                guard.clone(),
                Arc::new(JsonParser),
            ),
            ExecutionMode::Attended,
            Arc::new(SystemClock),
        )?;
        let Some(saved) = load_approved_config(
            &preflight,
            config_store.as_ref(),
            &manifests,
            &home,
            interactive,
            guard.as_ref(),
        )?
        else {
            return Ok(None);
        };
        let overrides = configuration::collect_egress_overrides(&cli, &saved);
        let Some(allow_environment) = retry_startup(
            || {
                decide_overrides(
                    &preflight,
                    config_store.as_ref(),
                    &manifests,
                    &overrides,
                    interactive,
                    guard.as_ref(),
                )
            },
            &home,
            guard.as_ref(),
            interactive,
            "override-review",
            "Correct the override or restart without it",
        )?
        else {
            return Ok(None);
        };
        let module_overrides = if allow_environment {
            configuration::selection_overrides(&cli)
        } else {
            std::collections::HashSet::default()
        };
        configuration::resolve_cli(&mut cli, &saved, allow_environment)?;
        Ok(Some(Self {
            cli,
            interactive,
            home,
            store,
            active,
            config_store,
            manifests,
            saved,
            allow_environment,
            module_overrides,
            overrides_active: allow_environment && !overrides.is_empty(),
            verifier,
            guard,
        }))
    }

    fn run(self, cancel: &CancellationToken) -> Result<bool> {
        let (registry, config_issues) = configured_registry(
            &self.cli,
            &self.saved,
            self.active.secret_backend.as_ref(),
            self.allow_environment,
            self.interactive,
        )?;
        let engine = self.compose_engine(&registry)?;
        let Self {
            cli,
            interactive,
            home,
            store,
            active,
            config_store,
            manifests,
            saved,
            allow_environment,
            module_overrides,
            overrides_active,
            verifier: _,
            guard,
        } = self;
        let secrets = active.secret_backend;
        let signer_backend = active.signer_backend;
        let new_analyst_key = interactive && active.new_analyst_key;
        let workspace_io = RootWorkspaceIo {
            home: home.clone(),
            credential_fields: compiled_credential_fields(),
            store: store.clone(),
            signer_backend,
            secret_backend: secrets.clone(),
            config_store,
            manifests,
            module_overrides,
            allow_environment,
            signer_id: active.signer_id,
            secrets_id: active.secrets_id,
            #[cfg(feature = "keystore-file")]
            file_backend: active.file_backend,
        };
        let module_statuses =
            module_statuses(&cli, &registry, &config_issues, &workspace_io, &saved);
        let selected_model = match cli.llm_module.as_deref() {
            Some(id) if interactive => registry.llm(id).ok(),
            Some(id) => Some(registry.llm(id)?),
            None => None,
        };
        present(
            cli.command,
            cli::AutomationContext {
                engine: &engine,
                store: &store,
                guard: &guard,
                registry: &registry,
                llm_module: cli.llm_module.as_deref(),
                selected_model,
                workspace_io: &workspace_io,
                module_statuses: &module_statuses,
                cancel,
                new_analyst_key,
                overrides_active,
                mouse_capture: saved.mouse_capture.unwrap_or(true),
            },
        )
    }

    fn compose_engine<'a>(&self, registry: &'a ModuleRegistry) -> Result<Engine<'a>> {
        let engine = registry.bind(
            Engine::new(
                EnginePorts::new(
                    self.store.clone(),
                    self.store.clone(),
                    self.store.clone(),
                    self.store.clone(),
                    CryptoPorts::new(self.active.signer.clone(), self.verifier.clone()),
                    self.guard.clone(),
                    registry.parser()?,
                ),
                ExecutionMode::Attended,
                Arc::new(SystemClock),
            )?
            .with_large_case_pipeline(self.store.clone(), Arc::new(JsonParser)),
        )?;
        apply_session_policy(
            engine,
            &self.cli,
            &self.saved,
            self.config_store.as_ref(),
            &self.manifests,
        )
    }
}

fn load_approved_config(
    preflight: &Engine<'_>,
    config_store: &TomlConfigurationStore,
    manifests: &[&irmind_app::modules::ModuleManifest],
    home: &std::path::Path,
    interactive: bool,
    guard: &MandatoryGuard,
) -> Result<Option<PersistentConfig>> {
    let reconciled = retry_startup(
        || reconcile_configuration(preflight, config_store, manifests, home, interactive, guard),
        home,
        guard,
        interactive,
        "config-recovery",
        "Review or restore config.toml",
    )?;
    if reconciled != Some(true) {
        return Ok(None);
    }
    retry_startup(
        || {
            let saved = config_store.load()?;
            saved.validate(manifests)?;
            Ok(saved)
        },
        home,
        guard,
        interactive,
        "config-load",
        "Restore the approved copy or correct config.toml",
    )
}

fn retry_startup<T>(
    mut operation: impl FnMut() -> Result<T>,
    home: &std::path::Path,
    guard: &MandatoryGuard,
    interactive: bool,
    stage: &str,
    advice: &str,
) -> Result<Option<T>> {
    loop {
        match operation() {
            Ok(value) => return Ok(Some(value)),
            Err(error) if interactive => {
                let reason = guard.screen(&format!("{error:#}"))?.text;
                tracing::error!(target: "irmind::operations", stage, causes = %reason, "startup operation failed");
                let message = format!(
                    "{reason}. {advice}, then retry. Diagnostics: {}",
                    home.join("diagnostics.log").display()
                );
                if !irmind_tui::show_startup_error(&message)? {
                    return Ok(None);
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn apply_session_policy<'a>(
    mut engine: Engine<'a>,
    cli: &Cli,
    saved: &PersistentConfig,
    store: &dyn ConfigurationStore,
    manifests: &[&irmind_app::modules::ModuleManifest],
) -> Result<Engine<'a>> {
    if let Some(path) = &cli.policy {
        let (policy, fingerprint) = load_policy(path)?;
        engine = engine.with_policy(policy, fingerprint)?;
    }
    if let Some(pricing) = load_pricing(saved)? {
        engine = engine.with_pricing(pricing);
    }
    engine.verify_configuration(store, manifests)?;
    Ok(engine)
}

fn run_verify_export(path: &std::path::Path, expected_key: Option<&str>) -> Result<bool> {
    let result = irmind_app::verify_export_details(&LocalExportVerifier, path, expected_key)?;
    println!(
        "verified {} audit entries; analyst key fingerprint {}",
        result.entries, result.analyst_key_fingerprint
    );
    if result.format_version == 4 {
        println!(
            "signed source manifests: {}; original bytes verified: {}; originals unavailable in package: {}",
            result.source_manifests, result.source_bytes_verified, result.source_bytes_unavailable
        );
    }
    Ok(false)
}

fn present(command: Option<Command>, context: cli::AutomationContext<'_, '_>) -> Result<bool> {
    match command {
        None => {
            let saved = context.workspace_io.config_store.load()?;
            irmind_tui::run_workspace(
                context.engine,
                context.selected_model,
                context.workspace_io,
                context.module_statuses,
                context.cancel,
                irmind_tui::WorkspaceLaunch {
                    initial_case: None,
                    resume_last_case: saved.resume_last_case.unwrap_or(true).into(),
                    new_analyst_key: context.new_analyst_key,
                    overrides_active: context.overrides_active,
                    mouse_capture: context.mouse_capture,
                    theme: saved.theme.as_deref(),
                },
            )
        }
        Some(command) => context.run(command),
    }
}

mod registration;
use registration::configured_registry;

fn open_local(
    cli: &Cli,
    interactive: bool,
) -> Result<(PathBuf, Arc<LocalStore>, keystore::ActiveKeystore)> {
    let home = match &cli.home {
        Some(path) => path.clone(),
        None => ProjectDirs::from("", "IRMind", "IRMind")
            .ok_or_else(|| anyhow!("cannot determine the user's standard data directory"))?
            .data_local_dir()
            .to_path_buf(),
    };
    let store = loop {
        match LocalStore::open(&home) {
            Ok(store) => break Arc::new(store),
            Err(error) if interactive => {
                let message = format!(
                    "Cannot open the private data directory {}: {error}. Check ownership and permissions, then retry.",
                    home.display()
                );
                if !irmind_tui::show_startup_error(&message)? {
                    return Err(error.into());
                }
            }
            Err(error) => return Err(error.into()),
        }
    };
    super::diagnostics::init(&home)?;
    let active = loop {
        match keystore::load_or_configure(
            &home,
            cli.passphrase_fd,
            interactive,
            !store.list_cases()?.is_empty(),
        ) {
            Ok(active) => break active,
            Err(error) if error.downcast_ref::<keystore::SetupCancelled>().is_some() => {
                return Err(error);
            }
            Err(error) if interactive => {
                let message = format!(
                    "Cannot read keystore configuration in {}: {error:#}. Repair the file or restore a backup, then retry.",
                    home.display()
                );
                tracing::error!(target: "irmind::operations", stage = "keystore-config", causes = %error, "startup operation failed");
                if !irmind_tui::show_startup_error(&message)? {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    };
    Ok((home, store, active))
}

fn trusted_verifier(
    store: &LocalStore,
    signer: &dyn irmind_app::Signer,
    signer_backend: &dyn SignerBackend,
) -> Result<LocalVerifier> {
    let mut verifier = LocalVerifier::from_signer(signer);
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
            let key = signer_backend
                .public_key_for_actor(&actor)
                .with_context(|| format!("load trusted public key for {}", actor.as_storage()))?;
            verifier = verifier.with_trusted_key(&actor, &key)?;
        }
    }
    Ok(verifier)
}
