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
    let Some(prepared) = PreparedStartup::new(cli, interactive)? else {
        return Ok(false);
    };
    prepared.run(cancel)
}

impl PreparedStartup {
    fn new(mut cli: Cli, interactive: bool) -> Result<Option<Self>> {
        let (home, store, active) = open_local(&cli, interactive)?;
        super::diagnostics::init(&home)?;
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
        if !reconcile_configuration(
            &preflight,
            config_store.as_ref(),
            &manifests,
            &home,
            interactive,
            guard.as_ref(),
        )? {
            return Ok(None);
        }
        let saved = config_store.load()?;
        saved.validate(&manifests)?;
        let overrides = configuration::collect_egress_overrides(&cli, &saved);
        let allow_environment = decide_overrides(
            &preflight,
            config_store.as_ref(),
            &manifests,
            &overrides,
            interactive,
            guard.as_ref(),
        )?;
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
            verifier,
            guard,
        } = self;
        let signer = active.signer;
        let secrets = active.secret_backend;
        let signer_backend = active.signer_backend;
        let new_analyst_key = interactive && active.new_analyst_key;
        let (registry, config_issues) = configured_registry(
            &cli,
            &saved,
            secrets.as_ref(),
            allow_environment,
            interactive,
        )?;
        let engine = registry.bind(Engine::new(
            EnginePorts::new(
                store.clone(),
                store.clone(),
                store.clone(),
                store.clone(),
                CryptoPorts::new(signer.clone(), verifier),
                guard.clone(),
                registry.parser()?,
            ),
            ExecutionMode::Attended,
            Arc::new(SystemClock),
        )?)?;
        let engine = apply_session_policy(engine, &cli, &saved, config_store.as_ref(), &manifests)?;
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
    let (fingerprint, entries) =
        irmind_app::verify_export(&LocalExportVerifier, path, expected_key)?;
    println!("verified {entries} audit entries; analyst key fingerprint {fingerprint}");
    Ok(false)
}

fn present(command: Option<Command>, context: cli::AutomationContext<'_, '_>) -> Result<bool> {
    match command {
        None => irmind_tui::run_workspace(
            context.engine,
            context.selected_model,
            context.workspace_io,
            context.module_statuses,
            context.cancel,
            irmind_tui::WorkspaceLaunch {
                initial_case: None,
                new_analyst_key: context.new_analyst_key,
                overrides_active: context.overrides_active,
                mouse_capture: context.mouse_capture,
            },
        ),
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
    let active = match keystore::load_or_configure(
        &home,
        cli.passphrase_fd,
        interactive,
        !store.list_cases()?.is_empty(),
    ) {
        Ok(active) => active,
        Err(error) => {
            if interactive {
                let _ = irmind_tui::show_startup_error(
                    "The selected keystore cannot be unlocked or configured. No investigation can start.",
                );
            }
            return Err(error);
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
