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

pub(super) fn run_once(cancel: &CancellationToken) -> Result<bool> {
    let mut cli = Cli::parse();
    let interactive = matches!(&cli.command, None | Some(Command::Tui { .. }));
    if let Some(Command::VerifyExport { path, expected_key }) = &cli.command {
        return run_verify_export(path, expected_key.as_deref());
    }
    let (home, store, active) = open_local(&cli, interactive)?;
    let config_store = Arc::new(TomlConfigurationStore::new(&home));
    let manifests = configuration::compiled_manifests();
    let saved = config_store.load()?;
    saved.validate(&manifests)?;
    let module_overrides = configuration::selection_overrides(&cli);
    configuration::resolve_cli(&mut cli, &saved)?;
    let new_analyst_key = interactive && active.new_analyst_key;
    let signer = active.signer;
    let secrets = active.secret_backend;
    let signer_backend = active.signer_backend;
    let verifier = trusted_verifier(store.as_ref(), signer.as_ref(), signer_backend.as_ref())?;
    let guard = Arc::new(MandatoryGuard::new()?);
    let (registry, config_issues) =
        configured_registry(&cli, &saved, secrets.as_ref(), interactive)?;
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
    if let Some(pricing) = load_pricing(&saved)? {
        engine = engine.with_pricing(pricing);
    }
    engine.verify_configuration(config_store.as_ref(), &manifests)?;
    let workspace_io = RootWorkspaceIo {
        home: home.clone(),
        credential_fields: compiled_credential_fields(),
        store: store.clone(),
        signer_backend,
        secret_backend: secrets.clone(),
        config_store,
        manifests,
        module_overrides,
        signer_id: active.signer_id,
        secrets_id: active.secrets_id,
        #[cfg(feature = "keystore-file")]
        file_backend: active.file_backend,
    };
    let module_statuses = module_statuses(&cli, &registry, &config_issues, &workspace_io, &saved);
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
        },
    )
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
            None,
            context.new_analyst_key,
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
