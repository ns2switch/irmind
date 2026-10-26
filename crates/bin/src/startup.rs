use super::{
    Anthropic, Arc, AuditLog, AwsCloudTrail, BTreeMap, CancellationToken, Cli, Command, Context,
    CrowdStrike, CryptoPorts, DEFAULT_LLM_MODULE, DeepSeek, Engine, EnginePorts, ExecutionMode,
    JsonParser, LocalExportVerifier, LocalStore, LocalVerifier, MandatoryGuard, Misp, ModuleConfig,
    ModuleRegistry, ModuleStatus, OpenAiCompatible, OpenRouter, Parser, PathBuf, ProjectDirs,
    Repository, Result, RootWorkspaceIo, SecretBackend, SentinelOne, SignerBackend, Splunk,
    SystemClock, VirusTotal, anyhow, cli, compiled_credential_fields, configuration_issue,
    keystore, load_module_config, load_policy, load_pricing,
};

mod status;
use status::module_statuses;

pub(super) fn run_once(cancel: &CancellationToken) -> Result<bool> {
    let cli = Cli::parse();
    let interactive = matches!(&cli.command, None | Some(Command::Tui { .. }));
    if let Some(Command::VerifyExport { path, expected_key }) = &cli.command {
        let (fingerprint, entries) =
            irmind_app::verify_export(&LocalExportVerifier, path, expected_key.as_deref())?;
        println!("verified {entries} audit entries; analyst key fingerprint {fingerprint}");
        return Ok(false);
    }
    let (home, store, active) = open_local(&cli, interactive)?;
    let new_analyst_key = interactive && active.new_analyst_key;
    let signer = active.signer;
    let secrets = active.secret_backend;
    let signer_backend = active.signer_backend;
    let verifier = trusted_verifier(store.as_ref(), signer.as_ref(), signer_backend.as_ref())?;
    let guard = Arc::new(MandatoryGuard::new()?);
    let (registry, config_issues) = configured_registry(&cli, secrets.as_ref(), interactive)?;
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
        home: home.clone(),
        credential_fields: compiled_credential_fields(),
        store: store.clone(),
        signer_backend,
        secret_backend: secrets.clone(),
        signer_id: active.signer_id,
        secrets_id: active.secrets_id,
        #[cfg(feature = "keystore-file")]
        file_backend: active.file_backend,
    };
    let module_statuses = module_statuses(&cli, &registry, &config_issues, &workspace_io);
    let selected_model = match cli.llm_module.as_deref() {
        Some(id) if interactive => registry.llm(id).ok(),
        Some(id) => Some(registry.llm(id)?),
        None => None,
    };
    let restart = match cli.command {
        None => irmind_tui::run_workspace(
            &engine,
            selected_model,
            &workspace_io,
            &module_statuses,
            cancel,
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
            cancel,
            new_analyst_key,
        }
        .run(command)?,
    };
    Ok(restart)
}

fn configured_registry(
    cli: &Cli,
    secrets: &dyn SecretBackend,
    interactive: bool,
) -> Result<(ModuleRegistry, BTreeMap<&'static str, String>)> {
    let mut registry = ModuleRegistry::new();
    let mut config_issues = BTreeMap::<&'static str, String>::new();
    registry.register(Box::new(JsonParser), &ModuleConfig::new())?;
    register_llm(cli, secrets, interactive, &mut registry, &mut config_issues)?;
    register_security_products(cli, secrets, interactive, &mut registry, &mut config_issues)?;
    register_edr_and_intel(cli, secrets, interactive, &mut registry, &mut config_issues)?;
    Ok((registry, config_issues))
}

fn register_llm(
    cli: &Cli,
    secrets: &dyn SecretBackend,
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
    secrets: &dyn SecretBackend,
    interactive: bool,
    registry: &mut ModuleRegistry,
    config_issues: &mut BTreeMap<&'static str, String>,
) -> Result<()> {
    let _ = (&secrets, &registry, &config_issues);
    #[cfg(feature = "siem-splunk")]
    if cli.enable_splunk {
        register_configured!(
            registry,
            Splunk,
            irmind_mod_siem_splunk::MANIFEST,
            secrets,
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
    secrets: &dyn SecretBackend,
    interactive: bool,
    registry: &mut ModuleRegistry,
    config_issues: &mut BTreeMap<&'static str, String>,
) -> Result<()> {
    let _ = (&secrets, &registry, &config_issues);
    #[cfg(feature = "edr-crowdstrike")]
    if cli.enable_crowdstrike {
        register_configured!(
            registry,
            CrowdStrike,
            irmind_mod_edr_crowdstrike::MANIFEST,
            secrets,
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
