use super::{
    CancellationToken, CaseId, CaseStatus, ConfigChange, CrosstermBackend, Engine, Event,
    HomeAction, HomeState, Instant, KeyCode, KeyModifiers, LlmPort, Mode, ModuleStatus, Result,
    Terminal, WorkspaceIo, case, event, io, load_rows, mpsc, render_home, update,
};
use crate::{prompt_hidden, workflow::CaseWorkflow};
use secrecy::ExposeSecret as _;
use std::time::Duration;

type Worker<'scope> = std::thread::ScopedJoinHandle<'scope, Result<String>>;

pub(super) struct HomeRuntime<'scope, 'env, 'ports> {
    pub terminal: &'env mut Terminal<CrosstermBackend<io::Stdout>>,
    pub engine: &'env Engine<'ports>,
    pub model: Option<&'env dyn LlmPort>,
    pub io_ops: &'env dyn WorkspaceIo,
    pub modules: &'env [ModuleStatus],
    pub shutdown: &'env CancellationToken,
    pub scope: &'scope std::thread::Scope<'scope, 'env>,
    pub state: HomeState,
    pub statuses: mpsc::Receiver<(CaseId, CaseStatus)>,
    pub new_analyst_key: bool,
    pub mouse_capture: bool,
    pub(super) verify_task: Option<Worker<'scope>>,
    pub(super) verify_started: Option<Instant>,
    pub(super) migration_task: Option<Worker<'scope>>,
    pub(super) migration_started: Option<Instant>,
    pub(super) model_probe_task: Option<Worker<'scope>>,
    pub(super) model_models_task:
        Option<std::thread::ScopedJoinHandle<'scope, Result<Vec<String>>>>,
    pub(super) outcome: crate::WorkspaceOutcome,
}

impl HomeRuntime<'_, '_, '_> {
    pub(super) fn run(&mut self) -> Result<crate::WorkspaceOutcome> {
        loop {
            if self.shutdown.is_cancelled() {
                break;
            }
            self.poll_tasks()?;
            while let Ok((id, status)) = self.statuses.try_recv() {
                if let Some(row) = self.state.rows.iter_mut().find(|row| row.id == id) {
                    row.status = status;
                }
            }
            render_home(
                self.terminal,
                &self.state,
                self.engine,
                self.modules,
                self.model,
                self.new_analyst_key,
            )?;
            if !event::poll(Duration::from_millis(100))? {
                continue;
            }
            let input = event::read()?;
            if let Event::Paste(value) = &input {
                super::state::paste(&mut self.state, value);
                continue;
            }
            let Event::Key(key) = input else {
                continue;
            };
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('u') {
                super::state::clear_active_field(&mut self.state);
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                self.state.confirm_exit = crate::ExitConfirmation::Pending;
                self.state.notice = "Exit IRMind? Enter confirms; Esc cancels.".into();
                continue;
            }
            if self.state.confirm_exit == crate::ExitConfirmation::Pending {
                let action = update(&mut self.state, key.code);
                if self.apply_action(action)? {
                    break;
                }
                continue;
            }
            if self.migration_task.is_some()
                || (self.verify_task.is_some() && self.state.mode == Mode::VerifyExport)
            {
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('k') {
                if self.state.mode != Mode::List {
                    self.state.palette_return = Some(self.state.mode);
                    self.state.mode = Mode::List;
                }
                self.state.input = "/".into();
                continue;
            }
            let action = update(&mut self.state, key.code);
            if self.apply_action(action)? {
                break;
            }
        }
        Ok(self.outcome)
    }

    fn poll_tasks(&mut self) -> Result<()> {
        self.poll_ollama_models();
        self.poll_model_probe();
        self.poll_verify_export();
        self.poll_migration()?;
        Ok(())
    }

    fn poll_ollama_models(&mut self) {
        if self
            .model_models_task
            .as_ref()
            .is_some_and(std::thread::ScopedJoinHandle::is_finished)
            && let Some(task) = self.model_models_task.take()
        {
            match task.join() {
                Ok(Ok(models)) => {
                    self.state.model_setup.models = models;
                    self.state.model_setup.selected_model = 0;
                    self.state.model_setup.step = super::model::ModelStep::AvailableModels;
                    self.state.model_setup.notice = if self.state.model_setup.models.is_empty() {
                        "No models returned; Tab enters a model ID manually".into()
                    } else {
                        "Choose an available model".into()
                    };
                }
                Ok(Err(error)) => {
                    self.state.model_setup.step = super::model::ModelStep::AvailableModels;
                    self.state.model_setup.notice = format!("Model list: {error}");
                }
                Err(_) => {
                    self.state.model_setup.step = super::model::ModelStep::AvailableModels;
                    self.state.model_setup.notice = "Model discovery failed".into();
                }
            }
        }
    }

    fn poll_model_probe(&mut self) {
        if self
            .model_probe_task
            .as_ref()
            .is_some_and(std::thread::ScopedJoinHandle::is_finished)
            && let Some(task) = self.model_probe_task.take()
        {
            self.state.model_setup.notice = match task.join() {
                Ok(Ok(message)) => message,
                Ok(Err(error)) => format!("Connection failed: {error}"),
                Err(_) => "Connection test failed".into(),
            };
        }
    }

    fn poll_verify_export(&mut self) {
        if self
            .verify_task
            .as_ref()
            .is_some_and(std::thread::ScopedJoinHandle::is_finished)
            && let Some(task) = self.verify_task.take()
        {
            self.state.notice = match task.join() {
                Ok(Ok(message)) => message,
                Ok(Err(_)) => {
                    "Export verification failed: check the package and expected key".into()
                }
                Err(_) => "Export verification worker failed".into(),
            };
            self.verify_started = None;
            self.state.mode = Mode::List;
        }
        if let Some(started) = self.verify_started {
            self.state.notice = format!(
                "Verifying export · {}s elapsed",
                started.elapsed().as_secs()
            );
        }
    }

    fn poll_migration(&mut self) -> Result<()> {
        if self
            .migration_task
            .as_ref()
            .is_some_and(std::thread::ScopedJoinHandle::is_finished)
            && let Some(task) = self.migration_task.take()
        {
            self.state.notice = match task.join() {
                Ok(Ok(message)) => {
                    self.state.restart_required = true;
                    message
                }
                Ok(Err(error)) => format!("Keystore migration failed: {error}"),
                Err(_) => "Keystore migration worker failed".into(),
            };
            self.migration_started = None;
            self.state.keystore = Some(self.io_ops.keystore_status()?);
        }
        if let Some(started) = self.migration_started {
            self.state.notice = format!(
                "Migrating keystore · {}s elapsed",
                started.elapsed().as_secs()
            );
        }
        Ok(())
    }

    fn apply_action(&mut self, action: HomeAction) -> Result<bool> {
        match action {
            HomeAction::None => {}
            HomeAction::Quit => return Ok(true),
            HomeAction::Restart => {
                self.outcome = crate::WorkspaceOutcome::Restart;
                return Ok(true);
            }
            HomeAction::Demo => {
                self.outcome = crate::WorkspaceOutcome::Demo;
                return Ok(true);
            }
            HomeAction::OpenCase(id) => self.open_case(&id)?,
            HomeAction::CreateCase => self.create_case()?,
            HomeAction::LoadKeystore => {
                self.state.keystore = Some(self.io_ops.keystore_status()?);
                if let Some(module) = self.state.modules.get(self.state.module_selected)
                    && let Some(name) = module.credentials.first()
                    && let Some(index) = self.state.keystore.as_ref().and_then(|status| {
                        status
                            .credentials
                            .iter()
                            .position(|item| &item.name == name)
                    })
                {
                    self.state.keystore_selected = index;
                }
            }
            HomeAction::VerifyExport(path, fingerprint) => {
                let io_ops = self.io_ops;
                self.verify_task = Some(
                    self.scope
                        .spawn(move || io_ops.verify_export(&path, &fingerprint)),
                );
                self.verify_started = Some(Instant::now());
            }
            HomeAction::Migrate(capability) => self.start_migration(capability),
            HomeAction::AddCredential => self.add_credential()?,
            HomeAction::DeleteCredential => self.delete_credential()?,
            HomeAction::ChangePassphrase => self.change_passphrase(),
            HomeAction::ChangeModule(change, confirmed) => {
                return Ok(self.change_module(change, confirmed));
            }
            HomeAction::DiscoverModels => {
                if self.model_models_task.is_none() {
                    let io_ops = self.io_ops;
                    let draft = self.state.model_setup.draft();
                    self.state.model_setup.notice = "Listing models…".into();
                    self.model_models_task = Some(self.scope.spawn(move || {
                        io_ops.list_provider_models(draft.provider, &draft.url, draft.key.as_ref())
                    }));
                }
            }
            HomeAction::ProbeModel(draft) => {
                if self.model_probe_task.is_none() {
                    let io_ops = self.io_ops;
                    self.state.model_setup.notice = "Testing with synthetic text…".into();
                    self.model_probe_task = Some(self.scope.spawn(move || {
                        io_ops.test_model_connection(
                            draft.provider,
                            &draft.url,
                            &draft.name,
                            draft.key.as_ref(),
                        )
                    }));
                }
            }
            HomeAction::SaveModel(draft) => return Ok(self.save_model(&draft)),
        }
        Ok(false)
    }

    fn save_model(&mut self, draft: &super::model::ModelDraft) -> bool {
        let result =
            super::model::save_configuration(self.io_ops, self.engine, self.modules, draft);
        match result {
            Ok(()) => {
                self.outcome = crate::WorkspaceOutcome::Restart;
                true
            }
            Err(error) => {
                self.state.model_setup.notice = format!("Cannot save model: {error}");
                false
            }
        }
    }

    fn change_module(&mut self, change: ConfigChange, confirmed: bool) -> bool {
        let change = if let ConfigChange::SetValue {
            module,
            field,
            value,
        } = &change
            && field.ends_with("_CA_PEM")
        {
            let sha256 = if value.is_empty() {
                String::new()
            } else {
                match self.io_ops.ca_fingerprint(std::path::Path::new(value)) {
                    Ok(fingerprint) => fingerprint,
                    Err(error) => {
                        self.state.notice = format!("Cannot approve CA file: {error}");
                        self.state.module_edit = Some(super::ModuleEdit {
                            module: module.clone(),
                            field: field.clone(),
                            value: value.clone(),
                            replace_on_type: false,
                        });
                        return false;
                    }
                }
            };
            ConfigChange::SetCertificateAuthority {
                module: module.clone(),
                path_field: field.clone(),
                path: value.clone(),
                sha256,
            }
        } else {
            change
        };
        match self
            .io_ops
            .change_module_configuration(self.engine, change.clone(), confirmed)
        {
            Ok(true) => {
                self.outcome = crate::WorkspaceOutcome::Restart;
                true
            }
            Ok(false) => {
                self.state.notice = "Configuration is unchanged".into();
                false
            }
            Err(error)
                if error
                    .downcast_ref::<irmind_app::AppError>()
                    .is_some_and(|error| {
                        matches!(
                            error,
                            irmind_app::AppError::Fixed(
                                irmind_app::FixedAppError::PolicyConfigurationConfirmationRequired
                            )
                        )
                    }) =>
            {
                self.state.pending_module_change = Some(change);
                self.state.notice =
                    "Confirm that this setting may send case data off this device".into();
                false
            }
            Err(error) => {
                if let ConfigChange::SetValue {
                    module,
                    field,
                    value,
                } = &change
                {
                    self.state.module_edit = Some(super::ModuleEdit {
                        module: module.clone(),
                        field: field.clone(),
                        value: value.clone(),
                        replace_on_type: false,
                    });
                }
                self.state.notice = format!("Configuration change failed: {error}");
                false
            }
        }
    }

    fn open_case(&mut self, id: &CaseId) -> Result<()> {
        let result = case::run_case(
            self.terminal,
            self.engine,
            self.model,
            self.io_ops,
            id,
            self.shutdown,
            case::CasePresentation {
                overrides_active: self.state.overrides_active,
                modules: self.modules,
                mouse_capture: self.mouse_capture,
                resumed: false,
            },
        );
        self.state.rows = load_rows(self.engine)?;
        match result {
            Ok(exit) => {
                super::apply_case_exit(&mut self.state, &exit);
                if self.state.mode == Mode::Keystore {
                    self.state.keystore = Some(self.io_ops.keystore_status()?);
                }
                if self.state.mode == Mode::List {
                    self.state.notice = "Returned to case list".into();
                }
            }
            Err(error) => {
                let Some(case_error) = error.downcast_ref::<irmind_app::AppError>() else {
                    return Err(error);
                };
                if matches!(
                    case_error,
                    irmind_app::AppError::InvalidChain(_)
                        | irmind_app::AppError::EvidenceMismatch(_)
                ) && let Some(row) = self.state.rows.iter_mut().find(|row| row.id == *id)
                {
                    row.status = CaseStatus::Inconsistent;
                }
                self.state.notice = format!("Cannot open case: {case_error}");
            }
        }
        Ok(())
    }

    fn create_case(&mut self) -> Result<()> {
        if let Some((field, message)) =
            super::new_case::check(&self.state, self.engine).first_issue()
        {
            self.state.notice = message.into();
            if field >= 2 {
                self.state.remote_scope_step = super::RemoteScopeStep::Remote;
            }
            self.state.form_field = field;
            return Ok(());
        }
        let scope_text = self.state.scope();
        let severity = irmind_app::Severity::parse(&self.state.form[1]);
        let workflow = CaseWorkflow {
            engine: self.engine,
            model: self.model,
            io_ops: self.io_ops,
        };
        let result = severity
            .map_err(|_| "severity must be low, medium, high or critical".to_owned())
            .and_then(|severity| {
                workflow
                    .create_case(&self.state.form[0], severity, &scope_text)
                    .map_err(|error| error.to_string())
            });
        match result {
            Ok(case_id) => {
                self.state.rows = load_rows(self.engine)?;
                self.state.mode = Mode::List;
                self.state.notice = format!("Created signed case {}", case_id.as_str());
                let exit = case::run_case(
                    self.terminal,
                    self.engine,
                    self.model,
                    self.io_ops,
                    &case_id,
                    self.shutdown,
                    case::CasePresentation {
                        overrides_active: self.state.overrides_active,
                        modules: self.modules,
                        mouse_capture: self.mouse_capture,
                        resumed: false,
                    },
                )?;
                super::apply_case_exit(&mut self.state, &exit);
                self.state.rows = load_rows(self.engine)?;
            }
            Err(error) => self.state.notice = format!("Case creation failed: {error}"),
        }
        Ok(())
    }

    fn start_migration(&mut self, capability: &'static str) {
        if let Some(status) = self.state.keystore.as_ref() {
            let current = if capability == "signer" {
                &status.signer_backend
            } else {
                &status.secrets_backend
            };
            let target = if current == "os" { "file" } else { "os" };
            let phrase = if target == "file" && !status.file_backend_active {
                let value = prompt_hidden(
                    self.terminal,
                    "Target file keystore passphrase (input hidden): ",
                );
                match value {
                    Ok(value) => Some(value),
                    Err(error) => {
                        self.state.notice = format!("Migration was not started: {error}");
                        return;
                    }
                }
            } else {
                None
            };
            let io_ops = self.io_ops;
            let engine = self.engine;
            self.migration_task = Some(self.scope.spawn(move || {
                io_ops.migrate_keystore(engine, capability, target, phrase.as_ref())?;
                Ok(format!(
                    "{capability} copied to {target}; restart IRMind to activate it"
                ))
            }));
            self.migration_started = Some(Instant::now());
        }
    }

    fn delete_credential(&mut self) -> Result<()> {
        if let Some(name) = self
            .state
            .keystore
            .as_ref()
            .and_then(|item| item.credentials.get(self.state.keystore_selected))
            .map(|item| item.name.clone())
        {
            self.state.restart_required = true;
            self.state.notice = match self.io_ops.delete_credential(&name) {
                Ok(()) => format!(
                    "Deleted {name}. Active connectors may still use it; use /restart for a new session"
                ),
                Err(error) => format!("Credential deletion failed: {error}"),
            };
            self.state.keystore = Some(self.io_ops.keystore_status()?);
        }
        Ok(())
    }

    fn add_credential(&mut self) -> Result<()> {
        if let Some((name, replacing)) = self
            .state
            .keystore
            .as_ref()
            .and_then(|item| item.credentials.get(self.state.keystore_selected))
            .map(|item| (item.name.clone(), item.present))
        {
            let value = match prompt_hidden(self.terminal, &format!("{name} (input hidden): ")) {
                Ok(value) => value,
                Err(error) => {
                    self.state.notice = format!("Credential entry was cancelled: {error}");
                    return Ok(());
                }
            };
            self.state.restart_required = true;
            self.state.notice = match self.io_ops.put_credential(&name, &value) {
                Ok(()) if replacing => format!(
                    "Replaced {name}. Active connectors still use the previous credential; use /restart for a new session"
                ),
                Ok(()) => {
                    format!("Saved {name}. Restart the session with r to activate the credential")
                }
                Err(error) => format!("Credential update failed: {error}"),
            };
            self.state.keystore = Some(self.io_ops.keystore_status()?);
        }
        Ok(())
    }

    fn change_passphrase(&mut self) {
        let value = match prompt_hidden(
            self.terminal,
            "New file keystore passphrase (input hidden): ",
        ) {
            Ok(value) => value,
            Err(error) => {
                self.state.notice = format!("Passphrase change cancelled: {error}");
                return;
            }
        };
        let repeated = match prompt_hidden(self.terminal, "Repeat new passphrase (input hidden): ")
        {
            Ok(value) => value,
            Err(error) => {
                self.state.notice = format!("Passphrase change cancelled: {error}");
                return;
            }
        };
        self.state.notice = if value.expose_secret() == repeated.expose_secret() {
            match self.io_ops.change_keystore_passphrase(&value) {
                Ok(()) => "File keystore passphrase changed".into(),
                Err(error) => format!("Passphrase change failed: {error}"),
            }
        } else {
            "Passphrases differ; the keystore was not changed".into()
        };
    }
}
