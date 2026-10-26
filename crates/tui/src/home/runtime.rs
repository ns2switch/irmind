use super::{
    CancellationToken, CaseId, CaseStatus, CrosstermBackend, Engine, Event, HomeAction, HomeState,
    Instant, KeyCode, KeyModifiers, LlmPort, Mode, ModuleStatus, Result, Terminal, WorkspaceIo,
    case, event, io, load_rows, mpsc, render_home, update,
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
    pub(super) verify_task: Option<Worker<'scope>>,
    pub(super) verify_started: Option<Instant>,
    pub(super) migration_task: Option<Worker<'scope>>,
    pub(super) migration_started: Option<Instant>,
    pub(super) restart_requested: bool,
}

impl HomeRuntime<'_, '_, '_> {
    pub(super) fn run(&mut self) -> Result<bool> {
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
            let Event::Key(key) = event::read()? else {
                continue;
            };
            if self.migration_task.is_some()
                || (self.verify_task.is_some() && self.state.mode == Mode::VerifyExport)
            {
                continue;
            }
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                break;
            }
            let action = update(&mut self.state, key.code);
            if self.apply_action(action)? {
                break;
            }
        }
        Ok(self.restart_requested)
    }

    fn poll_tasks(&mut self) -> Result<()> {
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
                self.restart_requested = true;
                return Ok(true);
            }
            HomeAction::OpenCase(id) => self.open_case(&id)?,
            HomeAction::CreateCase => self.create_case()?,
            HomeAction::LoadKeystore => self.state.keystore = Some(self.io_ops.keystore_status()?),
            HomeAction::VerifyExport(path, fingerprint) => {
                let io_ops = self.io_ops;
                self.verify_task = Some(
                    self.scope
                        .spawn(move || io_ops.verify_export(&path, &fingerprint)),
                );
                self.verify_started = Some(Instant::now());
            }
            HomeAction::Migrate(capability) => self.start_migration(capability)?,
            HomeAction::AddCredential => self.add_credential()?,
            HomeAction::DeleteCredential => self.delete_credential()?,
            HomeAction::ChangePassphrase => self.change_passphrase()?,
        }
        Ok(false)
    }

    fn open_case(&mut self, id: &CaseId) -> Result<()> {
        case::run_case(
            self.terminal,
            self.engine,
            self.model,
            self.io_ops,
            id,
            self.shutdown,
        )?;
        self.state.rows = load_rows(self.engine)?;
        self.state.notice = "Returned to case list".into();
        Ok(())
    }

    fn create_case(&mut self) -> Result<()> {
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
                case::run_case(
                    self.terminal,
                    self.engine,
                    self.model,
                    self.io_ops,
                    &case_id,
                    self.shutdown,
                )?;
                self.state.rows = load_rows(self.engine)?;
            }
            Err(error) => self.state.notice = format!("Case creation failed: {error}"),
        }
        Ok(())
    }

    fn start_migration(&mut self, capability: &'static str) -> Result<()> {
        if let Some(status) = self.state.keystore.as_ref() {
            let current = if capability == "signer" {
                &status.signer_backend
            } else {
                &status.secrets_backend
            };
            let target = if current == "os" { "file" } else { "os" };
            let phrase = if target == "file" && !status.file_backend_active {
                Some(prompt_hidden(
                    self.terminal,
                    "Target file keystore passphrase (input hidden): ",
                )?)
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
        Ok(())
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
                    "Deleted {name}. Active connectors may still use it; press r to restart this session"
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
            let value = prompt_hidden(self.terminal, &format!("{name} (input hidden): "))?;
            self.state.restart_required = true;
            self.state.notice = match self.io_ops.put_credential(&name, &value) {
                Ok(()) if replacing => format!(
                    "Replaced {name}. Active connectors still use the previous credential; press r to restart this session"
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

    fn change_passphrase(&mut self) -> Result<()> {
        let value = prompt_hidden(
            self.terminal,
            "New file keystore passphrase (input hidden): ",
        )?;
        let repeated = prompt_hidden(self.terminal, "Repeat new passphrase (input hidden): ")?;
        self.state.notice = if value.expose_secret() == repeated.expose_secret() {
            match self.io_ops.change_keystore_passphrase(&value) {
                Ok(()) => "File keystore passphrase changed".into(),
                Err(error) => format!("Passphrase change failed: {error}"),
            }
        } else {
            "Passphrases differ; the keystore was not changed".into()
        };
        Ok(())
    }
}
