use super::command_registry;
use super::conversation::{Card, CardKind};
use super::demo_guide::DemoEvent;
use super::runtime::CaseRuntime;
use super::{CaseWorkflow, FindingKind, PathBuf, PathPicker, Result, parse_approval_args};
use irmind_app::CaseScope;

mod export;
mod parsers;

impl<'env, 'ports> CaseRuntime<'_, 'env, 'ports> {
    pub(super) fn submit(&mut self, prompt: String) -> Result<bool> {
        if prompt.is_empty() {
            return Ok(false);
        }
        if let Some(name) = prompt.strip_prefix("/help ") {
            self.state.messages.push(command_registry::help_for(name));
            return Ok(false);
        }
        if prompt == "/demo exit" && self.io_ops.demo_mode() {
            self.exit_to = super::CaseExit::Quit;
            return Ok(true);
        }
        if self.demo_command(&prompt)? {
            return Ok(false);
        }
        if prompt == "/quit" {
            self.exit_to = super::CaseExit::Quit;
            return Ok(true);
        }
        if prompt == "/home" || prompt == "/cases" {
            return Ok(true);
        }
        if let Some(destination) = match prompt.as_str() {
            "/new" => Some(super::CaseExit::New),
            "/settings" => Some(super::CaseExit::Settings(None, false)),
            "/model" => Some(super::CaseExit::Settings(Some("model".into()), true)),
            "/modules" | "/edit-param" => {
                Some(super::CaseExit::Settings(Some("connectors".into()), true))
            }
            "/config" => Some(super::CaseExit::Settings(Some("preferences".into()), true)),
            "/keystore" | "/cred-add" | "/cred-delete" | "/passphrase" | "/migrate-signer"
            | "/migrate-secrets" => Some(super::CaseExit::Settings(Some("keystore".into()), true)),
            "/open" => Some(super::CaseExit::Home),
            _ => prompt
                .strip_prefix("/open ")
                .map(|value| super::CaseExit::Open(value.into())),
        } {
            self.exit_to = destination;
            return Ok(true);
        }
        if let Some(section) = prompt.strip_prefix("/settings ") {
            self.exit_to = super::CaseExit::Settings(Some(section.trim().to_owned()), false);
            return Ok(true);
        }
        if prompt.starts_with("/module ") {
            self.exit_to = super::CaseExit::Settings(Some("connectors".into()), true);
            return Ok(true);
        }
        if self.session_command(&prompt) {
            return Ok(false);
        }
        if self.active.is_some() {
            let message = if self
                .state
                .demo_guide
                .as_ref()
                .is_some_and(|guide| !guide.hidden())
            {
                "Investigation running."
            } else {
                "Investigation running; use /pause before another command."
            };
            self.state.messages.push(message.into());
            return Ok(false);
        }
        if self.parser_command(&prompt) {
            return Ok(self.parser_exit_requested());
        }
        if !(self.long_command(&prompt)?
            || self.case_command(&prompt)?
            || self.graph_command(&prompt)
            || self.objects_command(&prompt)
            || self.siem_command(&prompt)
            || self.finding_command(&prompt)?
            || self.approval_command(&prompt)?
            || self.evidence_command(&prompt))
        {
            self.investigate_prompt(prompt);
        }
        Ok(false)
    }

    fn session_command(&mut self, prompt: &str) -> bool {
        if prompt == "/sidebar" {
            self.state.sidebar_visible = !self.state.sidebar_visible;
            self.state.focus = if self.state.sidebar_visible {
                super::Focus::Sidebar
            } else {
                super::Focus::Composer
            };
            return true;
        }
        if prompt == "/pause" {
            if let Some((cancel, _, _)) = &self.active {
                cancel.cancel();
                self.state
                    .messages
                    .push("Cancelling active investigation…".into());
            } else {
                self.state
                    .messages
                    .push("No investigation is running.".into());
            }
            return true;
        }
        self.continue_command(prompt)
    }

    fn demo_command(&mut self, prompt: &str) -> Result<bool> {
        if prompt.starts_with("/demo ") && !self.io_ops.demo_mode() {
            self.state
                .messages
                .push("Start /demo from the home screen first.".into());
            return Ok(true);
        }
        if let Some(action) = prompt.strip_prefix("/demo ")
            && let Some(guide) = self.state.demo_guide.as_mut()
        {
            match action {
                "next" => guide.next(),
                "back" => guide.back(),
                "hint" => guide.hint(),
                "skip" => guide.skip(),
                "hide" => guide.hide(),
                "show" => guide.show(),
                "check" => {}
                _ => {
                    self.state.messages.push(
                        "Use /demo next, back, hint, skip, hide, show, check, or exit.".into(),
                    );
                    return Ok(true);
                }
            }
            if action != "check" {
                if matches!(action, "next" | "back" | "skip") {
                    self.state
                        .messages
                        .push(format!("Demo step {}/10", guide.step() + 1));
                }
                return Ok(true);
            }
        }
        if prompt == "/demo check" {
            match self.io_ops.demo_check(self.engine, self.id)? {
                Some(result) => {
                    let safe = self.engine.guard.screen(&result)?.text;
                    self.state.conversation.push(
                        Card::new(CardKind::ToolResult, "Demo check", safe.clone(), false)
                            .with_summary(safe),
                    );
                    if let Some(guide) = self.state.demo_guide.as_mut() {
                        guide.record(DemoEvent::Checked);
                    }
                }
                None => self
                    .state
                    .messages
                    .push("/demo check is available only in the demo".into()),
            }
            return Ok(true);
        }
        if prompt == "/demo" {
            self.state
                .messages
                .push(if let Some(guide) = self.state.demo_guide.as_mut() {
                    guide.show();
                    "The demo guide is visible.".into()
                } else {
                    "Return to /home before starting /demo.".into()
                });
            return Ok(true);
        }
        if self.demo_verify_command(prompt)
            || self.demo_export_command(prompt)?
            || self.demo_verify_export_command(prompt)
        {
            return Ok(true);
        }
        if self.io_ops.demo_mode()
            && ["/ingest", "/settings", "/objects", "/object-read"]
                .iter()
                .any(|command| prompt == *command || prompt.starts_with(&format!("{command} ")))
        {
            self.state.messages.push("The demo uses only its bundled synthetic evidence. Leave the demo to configure connectors or export a real case.".into());
            return Ok(true);
        }
        Ok(false)
    }

    fn demo_export_command(&mut self, prompt: &str) -> Result<bool> {
        if self.io_ops.demo_mode() && (prompt == "/export" || prompt.starts_with("/export ")) {
            if self.active.is_some() {
                self.state
                    .messages
                    .push("Waiting for the current task.".into());
                return Ok(true);
            }
            let Some((path, _)) = self.io_ops.demo_export_identity() else {
                self.state
                    .messages
                    .push("Demo export is unavailable.".into());
                return Ok(true);
            };
            let command = format!("/export {}", path.display());
            if prompt != "/export" && prompt != command {
                self.state
                    .messages
                    .push("The demo exports only inside its temporary directory.".into());
                return Ok(true);
            }
            self.seal_or_export_command(&command)?;
            return Ok(true);
        }
        Ok(false)
    }

    fn demo_verify_command(&mut self, prompt: &str) -> bool {
        if prompt != "/verify" || !self.io_ops.demo_mode() {
            return false;
        }
        let Some(root) = self.io_ops.demo_source_root() else {
            self.state
                .messages
                .push("Demo source is unavailable.".into());
            return true;
        };
        let workflow = self.workflow();
        let id = self.id;
        self.start_task("Verify originals", move |cancel| {
            workflow.verify_with_source_root(id, &root, irmind_app::SourceCheckMode::Full, &cancel)
        });
        true
    }

    fn demo_verify_export_command(&mut self, prompt: &str) -> bool {
        if prompt == "/verify-export" && self.io_ops.demo_mode() {
            if self.active.is_some() {
                self.state
                    .messages
                    .push("Waiting for the current task.".into());
                return true;
            }
            let Some((path, fingerprint)) = self.io_ops.demo_export_identity() else {
                self.state
                    .messages
                    .push("Demo export is unavailable.".into());
                return true;
            };
            let io_ops = self.io_ops;
            self.start_task("Verify export", move |cancel| {
                if cancel.is_cancelled() {
                    return Err(irmind_app::AppError::Cancelled);
                }
                let checked = io_ops
                    .verify_export(&path, &fingerprint)
                    .map_err(|error| irmind_app::AppError::Policy(error.to_string()))?;
                if cancel.is_cancelled() {
                    Err(irmind_app::AppError::Cancelled)
                } else {
                    Ok(checked)
                }
            });
            return true;
        }
        false
    }

    fn continue_command(&mut self, prompt: &str) -> bool {
        if prompt != "/continue" {
            return false;
        }
        if self.active.is_some() {
            self.state
                .messages
                .push("Investigation is still running.".into());
        } else {
            self.investigate_prompt("Continue the previous investigation from the signed case history. Focus on pending questions and cite evidence.".into());
        }
        true
    }

    fn workflow(&self) -> CaseWorkflow<'env, 'ports> {
        CaseWorkflow {
            engine: self.engine,
            model: self.model,
            io_ops: self.io_ops,
        }
    }

    fn investigate_prompt(&mut self, prompt: String) {
        if self.model.is_none() {
            self.state.messages.push(
                "No LLM selected. Use /settings model to configure one, then try again.".into(),
            );
            return;
        }
        match self.engine.guard.screen(&prompt) {
            Ok(visible) => self.state.conversation.push(Card::new(
                CardKind::Analyst,
                "Analyst",
                visible.text,
                false,
            )),
            Err(error) => {
                self.state.messages.push(format!("Guard error: {error}"));
                return;
            }
        }
        self.state.live_reply_cutoff_seq =
            Some(self.state.entries.last().map_or(0, |entry| entry.seq));
        self.state.model_preview.clear();
        let workflow = self.workflow();
        let id = self.id;
        let model_tx = self.model_tx.clone();
        self.start_task("IRMind", move |cancel| {
            workflow.investigate_with_progress(id, &prompt, &cancel, &move |progress| {
                let _ = model_tx.send(progress);
            })
        });
    }

    fn long_command(&mut self, prompt: &str) -> Result<bool> {
        if prompt == "/ingest" {
            self.state.picker = Some(PathPicker::open(std::env::current_dir()?)?);
            return Ok(true);
        }
        if let Some(path) = prompt.strip_prefix("/ingest ") {
            let options = irmind_app::IngestOptions::parse(path)?;
            self.state.pending_ingest = Some(super::state::PendingIngest {
                path: PathBuf::from(options.path),
                copy_original: options.copy_original,
                forced_parser: options.parser,
                analyst_choices: std::collections::BTreeMap::new(),
                time_contexts: std::collections::BTreeMap::new(),
                default_time_context: options.time_context,
            });
            self.start_pending_ingest();
            return Ok(true);
        }
        if prompt == "/rebuild" {
            let workflow = self.workflow();
            let id = self.id;
            self.start_task("Migrate copied evidence", move |cancel| {
                workflow
                    .rebuild_graph(id, &cancel)
                    .map(|count| format!("Converted {count} copied sources to Parquet"))
            });
            return Ok(true);
        }
        if prompt == "/migrate" {
            let workflow = self.workflow();
            let id = self.id;
            self.start_task("Migrate copied evidence", move |cancel| {
                workflow
                    .migrate_legacy(id, &cancel)
                    .map(|count| format!("Converted {count} legacy copied sources to Parquet"))
            });
            return Ok(true);
        }
        if self.verify_command(prompt)? {
            return Ok(true);
        }
        self.seal_or_export_command(prompt)
    }

    pub(super) fn start_pending_ingest(&mut self) {
        let Some(pending) = self.state.pending_ingest.clone() else {
            return;
        };
        let workflow = self.workflow();
        let id = self.id;
        let progress = self.progress_tx.clone();
        self.start_task("Ingest", move |cancel| {
            workflow
                .ingest_path_with_selections(
                    crate::workflow::ingest::IngestRequest {
                        id,
                        path: &pending.path,
                        copy_original: pending.copy_original,
                        forced_parser: pending.forced_parser.as_deref(),
                        analyst_choices: &pending.analyst_choices,
                        time_contexts: &pending.time_contexts,
                        default_time_context: pending.default_time_context,
                        cancel: &cancel,
                    },
                    |done, count, source| {
                        let _ = progress.send(format!("Ingested {done}/{count}: {source}"));
                    },
                )
                .map(|count| format!("Ingested {count} files"))
        });
    }

    fn verify_command(&mut self, prompt: &str) -> Result<bool> {
        if prompt == "/verify" {
            let workflow = self.workflow();
            let id = self.id;
            self.start_task("Verify", move |cancel| {
                workflow
                    .verify(id, &cancel)
                    .map(|count| format!("Verified {count} audit entries"))
            });
            return Ok(true);
        }
        if let Some(args) = prompt.strip_prefix("/verify ") {
            let workflow = self.workflow();
            let id = self.id;
            let (mode, root) = if let Some(sample) = args.strip_prefix("--sample ") {
                let (count, root) = sample
                    .split_once(' ')
                    .ok_or_else(|| anyhow::anyhow!("use /verify --sample <count> <source-root>"))?;
                (irmind_app::SourceCheckMode::Sample(count.parse()?), root)
            } else {
                (irmind_app::SourceCheckMode::Full, args)
            };
            let root = PathBuf::from(root);
            self.start_task("Verify originals", move |cancel| {
                workflow.verify_with_source_root(id, &root, mode, &cancel)
            });
            return Ok(true);
        }
        if prompt == "/verify-graph" {
            let workflow = self.workflow();
            let id = self.id;
            self.start_task("Verify", move |cancel| {
                workflow
                    .verify_graph(id, &cancel)
                    .map(|count| format!("Verified {count} graph records"))
            });
            return Ok(true);
        }
        if let Some(root) = prompt.strip_prefix("/verify-graph ") {
            let workflow = self.workflow();
            let id = self.id;
            let root = PathBuf::from(root);
            self.start_task("Verify Parquet", move |cancel| {
                workflow
                    .verify_parquet_rebuild(id, &root, &cancel)
                    .map(|count| format!("Rebuilt and compared {count} Parquet sources"))
            });
            return Ok(true);
        }
        Ok(false)
    }

    fn case_command(&mut self, prompt: &str) -> Result<bool> {
        match prompt {
            "/help" => self.state.messages.push(command_registry::help()),
            "/scope" => {
                self.state
                    .messages
                    .push(format!("Scope: {}", self.state.case.scope));
                if let Some(guide) = self.state.demo_guide.as_mut() {
                    guide.record(DemoEvent::ScopeViewed);
                }
            }
            "/approvals" => {
                self.state.approvals = self.engine.pending_approvals(self.id)?;
                self.state.approval_sources =
                    super::load_approval_sources(self.engine, self.id, &self.state.approvals)?;
                self.state.tab = 4;
            }
            "/findings" => {
                self.state.findings = self.engine.findings(self.id)?;
                self.state.tab = 8;
            }
            "/iocs" => self.state.tab = 5,
            "/hypotheses" => self.state.tab = 6,
            "/techniques" => self.state.tab = 7,
            "/report" => match self.engine.report(self.id) {
                Ok(report) => self.state.messages.push(report),
                Err(error) => self.state.messages.push(format!("Report error: {error}")),
            },
            "/graph" => match self.engine.graph.graph_summary(self.id) {
                Ok(summary) => self.state.result_cards.push(("Evidence graph", summary)),
                Err(error) => self.state.messages.push(format!("Graph error: {error}")),
            },
            _ => {
                if let Some(scope) = prompt.strip_prefix("/scope ") {
                    self.expand_scope(scope)?;
                } else {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn expand_scope(&mut self, scope: &str) -> Result<()> {
        let changed = scope_expansion(&self.state.case.scope, scope);
        match changed.map_err(str::to_owned).and_then(|value| {
            self.engine
                .change_scope(self.id, &value)
                .map_err(|error| error.to_string())
        }) {
            Ok(()) => {
                self.state.case = self.engine.repo.get_case(self.id)?;
                self.state
                    .messages
                    .push(format!("Scope updated: {}", self.state.case.scope));
                self.state.needs_refresh = true;
            }
            Err(error) => self.state.messages.push(format!("Scope error: {error}")),
        }
        Ok(())
    }

    fn finding_command(&mut self, prompt: &str) -> Result<bool> {
        if let Some(rest) = prompt.strip_prefix("/add ") {
            let parts = rest.splitn(3, ' ').collect::<Vec<_>>();
            if let [kind, evidence_hash, value] = parts.as_slice() {
                match FindingKind::parse(kind)
                    .and_then(|kind| self.engine.add_finding(self.id, kind, value, evidence_hash))
                {
                    Ok(finding_id) => self
                        .state
                        .messages
                        .push(format!("Finding proposed: {finding_id}")),
                    Err(error) => self.state.messages.push(format!("Finding error: {error}")),
                }
                self.refresh_findings()?;
            } else {
                self.state
                    .messages
                    .push("Usage: /add <kind> <evidence_hash> <value>".into());
            }
        } else if let Some(finding_id) = prompt.strip_prefix("/confirm ") {
            match self.engine.confirm_finding(self.id, finding_id) {
                Ok(()) => {
                    self.state.messages.push("Finding confirmed".into());
                    if let Some(guide) = self.state.demo_guide.as_mut() {
                        guide.record(DemoEvent::FindingResolved);
                    }
                }
                Err(error) => self.state.messages.push(format!("Finding error: {error}")),
            }
            self.refresh_findings()?;
        } else if let Some(rest) = prompt.strip_prefix("/dismiss ") {
            if let Some((finding_id, reason)) = rest.split_once(' ') {
                match self.engine.dismiss_finding(self.id, finding_id, reason) {
                    Ok(()) => {
                        self.state.messages.push("Finding dismissed".into());
                        if let Some(guide) = self.state.demo_guide.as_mut() {
                            guide.record(DemoEvent::FindingResolved);
                        }
                    }
                    Err(error) => self.state.messages.push(format!("Finding error: {error}")),
                }
                self.refresh_findings()?;
            } else {
                self.state
                    .messages
                    .push("Usage: /dismiss <id> <reason>".into());
            }
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    fn refresh_findings(&mut self) -> Result<()> {
        self.state.findings = self.engine.findings(self.id)?;
        self.state.needs_refresh = true;
        self.state.tab = 5;
        Ok(())
    }
}

fn scope_expansion(current: &str, command: &str) -> Result<String, &'static str> {
    if let Some(rest) = command.strip_prefix("add ") {
        let (field, value) = rest
            .split_once(' ')
            .ok_or("use /scope add <field> <value>")?;
        return CaseScope::parse(current)
            .map_err(|_| "invalid current scope")?
            .extend_target(field, value)
            .and_then(|scope| scope.to_current_string())
            .map_err(|_| "invalid scope expansion");
    }
    if let Some(rest) = command.strip_prefix("window ") {
        let (from, to) = rest
            .split_once(' ')
            .ok_or("use /scope window <from> <to>")?;
        return CaseScope::parse(current)
            .map_err(|_| "invalid current scope")?
            .expand_window(from, to)
            .and_then(|scope| scope.to_current_string())
            .map_err(|_| "invalid scope window");
    }
    Ok(command.to_owned())
}
mod approval;
mod graph;
mod objects;
mod siem;

#[cfg(test)]
mod tests {
    use super::scope_expansion;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn scope_command_expands_project_and_rejects_narrower_window() {
        let current = "v2;sources=cloud;accounts=;projects=project-a;hosts=;from=2026-10-23T00:00:00Z;to=2026-10-23T23:59:59Z";
        let expanded = scope_expansion(current, "add project project-b").unwrap();
        assert!(expanded.contains("projects=project-a,project-b"));
        assert!(
            scope_expansion(current, "window 2026-10-24T00:00:00Z 2026-10-24T23:59:59Z").is_err()
        );
    }
}
