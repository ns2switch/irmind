use super::runtime::CaseRuntime;
use super::{
    CaseWorkflow, Confirmation, FindingKind, PathBuf, PathPicker, Result, confirmation_summary,
    parse_approval_args,
};
use irmind_app::CaseScope;

impl<'env, 'ports> CaseRuntime<'_, 'env, 'ports> {
    pub(super) fn submit(&mut self, prompt: String) -> Result<bool> {
        if prompt.is_empty() {
            return Ok(false);
        }
        if prompt == "/quit" || prompt == "/home" {
            return Ok(true);
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
            return Ok(false);
        }
        if self.active.is_some() {
            self.state
                .messages
                .push("Investigation running; use /pause before another command.".into());
            return Ok(false);
        }
        if !(self.long_command(&prompt)?
            || self.case_command(&prompt)?
            || self.graph_command(&prompt)
            || self.finding_command(&prompt)?
            || self.approval_command(&prompt)?
            || self.evidence_command(&prompt))
        {
            self.investigate_prompt(prompt);
        }
        if self.state.messages.len() > 30 {
            self.state.messages.drain(..self.state.messages.len() - 30);
        }
        Ok(false)
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
            self.state.messages.push("No LLM selected. Launch with --llm-module after approval, or use case commands without a model.".into());
            return;
        }
        self.state.messages.push(format!("Analyst: {prompt}"));
        self.state.model_preview.clear();
        let workflow = self.workflow();
        let id = self.id;
        let model_tx = self.model_tx.clone();
        self.start_task("IRMind", move |cancel| {
            workflow.investigate_with_progress(id, &prompt, &cancel, &move |delta| {
                let _ = model_tx.send(delta.to_owned());
            })
        });
    }

    fn long_command(&mut self, prompt: &str) -> Result<bool> {
        if prompt == "/ingest" {
            self.state.picker = Some(PathPicker::open(std::env::current_dir()?)?);
            return Ok(true);
        }
        if let Some(path) = prompt.strip_prefix("/ingest ") {
            let path = PathBuf::from(path);
            let workflow = self.workflow();
            let id = self.id;
            let progress = self.progress_tx.clone();
            self.start_task("Ingest", move |cancel| {
                workflow
                    .ingest_path(id, &path, &cancel, |done, count, source| {
                        let _ = progress.send(format!("Ingested {done}/{count}: {source}"));
                    })
                    .map(|count| format!("Ingested {count} files"))
            });
            return Ok(true);
        }
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
        if prompt == "/rebuild" {
            let workflow = self.workflow();
            let id = self.id;
            self.start_task("Rebuild graph", move |cancel| {
                workflow
                    .rebuild_graph(id, &cancel)
                    .map(|count| format!("Rebuilt {count} records"))
            });
            return Ok(true);
        }
        if prompt == "/verify-graph" {
            let engine = self.engine;
            let id = self.id;
            self.start_task("Verify", move |cancel| {
                engine
                    .verify_graph_cancelable(id, &cancel)
                    .map(|count| format!("Verified {count} graph records"))
            });
            return Ok(true);
        }
        self.seal_or_export_command(prompt)
    }

    fn seal_or_export_command(&mut self, prompt: &str) -> Result<bool> {
        if prompt == "/seal" {
            if let Some(Confirmation::Seal(preview, _)) = self.state.confirmed_action.take() {
                let workflow = self.workflow();
                self.start_task("Seal", move |cancel| {
                    if cancel.is_cancelled() {
                        return Err(irmind_app::AppError::Cancelled);
                    }
                    workflow.seal_prepared(&preview)?;
                    Ok("Case sealed".into())
                });
            } else {
                let workflow = self.workflow();
                let id = self.id;
                let sender = self.seal_tx.clone();
                self.start_task("Prepare seal", move |cancel| {
                    let preview = workflow.prepare_seal(id, &cancel)?;
                    sender.send(preview).map_err(|_| {
                        irmind_app::AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                            irmind_app::AdapterStorageError::SealPreviewUIUnavailable,
                        ))
                    })?;
                    Ok("review the signed preview".into())
                });
            }
            return Ok(true);
        }
        if prompt == "/export" || prompt.starts_with("/export ") {
            let path = prompt.strip_prefix("/export ").map_or_else(
                || PathBuf::from(format!("{}.irmind.json", self.id.as_str())),
                PathBuf::from,
            );
            if let Some(Confirmation::Export(approved, _)) = self.state.confirmed_action.take()
                && approved == path
            {
                let workflow = self.workflow();
                let id = self.id;
                self.start_task("Export", move |cancel| {
                    if cancel.is_cancelled() {
                        return Err(irmind_app::AppError::Cancelled);
                    }
                    workflow
                        .export(id, &path, &cancel)
                        .map(|fingerprint| format!("Exported case; analyst key {fingerprint}"))
                });
            } else {
                let summary = confirmation_summary(self.engine, self.id, "Export")?;
                self.state.confirmation = Some(Confirmation::Export(
                    path.clone(),
                    format!("{summary}\nDestination: {}", path.display()),
                ));
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn case_command(&mut self, prompt: &str) -> Result<bool> {
        match prompt {
            "/help" => self.state.messages.push("Case: /ingest, /verify, /rebuild, /verify-graph, /report, /seal, /export [path], /scope, /scope add <source|account|project|host> <id>, /scope window <from> <to>, /evidence <hash>, /evidence-save <hash> <path>, /pause, /home. Graph: /graph, /timeline, /entity, /neighbors, /entity-timeline, /path, /search, /raw. Findings: /add, /confirm, /dismiss. Approvals: /approvals, /approve, /deny, /edit.".into()),
            "/scope" => self.state.messages.push(format!("Scope: {}", self.state.case.scope)),
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
                Ok(summary) => self.state.messages.push(summary),
                Err(error) => self.state.messages.push(format!("Graph error: {error}")),
            },
            "/timeline" => self.state.tab = 0,
            _ => {
                if let Some(scope) = prompt.strip_prefix("/scope ") {
                    let changed = scope_expansion(&self.state.case.scope, scope);
                    match changed.map_err(str::to_owned).and_then(|value| {
                        self.engine.change_scope(self.id, &value).map_err(|error| error.to_string())
                    }) {
                        Ok(()) => {
                            self.state.case = self.engine.repo.get_case(self.id)?;
                            self.state.messages.push(format!("Scope updated: {}", self.state.case.scope));
                            self.state.needs_refresh = true;
                        }
                        Err(error) => self.state.messages.push(format!("Scope error: {error}")),
                    }
                } else { return Ok(false); }
            }
        }
        Ok(true)
    }

    fn graph_command(&mut self, prompt: &str) -> bool {
        if let Some(rest) = prompt.strip_prefix("/entity ") {
            if let Some((kind, value)) = rest.split_once(' ') {
                self.push_graph(self.engine.graph.entity_lookup(self.id, kind, value));
            }
        } else if let Some(rest) = prompt.strip_prefix("/neighbors ") {
            if let Some((kind, value)) = rest.split_once(' ') {
                self.push_graph(self.engine.graph.neighbors(self.id, kind, value, 10));
            }
        } else if let Some(rest) = prompt.strip_prefix("/entity-timeline ") {
            if let Some((kind, value)) = rest.split_once(' ') {
                self.push_graph(self.engine.graph.entity_timeline(self.id, kind, value, 10));
            }
        } else if let Some(rest) = prompt.strip_prefix("/path ") {
            let parts = rest.splitn(4, ' ').collect::<Vec<_>>();
            if let [from_kind, from_value, to_kind, to_value] = parts.as_slice() {
                self.push_graph(self.engine.graph.graph_path(
                    self.id,
                    (from_kind, from_value),
                    (to_kind, to_value),
                ));
            }
        } else if let Some(query) = prompt.strip_prefix("/search ") {
            self.push_graph(self.engine.graph.text_search(self.id, query, 10));
        } else if let Some(rest) = prompt.strip_prefix("/raw ") {
            if let Some((hash, index)) = rest.split_once(' ')
                && let Ok(index) = index.parse::<usize>()
            {
                self.push_graph(self.engine.graph.raw_record(self.id, hash, index));
            }
        } else {
            return false;
        }
        true
    }

    fn push_graph(&mut self, result: Result<String, irmind_app::AppError>) {
        match result {
            Ok(result) => self.state.messages.push(result),
            Err(error) => self.state.messages.push(format!("Graph error: {error}")),
        }
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
                Ok(()) => self.state.messages.push("Finding confirmed".into()),
                Err(error) => self.state.messages.push(format!("Finding error: {error}")),
            }
            self.refresh_findings()?;
        } else if let Some(rest) = prompt.strip_prefix("/dismiss ") {
            if let Some((finding_id, reason)) = rest.split_once(' ') {
                match self.engine.dismiss_finding(self.id, finding_id, reason) {
                    Ok(()) => self.state.messages.push("Finding dismissed".into()),
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
            .and_then(|scope| scope.to_v2_string())
            .map_err(|_| "invalid scope expansion");
    }
    if let Some(rest) = command.strip_prefix("window ") {
        let (from, to) = rest
            .split_once(' ')
            .ok_or("use /scope window <from> <to>")?;
        return CaseScope::parse(current)
            .map_err(|_| "invalid current scope")?
            .expand_window(from, to)
            .and_then(|scope| scope.to_v2_string())
            .map_err(|_| "invalid scope window");
    }
    Ok(command.to_owned())
}
mod approval;

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
