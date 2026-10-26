impl CaseRuntime<'_, '_, '_> {
    fn approval_command(&mut self, prompt: &str) -> Result<bool> {
        if let Some(request_id) = prompt.strip_prefix("/approve ") {
            self.start_approval(request_id.to_owned());
        } else if let Some(rest) = prompt.strip_prefix("/deny ") {
            if let Some((request_id, reason)) = rest.split_once(' ') {
                match self.engine.deny(self.id, request_id, reason) {
                    Ok(result) => self.state.messages.push(result),
                    Err(error) => self.state.messages.push(format!("Approval error: {error}")),
                }
            } else {
                self.state
                    .messages
                    .push("Usage: /deny <id> <reason>".into());
            }
            self.refresh_approvals()?;
        } else if let Some(rest) = prompt.strip_prefix("/edit ") {
            if let Some((request_id, args_json)) = rest.split_once(' ') {
                match parse_approval_args(args_json).and_then(|args| {
                    self.engine
                        .edit_approval(self.id, request_id, args)
                        .map_err(Into::into)
                }) {
                    Ok(result) => self.state.messages.push(result),
                    Err(error) => self.state.messages.push(format!("Approval error: {error}")),
                }
            } else {
                self.state
                    .messages
                    .push("Usage: /edit <id> {\"ioc\":\"example.com\"}".into());
            }
            self.refresh_approvals()?;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    fn refresh_approvals(&mut self) -> Result<()> {
        self.state.approvals = self.engine.pending_approvals(self.id)?;
        self.state.needs_refresh = true;
        Ok(())
    }

    fn evidence_command(&mut self, prompt: &str) -> bool {
        if let Some(rest) = prompt.strip_prefix("/evidence-save ") {
            if let Some((hash, path)) = rest.split_once(' ') {
                let hash = hash.to_owned();
                let path = PathBuf::from(path);
                let engine = self.engine;
                let io_ops = self.io_ops;
                let id = self.id;
                self.start_task("Save evidence", move |cancel| {
                    if cancel.is_cancelled() {
                        return Err(irmind_app::AppError::Cancelled);
                    }
                    let bytes = engine.evidence_store.get_evidence(id, &hash)?;
                    if cancel.is_cancelled() {
                        return Err(irmind_app::AppError::Cancelled);
                    }
                    io_ops.save_evidence(&path, &bytes).map_err(|_| {
                        irmind_app::AppError::Fixed(irmind_app::FixedAppError::AdapterStorage(
                            irmind_app::AdapterStorageError::EvidenceSaveFailed,
                        ))
                    })?;
                    Ok(format!("Saved evidence {hash}"))
                });
            } else {
                self.state
                    .messages
                    .push("Usage: /evidence-save <hash> <path>".into());
            }
        } else if let Some(hash) = prompt.strip_prefix("/evidence ") {
            match self.engine.evidence_store.get_evidence(self.id, hash) {
                Ok(bytes) => {
                    let literal = String::from_utf8_lossy(&bytes[..bytes.len().min(4000)]);
                    let visible = literal.chars().fold(String::new(), |mut out, ch| {
                        if (ch.is_control() && ch != '\n' && ch != '\t')
                            || matches!(ch, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                            out.extend(ch.escape_default());
                        } else { out.push(ch); }
                        out
                    });
                    self.state
                        .messages
                        .push(format!("Evidence {hash}:\n{visible}"));
                }
                Err(error) => self.state.messages.push(format!("Evidence error: {error}")),
            }
        } else {
            return false;
        }
        true
    }
}
